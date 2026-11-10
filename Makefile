# rosci — build control panel
#
# Ground rules enforced here:
#   * Everything builds INSIDE the pinned builder container. The host stays toolchain-free.
#   * Everything caches INSIDE this directory (.cargo-home) — gitignored.
#   * `make check` runs every gate; run it before submitting anything.
#
# Container runtime: docker or podman, first one found wins. Override with:
#   make OCI=podman test

# Prefer the real podman over the docker-shim: same engine, less banner noise.
OCI            ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
ifeq ($(strip $(OCI)),)
$(error No container runtime found. Install docker or podman — building on the bare host is not supported.))
endif

WORK           := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
IMAGE          := rosci-builder:2
HOST_UID       := $(shell id -u)
HOST_GID       := $(shell id -g)

# Rootless podman needs newuidmap, and newuidmap needs setuid — which dies
# silently in process trees marked PR_SET_NO_NEW_PRIVS (inherited from
# launchers like the ZCode app; descendants can never clear the flag).
# Symptom: "newuidmap: write to uid_map failed: Operation not permitted" on
# every container target. When we detect the flag we don't fight it: the
# namespace work moves into the user-level API service (podman.socket, exec'd
# by the user manager, which carries no such flag) and this tree keeps only
# the capability-free remote client. Root has CAP_SETUID regardless of the
# flag, and docker never needed newuidmap — so this is podman-only.
ifeq ($(shell awk '/^NoNewPrivs:/{print $$2}' /proc/self/status),1)
ifneq ($(HOST_UID),0)
ifneq ($(findstring podman,$(OCI)),)
ifeq ($(origin CONTAINER_HOST),undefined)
  export CONTAINER_HOST := unix:///run/user/$(HOST_UID)/podman/podman.sock
  ifeq ($(wildcard /run/user/$(HOST_UID)/podman/podman.sock),)
    $(error NoNewPrivileges=1 in this process tree (inherited from the launching app) and podman.socket is not listening. Enable it once: systemctl --user enable --now podman.socket — or run make from a terminal outside the flagged app)
  endif
endif
  OCI := $(OCI) --remote
endif
endif
endif

# Rootless podman maps container-root to the invoking user (no --user needed,
# and passing one would land on a subuid that cannot write to the bind mount).
# Real docker needs the explicit --user so artifacts don't come out root-owned.
CONTAINER_USER := $(if $(findstring podman,$(OCI)),,--user $(HOST_UID):$(HOST_GID))

# All the honoring of "keep everything in this directory" happens right here:
# cargo caches and registry live under /work.
IN_CONTAINER = $(OCI) run --rm \
  $(CONTAINER_USER) \
  -e HOME=/work \
  -e CARGO_HOME=/work/.cargo-home \
  -e XDG_CACHE_HOME=/work/.cache \
  -v $(WORK):/work \
  -w /work \
  $(IMAGE)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: image ## Build the builder image and verify the toolchain is ready
	@echo "Setup complete. Builder image: $(IMAGE)"

.PHONY: image
image: ## Build the pinned builder container image
	$(OCI) build -f container/Dockerfile.builder -t $(IMAGE) container/

.PHONY: build
build: image ## Build the Rust workspace
	$(IN_CONTAINER) cargo build --workspace --all-targets

.PHONY: test
test: image ## Run all tests (unit/integration/e2e, in-process intermediary)
	$(IN_CONTAINER) cargo test --workspace

.PHONY: interop
interop: build ## Opt-in interop suite — CONTACTS gov.test.osci.de (real intermediary; functional tests only, never part of test/check)
	$(IN_CONTAINER) bash -c 'ROSCI_INTEROP=1 cargo test -p osci-cli --test interop -- --nocapture'

.PHONY: lint
lint: image ## Rustfmt + clippy -D warnings
	$(IN_CONTAINER) cargo fmt --all -- --check
	$(IN_CONTAINER) cargo clippy --workspace --all-targets -- -D warnings

.PHONY: audit
audit: image ## cargo-deny (workspace + fuzz tree): licenses, advisories, crate sources
	$(IN_CONTAINER) cargo deny --config deny.toml check --hide-inclusion-graph licenses advisories sources
	$(IN_CONTAINER) bash -c 'cd fuzz && cargo deny --config ../deny.toml check --hide-inclusion-graph advisories sources'

.PHONY: coverage
coverage: image ## Measured coverage: cargo-llvm-cov, lcov report in coverage/
	$(IN_CONTAINER) bash -c 'mkdir -p coverage && cargo llvm-cov --workspace --lcov --output-path coverage/lcov.info'
	@echo "Rust lcov report: coverage/lcov.info"

# Fuzz toolchain pins: a dated nightly and an exactly-versioned cargo-fuzz.
# Dev-time only (never touches shipped artifacts), but `cargo install` of an
# unpinned tool still executes whatever crates.io resolves to on THAT day —
# so it gets the same pin-and-checksum discipline as everything else.
# The installer runs against the image's CARGO_HOME because rustup >= 1.29
# refuses to install when the cargo home has no rustup launcher in bin/ (the
# runtime CARGO_HOME=/work/.cargo-home doesn't — the failure this target's old
# `|| true` used to bury, which is also why the nightly had floated silently).
NIGHTLY_DATE     := 2026-10-03
CARGO_FUZZ_VERSION := 0.13.2

.PHONY: fuzz
fuzz: image ## 60s libFuzzer smoke on the bridge-response parser (pinned nightly + cargo-fuzz, installed on demand)
	$(IN_CONTAINER) bash -c '\
	  export RUSTUP_HOME=/work/.rustup PATH="/work/.cargo-home/bin:$$PATH"; \
	  env CARGO_HOME=/opt/cargo rustup toolchain install nightly-$(NIGHTLY_DATE) --profile minimal >/dev/null || exit 1; \
	  export RUSTUP_TOOLCHAIN=nightly-$(NIGHTLY_DATE); \
	  cargo-fuzz --version 2>/dev/null | grep -q "$(CARGO_FUZZ_VERSION)" || cargo install cargo-fuzz --locked --version $(CARGO_FUZZ_VERSION) >/dev/null || exit 1; \
	  cd fuzz && set -o pipefail && cargo fuzz run dto_json_parse -- -max_total_time=60 2>&1 | tail -12'

.PHONY: release
release: image ## Produce dist/: rosci + roscid binaries, SHA256SUMS
	$(IN_CONTAINER) cargo build --workspace --release
	$(IN_CONTAINER) bash -c '\
	  install -d dist/bin \
	  && install -m 0755 target/release/rosci dist/bin/rosci \
	  && install -m 0755 target/release/roscid dist/bin/roscid \
	  && cd dist && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; > SHA256SUMS'
	@echo "Release artifacts in dist/ — checksums in dist/SHA256SUMS."

.PHONY: check
check: lint test audit ## Everything a good day needs: all gates in one command (CI runs this too)
	@echo "check: all gates green. Das Amt hätte nichts zu bemängeln."

.PHONY: lock-info
lock-info: image ## Print exact tool versions + digests for container/LOCK.md
	@OCI="$(OCI)" bash container/record-lock.sh $(IMAGE)

.PHONY: shell
shell: image ## Drop into an interactive shell in the builder container
	$(IN_CONTAINER) /bin/bash

.PHONY: clean
clean: ## Remove all build outputs, caches and tool downloads (keeps the builder image; nothing tracked is touched)
	rm -rf target dist coverage \
	       .deps .cargo-home .rustup \
	       fuzz/target fuzz/corpus fuzz/coverage fuzz/artifacts \
	       './$$TMPDIR'
	@# .cache can hold root-owned podman-root-trash from --remote runs
	@# (containers deleting bind-mount files as container-root). Not
	@# deletable without sudo — warn instead of aborting the clean.
	@if ! rm -rf .cache 2>/dev/null; then \
	  echo "clean: .cache is only partially removable (root-owned podman-root-trash — clear with sudo)" >&2; \
	fi

.PHONY: clean-image
clean-image: ## Also remove the pinned builder image (make image rebuilds it)
	$(OCI) rmi -f $(IMAGE)
