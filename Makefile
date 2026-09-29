# osci-deshittifier — build control panel
#
# Mission rules enforced here:
#   * Everything builds INSIDE the pinned builder container. The host stays Java-free.
#   * Everything caches INSIDE this directory (.cargo-home, .m2-repo) — gitignored.
#   * Nothing is ever pushed. See `git-guard` and hooks/pre-push.
#
# Container runtime: docker or podman, first one found wins. Override with:
#   make OCI=podman test

# Prefer the real podman over the docker-shim: same engine, less banner noise.
OCI            ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
ifeq ($(strip $(OCI)),)
$(error No container runtime found. Install docker or podman — building on the bare host is against the mission rules.))
endif

WORK           := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
IMAGE          := osci-deshittifier-builder:1
HOST_UID       := $(shell id -u)
HOST_GID       := $(shell id -g)

# All the honoring of "keep everything in this directory" happens right here:
# cargo caches, registry and (below) the maven local repo live under /work.
IN_CONTAINER = $(OCI) run --rm \
  --user $(HOST_UID):$(HOST_GID) \
  -e HOME=/work \
  -e CARGO_HOME=/work/.cargo-home \
  -e XDG_CACHE_HOME=/work/.cache \
  -v $(WORK):/work \
  -w /work \
  $(IMAGE)

MVN = mvn -q -Dmaven.repo.local=/work/.m2-repo

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: image ## Build the builder image, wire git hooks, verify we are push-less
	@git config core.hooksPath hooks
	@$(MAKE) --no-print-directory git-guard
	@echo "Setup complete. Builder image: $(IMAGE)"

.PHONY: image
image: ## Build the pinned builder container image
	$(OCI) build -f container/Dockerfile.builder -t $(IMAGE) container/

.PHONY: build
build: image ## Build everything (Java bridge jar + Rust workspace)
	$(IN_CONTAINER) $(MVN) -f java/osci-bridge/pom.xml package
	$(IN_CONTAINER) cargo build --workspace --all-targets

.PHONY: test
test: image ## Run all tests (Java unit + Rust unit/integration/e2e)
	$(IN_CONTAINER) $(MVN) -f java/osci-bridge/pom.xml test
	$(IN_CONTAINER) cargo test --workspace

.PHONY: lint
lint: image ## Rustfmt + clippy -D warnings + maven verify
	$(IN_CONTAINER) cargo fmt --all -- --check
	$(IN_CONTAINER) cargo clippy --workspace --all-targets -- -D warnings
	$(IN_CONTAINER) $(MVN) -f java/osci-bridge/pom.xml verify

.PHONY: release
release: image ## Produce dist/: osci binary, osci-bridge.jar, SHA256SUMS
	$(IN_CONTAINER) $(MVN) -f java/osci-bridge/pom.xml package
	$(IN_CONTAINER) cargo build --workspace --release
	$(IN_CONTAINER) bash -c '\
	  install -d dist/bin dist/lib \
	  && install -m 0755 target/release/osci dist/bin/osci \
	  && install -m 0644 java/osci-bridge/target/osci-bridge.jar dist/lib/osci-bridge.jar \
	  && cd dist && find . -type f -exec sha256sum {} \; > SHA256SUMS'
	@echo "Release artifacts in dist/ — checksums in dist/SHA256SUMS."

.PHONY: manifest
manifest: image ## (Re)generate the Java dependency checksum manifest (commit the result)
	$(IN_CONTAINER) bash -c '\
	  test -d .m2-repo || { echo "Run make build first."; exit 2; }; \
	  find .m2-repo -type f \( -name "*.jar" -o -name "*.pom" \) -printf "%P\n" | sort \
	  | (cd .m2-repo && xargs -d "\n" sha256sum) \
	  > java/osci-bridge/DEPENDENCY_MANIFEST.sha256'
	@echo "Wrote java/osci-bridge/DEPENDENCY_MANIFEST.sha256 — commit it."

.PHONY: verify-deps
verify-deps: image ## Verify the maven cache against DEPENDENCY_MANIFEST.sha256
	$(IN_CONTAINER) bash -c '\
	  (cd .m2-repo && sha256sum -c ../../../java/osci-bridge/DEPENDENCY_MANIFEST.sha256)'

.PHONY: git-guard
git-guard: ## Fail if this repository ever grows a remote (mission rule: no traces)
	@remotes=$$(git remote); \
	if [ -n "$$remotes" ]; then \
	  echo "VIOLATION: repository has remote(s): $$remotes" >&2; \
	  echo "The mission says: never push this anywhere." >&2; exit 1; \
	fi
	@echo "git-guard: no remotes configured. Gut so."

.PHONY: lock-info
lock-info: image ## Print exact tool versions + digests for container/LOCK.md
	@bash container/record-lock.sh $(IMAGE)

.PHONY: shell
shell: image ## Drop into an interactive shell in the builder container
	$(IN_CONTAINER) /bin/bash

.PHONY: clean
clean: ## Remove build outputs and caches (keeps git history, obviously)
	rm -rf target dist java/osci-bridge/target .cargo-home .m2-repo .cache
