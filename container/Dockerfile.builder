# syntax=docker/dockerfile:1
#
# The one and only build environment for rosci — 0.5.0, fully native:
# no JDK, no Maven, no Java anything. What remains is exactly what the
# Rust workspace and its gates need.
#
# Base:  ubuntu 22.04 (jammy), digest-pinned (the amd64 manifest the
#        moving tag resolved to when pinned — re-verify before bumping:
#        the tag can float independently per platform)
# Rust:  pinned stable via a checksummed rustup-init (exact versions also
#        recorded in container/LOCK.md)

FROM docker.io/library/ubuntu:22.04@sha256:8a2321a92b438238f93b4346fff61bc4259c99fdd4d9b52ee86f153fee0c344f

ARG RUST_VERSION=1.98.1
# The rustup installer itself is pinned and checksummed — piping sh.rustup.rs
# into a shell would let whatever the CDN serves today bootstrap our toolchain.
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_INIT_SHA256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71

# gcc: rustc needs a linker; g++: libFuzzer's sanitizer runtime links via c++;
# git: cargo may want it; openssl: test-PKI generation;
# libxml2-utils: xmllint, validates captured OSCI traffic against the
# normative schemas (docs/STANDARD-COMPLIANCE.md §3.4)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc \
        g++ \
        libc6-dev \
        git \
        libxml2-utils \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# --- Rust toolchain (pinned, checksummed installer) ---------------------------
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo
RUN curl -fsSL -o /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
    && echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --default-toolchain "${RUST_VERSION}" --profile minimal \
    && /opt/cargo/bin/rustup component add rustfmt clippy \
    && chmod -R a+rX /opt/rustup /opt/cargo \
    && rm -f /tmp/rustup-init
ENV PATH=/opt/cargo/bin:$PATH

# cargo-deny for license/advisory enforcement (see deny.toml). Pinned like
# everything else; a supply-chain gate that floats is a suggestion.
ARG CARGO_DENY_VERSION=0.20.2
# cargo-llvm-cov for measured coverage (make coverage).
ARG CARGO_LLVM_COV_VERSION=0.9.1
RUN /opt/cargo/bin/cargo install cargo-deny --locked --version "${CARGO_DENY_VERSION}" \
    && /opt/cargo/bin/cargo install cargo-llvm-cov --locked --version "${CARGO_LLVM_COV_VERSION}" \
    && chmod -R a+rX /opt/cargo

WORKDIR /work

# The Makefile always runs us as the invoking user's uid/gid and points
# CARGO_HOME into /work so nothing escapes this directory.
CMD ["/bin/bash"]
