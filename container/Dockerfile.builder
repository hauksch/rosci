# syntax=docker/dockerfile:1
#
# The one and only build environment for osci-deshittifier.
# Pinned like a bureaucracy pins its processes — but on purpose, and with
# checksums. Everything the mission needs to turn XTA into valid OSCI without
# installing a single JVM on the host. The host has suffered enough.
#
# Base:  Eclipse Temurin JDK 21 (runs the OSCI lib's Java 11 bytecode just fine)
# Rust:  pinned stable via rustup (exact version also recorded in container/LOCK.md)
# Maven: pinned tarball, sha512-verified, because trusting transitive infra is
#        how you end up explaining an incident to the Landesrechenzentrum.

# Fully qualified on purpose: podman refuses to guess registries, and honestly,
# a build tool that guesses is how supply-chain incidents get their own RFCs.
FROM docker.io/library/eclipse-temurin:21-jdk-jammy

ARG RUST_VERSION=1.98.1
ARG MAVEN_VERSION=3.9.11
ARG MAVEN_SHA512=bcfe4fe305c962ace56ac7b5fc7a08b87d5abd8b7e89027ab251069faebee516b0ded8961445d6d91ec1985dfe30f8153268843c89aa392733d1a3ec956c9978

# gcc: rustc needs a linker; g++: libFuzzer's sanitizer runtime links via c++;
# git: cargo may want it; openssl: test-PKI generation; zip/unzip: jar tooling
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc \
        g++ \
        libc6-dev \
        git \
        openssl \
        unzip \
        zip \
    && rm -rf /var/lib/apt/lists/*

# --- Rust toolchain (pinned) -------------------------------------------------
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal \
    && /opt/cargo/bin/rustup component add rustfmt clippy \
    && chmod -R a+rX /opt/rustup /opt/cargo
ENV PATH=/opt/cargo/bin:$PATH

# cargo-deny for license/advisory enforcement (see deny.toml). Pinned like
# everything else; a supply-chain gate that floats is a suggestion.
ARG CARGO_DENY_VERSION=0.20.2
# cargo-llvm-cov for measured coverage (make coverage).
ARG CARGO_LLVM_COV_VERSION=0.9.1
RUN /opt/cargo/bin/cargo install cargo-deny --locked --version "${CARGO_DENY_VERSION}" \
    && /opt/cargo/bin/cargo install cargo-llvm-cov --locked --version "${CARGO_LLVM_COV_VERSION}" \
    && chmod -R a+rX /opt/cargo

# --- Maven (pinned, checksummed) ----------------------------------------------
RUN curl -fsSL -o /tmp/maven.tgz \
        "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/${MAVEN_VERSION}/apache-maven-${MAVEN_VERSION}-bin.tar.gz" \
    && echo "${MAVEN_SHA512}  /tmp/maven.tgz" | sha512sum -c - \
    && tar -xzf /tmp/maven.tgz -C /opt \
    && ln -s "/opt/apache-maven-${MAVEN_VERSION}/bin/mvn" /usr/local/bin/mvn \
    && rm -f /tmp/maven.tgz

WORKDIR /work

# The Makefile always runs us as the invoking user's uid/gid and points
# CARGO_HOME/-Dmaven.repo.local into /work so nothing escapes this directory.
CMD ["/bin/bash"]
