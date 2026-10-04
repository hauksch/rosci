# Build environment lock

Recorded: 2026-09-30 (via `make lock-info`); amended 2026-10-04 (supply-chain
hardening: digest-pinned base image, checksummed rustup-init, pinned fuzz
toolchain, OSV gate for the Java tree).

| Component   | Version / pin                                                              |
|-------------|----------------------------------------------------------------------------|
| Base image  | `docker.io/library/eclipse-temurin:21-jdk-jammy@sha256:bc46d736fd7dfe699fa4cd96b14faa2a12a6ced042938dab8b2d7a249e3d2cb6` — the Dockerfile pins this amd64 manifest digest directly (verified 2026-10-04 to be the current content of the moving tag; multi-arch index digest at that moment: `sha256:e0c60c487345d1dc9d0fc7b6f0496f3cc941e5132e09296cc17a6decc71b902b`) |
| Java        | OpenJDK 21.0.12.1 LTS (runs the OSCI lib's Java 11 bytecode — it's fine)    |
| Rust        | 1.98.1 via rustup-init **1.29.1, sha256-verified in the Dockerfile** (`--profile minimal`) + rustfmt/clippy |
| rustup-init | 1.29.1 — `sha256:dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71` (x86_64-unknown-linux-gnu, from static.rust-lang.org/rustup/archive; pinned via `ARG RUSTUP_INIT_SHA256`) |
| cargo-deny  | 0.20.2 (`cargo install --locked`, license/advisory gate)                    |
| cargo-llvm-cov | 0.9.1 (`cargo install --locked`, coverage — added to the image in 0.3.0, row was missing from this table until 2026-10-04) |
| cargo-fuzz  | 0.13.2 (`cargo install --locked --version`, dev-time only, installed on demand by `make fuzz`) |
| nightly     | `nightly-2026-10-03` (dated pin, dev-time only, `make fuzz`; rustc 1.101.0-nightly) |
| OSV gate    | `container/osv-java.sh` — scans all Maven artifacts from DEPENDENCY_MANIFEST.sha256 against api.osv.dev (`make audit`); build-time-only allowlist in the script |
| Maven       | 3.9.11 (tarball, sha512-verified in Dockerfile)                              |
| OpenSSL     | 3.0.2 (distro package, test-PKI generation)                                  |
| libxml2-utils | 2.9.13 (distro package, `xmllint` — schema-validates captured OSCI traffic against schema/, added 2026-10-04) |
| Linker      | gcc (Ubuntu jammy, distro package)                                           |

Builder image (locally built, tag `osci-deshittifier-builder:1`):

```
localhost/osci-deshittifier-builder@sha256:6fd4c4726c427f5d2c2d9bbc12a79bfd56dadb643cc0b36613cf9ab50c32e069
```

(Recorded 2026-10-04 via `make lock-info` after the supply-chain hardening
rebuild — checksummed rustup-init, digest-pinned base image, OSV gate. The
digest identifies the locally built image including cargo-deny and
cargo-llvm-cov; the Dockerfile pins every input, which is the durable
guarantee — the digest is the convenience.)

## Java dependency pins (see `java/osci-bridge/pom.xml`)

| Artifact                              | Version | Source                                    |
|---------------------------------------|---------|-------------------------------------------|
| `de.osci:osci-bibliothek`             | 2.6.1   | Maven Central (2026-08-20 release)         |
| `de.osci:osci-bibliothek-bom`         | 2.6.1   | Maven Central (version alignment)          |
| BouncyCastle bcprov-jdk18on           | 1.85.2  | managed by the osci BOM                    |
| BouncyCastle bcpkix-jdk18on (test)    | 1.85    | matches the 1.85.x line                    |
| Gson                                  | 2.13.2  | Maven Central                              |

Dependency tree checksums: `java/osci-bridge/DEPENDENCY_MANIFEST.sha256`
(regenerate with `make manifest`, verify with `make verify-deps`).

To re-verify the whole environment from scratch: `make image && make verify-deps && make audit`.
Reproducibility is not a mood, it's a checksum.
