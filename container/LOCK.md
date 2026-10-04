# Build environment lock

Recorded: 2026-09-30 (via `make lock-info`); amended 2026-10-04.

| Component   | Version / pin                                                              |
|-------------|----------------------------------------------------------------------------|
| Base image  | `docker.io/library/eclipse-temurin:21-jdk-jammy` — observed amd64 digest `sha256:bc46d736fd7dfe699fa4cd96b14faa2a12a6ced042938dab8b2d7a249e3d2cb6` (2026-10-04). The Dockerfile still pins by tag; digest-pinning is the pending follow-up below |
| Java        | OpenJDK 21.0.12.1 LTS (runs the OSCI lib's Java 11 bytecode — it's fine)    |
| Rust        | 1.98.1 (rustup-pinned in Dockerfile, `--profile minimal`) + rustfmt/clippy  |
| cargo-deny  | 0.20.2 (`cargo install --locked`, license/advisory gate)                    |
| cargo-llvm-cov | 0.9.1 (`cargo install --locked`, coverage — added to the image in 0.3.0, row was missing from this table until 2026-10-04) |
| Maven       | 3.9.11 (tarball, sha512-verified in Dockerfile)                              |
| OpenSSL     | 3.0.2 (distro package, test-PKI generation)                                  |
| Linker      | gcc (Ubuntu jammy, distro package)                                           |

Builder image (locally built, tag `osci-deshittifier-builder:1`):

```
localhost/osci-deshittifier-builder@sha256:377ff2d02dc24a251f0bdb5723b87e6c5c356c2537dd63db4ab5afac94eb9a17
```

(The digest identifies the locally built image including the pinned
cargo-deny addition; the Dockerfile pins every input, which is the
durable guarantee — the digest is the convenience.)

**Pending re-record (2026-10-04):** the builder digest above predates the
cargo-llvm-cov addition and must be re-recorded via `make lock-info` the
next time the image is rebuilt. The base-image digest in the table was
recorded from a direct pull of the pinned tag and is current.

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
