# Build environment lock

Recorded: 2026-09-29 (via `make lock-info`)

| Component   | Version / pin                                                              |
|-------------|----------------------------------------------------------------------------|
| Base image  | `docker.io/library/eclipse-temurin:21-jdk-jammy`                            |
| Java        | OpenJDK 21.0.12.1 LTS (runs the OSCI lib's Java 11 bytecode — it's fine)    |
| Rust        | 1.98.1 (rustup-pinned in Dockerfile, `--profile minimal`)                    |
| Maven       | 3.9.11 (tarball, sha512-verified in Dockerfile)                              |
| OpenSSL     | 3.0.2 (distro package, test-PKI generation)                                  |
| Linker      | gcc (Ubuntu jammy, distro package)                                           |

Builder image (locally built, tag `osci-deshittifier-builder:1`):

```
localhost/osci-deshittifier-builder@sha256:5285f6420fefe9b6ac90d5266800ab5231023f04db173424971739a238875f52
```

## Java dependency pins (see `java/osci-bridge/pom.xml`)

| Artifact                              | Version | Source                                    |
|---------------------------------------|---------|-------------------------------------------|
| `de.osci:osci-bibliothek-lib`         | 2.6.1   | Maven Central (2026-08-20 release)         |

Dependency tree checksums: `java/osci-bridge/DEPENDENCY_MANIFEST.sha256`
(regenerate with `make manifest`, verify with `make verify-deps`).

To re-verify the whole environment from scratch: `make image && make verify-deps`.
Reproducibility is not a mood, it's a checksum.
