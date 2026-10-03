# Changelog

All notable changes to this project are documented in this file. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/); dates are
ISO-8601. This repository is never published anywhere (mission rule), so
versions are internal milestones, not releases to a registry.

## [0.3.0] — 2026-10-03 — quality pass

Closed every remaining audit gap from the repository review.

### Added
- Measured coverage: `make coverage` (cargo-llvm-cov for Rust, JaCoCo for
  the Java bridge — including an agent attached through `OSCI_JAVA_OPTS`
  during the e2e suite, so the real flows count). Baselines in AUDIT.md:
  Rust 88.0 %, bridge 71.4 % combined.
- Property-based tests (proptest) for the response parser, the filename
  sanitizer and the XML sniffer; libFuzzer smoke target (`make fuzz`,
  5.6 M executions, zero crashes on first run).
- Mock intermediary now signs every response (XML-DSIG supplier
  signatures: JDK inclusive-C14N part digests, RSA-PSS over the
  SignedInfo, `cid:` attachment references, IntermediaryCertificates
  header). The client's automatic verification runs in every e2e flow;
  a `--tamper-signature` mode proves one flipped byte fails loudly.
- Encrypted fetch content: the mock's canned message carries a sealed
  `xenc:EncryptedData` block; the bridge's decrypt path is exercised and
  asserted end-to-end.
- Large-payload handling: 5 MB verified manually through both transports,
  ~2 MB regression case in the e2e suite; chunking documented as
  unimplemented with its failure mode (loud, not silent).
- `rosci version` reports the bridge jar's SHA-256 (per-invocation audit
  trail); `response_signed` in the line protocol.
- `--insecure-transport` now refuses non-loopback intermediaries unless
  `--insecure-transport-any-host` is given explicitly.
- `make check` (lint + test + audit + verify-deps + git-guard).

### Changed
- Java builds compile with `-Xlint:all` and fail on warnings (found and
  fixed: missing `serialVersionUID`, a redundant cast, use of deprecated
  PKCS#1 v1.5 constants — the PSS-only path is now the only path).
- Rust library denies `missing_docs` and warns on `unwrap`/`expect` in
  library code.
- Bridge jars are reproducible: pinned `outputTimestamp`, byte-identical
  across clean builds (verified).
- PINs are zeroized on drop on the Rust side (`zeroize`); JVM-side string
  residency documented as the irreducible remainder.

## [0.2.0] — 2026-09-30 — review & hardening

- Full repository review (`docs/REVIEW.md`, 22 findings, all actionable
  ones fixed): UTF-8 BOM handling, Drop shutdown could block 300 s,
  exe-relative jar resolution, `dvdv find` UX, stale lock digest.
- Mock intermediary became a real cryptographic peer: RSA-OAEP + AES-GCM
  transport decryption/encryption both directions; e2e asserts on raw
  ciphertext, decrypted inner envelopes and encrypted responses.
- Mock serves canned fetch content and Laufzettel; fetch/status covered
  end-to-end. Test count 67 → 85.
- CLI renamed `osci` → `rosci` (library crate remains `osci`).

## [0.1.0] — 2026-09-29 — first working system

- Rust library (`osci`) + CLI (`rosci`) + Java sidecar bridge
  (`osci-bridge`) speaking a one-line JSON protocol over stdio
  (docs/PROTOCOL.md), wrapping `de.osci:osci-bibliothek:2.6.1`.
- `rosci send|fetch|status|dvdv|version`, DVDV file-based resolution,
  curl-style flags and `OSCI_*` environment variables, stable exit codes.
- Everything builds via `make` inside a pinned podman/docker container;
  the host stays Java-free. Local mock intermediary (`osci-mock`) for the
  e2e suite — no online traces, ever; pre-push hook and `git-guard`
  enforce the no-remote rule. MIT license.
