# Changelog

All notable changes to this project are documented in this file. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/); dates are
ISO-8601. This repository is never published anywhere (mission rule), so
versions are internal milestones, not releases to a registry.

## [Unreleased]

### Added
- **TLS client authentication** for the intermediary connection:
  `--tls-client-cert FILE` + `--tls-client-pin`/`OSCI_TLS_CLIENT_PIN`.
  The bridge already consumed mutual-TLS bundles — the CLI just never
  exposed them (`Tls::with_client_p12_file` is the new library builder;
  parsing and PIN errors surface JVM-side).
- **Schema-conformance harness** (spec §7 obligation 2,
  docs/STANDARD-COMPLIANCE.md §3.4): the normative OSCI 1.2 XSDs
  (Korrigenda 1–10) are vendored in `schema/` (provenance + the one
  whitespace deviation we had to apply in `order.xsd` recorded in
  `schema/PROVENANCE.md` — libxml2 refuses a QName with trailing
  whitespace that Xerces tolerates), the builder image gains
  `libxml2-utils`, and the new e2e test `wire_traffic_is_schema_valid`
  validates every rosci-produced request envelope — plain and encrypted
  transport, decrypted inner envelopes included — against the matching
  `soap<Auftrag>.xsd`. Six documents validated green. Responses are
  intermediary-produced and counted but not validated; the harness
  promptly found that the mock's rich responses are *not*
  schema-conform (filed as §7 finding 7 in the compliance doc).
- **Supply-chain hardening (external audit follow-up).** The builder image
  no longer pipes `sh.rustup.rs` into a shell: rustup-init 1.29.1 is
  downloaded from the static.rust-lang.org archive and sha256-verified
  (`ARG RUSTUP_INIT_SHA256`) before it may bootstrap the toolchain. The
  base image is digest-pinned (`eclipse-temurin:21-jdk-jammy@sha256:…`,
  amd64 manifest, verified current against the registry at pin time).
  `make fuzz` installs an exactly-versioned `cargo-fuzz` 0.13.2 against a
  dated `nightly-2026-10-03` (no more floating nightly, no more `|| true`
  swallowing install failures) — which un-buried a real breakage the `|| true`
  had been hiding: rustup ≥ 1.29 refuses to install without a rustup launcher
  in the cargo home, so the old target had silently fuzzed on whatever nightly
  the `RUSTUP_HOME` cache happened to hold. The target now installs against
  the image's cargo home, puts the cargo-install bin dir on PATH, and
  verifies the installed cargo-fuzz version, and `make audit` now scans the
  fuzz tree's
  own lockfile too (it was workspace-excluded and invisible to cargo-deny).
  New `container/osv-java.sh` (wired into `make audit`): all 77 Maven
  artifacts from DEPENDENCY_MANIFEST.sha256 are checked against the OSV
  database — the checksum manifest proves integrity, the OSV gate proves
  "and no advisory is published against it". The gate's first run caught
  nine advisory-flagged versions (commons-io, commons-lang3,
  plexus-utils ×5, iq80 snappy — all build-plugin transitives, none shipped
  in the shaded jar), and every one was **moved** rather than accepted:
  compiler 3.13.0 → 3.16.0, jar 3.4.1/3.4.2 → 3.5.1, resources
  (unpinned/super-POM) → 3.5.0 and surefire (unpinned) → 3.6.0 now pinned
  in **both** poms, jacoco 0.8.13 → 0.8.15 (with the `make coverage` agent
  zip re-pinned and re-hashed to match), and — for shade 3.6.2, resources
  3.5.0 and jacoco, which are already the newest stable releases but still
  declare plexus-utils 3.6.0/3.0.24 — plugin-level dependency overrides to
  plexus-utils 3.6.2. The OSV gate now reports clean across all 80 Maven
  artifacts with an **empty allowlist**. The workspace crates now set
  `publish = false`, and `rust-toolchain.toml` mirrors the container's
  `ARG RUST_VERSION` so cargo outside the container cannot float either.
  LOCK.md records the new pins; known RustSec advisories against the
  locked tree: zero (verified against the advisory DB of 2026-10-03).
- `docs/STANDARD-COMPLIANCE.md`: where OSCI 1.2 normatively lives
  (Spezifikation + individually authoritative Korrigenda 1–10 + XML
  schemas on xoev.de; the consolidated PDF is nicht-normativ) and how
  rosci is compared for completeness — five-method framework, the
  order-type matrix over all ten Aufträge (spec §7 licenses user
  software to implement a subset), security-mechanism matrix, feedback
  policy, deviations and gaps (EFFI chunking, TLS client-auth CLI flag,
  single-content send, Ergänzungen), re-verification procedure.
- Opt-in interop suite (`crates/osci-cli/tests/interop.rs`, `make
  interop`): real store deliveries against Governikus' public
  OSCI-Manager test intermediary (gov.test.osci.de) using the library's
  published demo identities — secure send, `--no-encrypt`/`--no-sign`
  variants (all answered with verified signed responses), structured
  live rejections for `status`, loud failure on a wrong intermediary
  certificate, a DOI-identity rung gated on
  `ROSCI_INTEROP_CERT`/`ROSCI_INTEROP_CERT_PIN` — and **the full
  postbox round trip**: fetch authenticated as the recipient (bob)
  returns alice's content-encrypted delivery byte-exact, while the
  same id fetched as the sender is cleanly rejected (postbox
  isolation). `fetch --all` is covered too: it is spec §6.6.9 rule 3
  („oldest pending delivery") and delivers with warning 3800 — with the
  caveat that bob's postbox on the public instance is shared with other
  testers, so `--all` assertions stay structural and `--message-id`
  carries the byte-exact check. Fixtures are the vendor's public demo
  certs (PEM-converted, pinned by SHA256SUMS, documented .gitignore
  exceptions — the intermediary rejects self-signed senders, feedback
  3707, so generated identities are not an option). `make test`/`make
  check` never touch the network: ungated, the suite skips at zero
  cost.
- `docs/TEST-INFRASTRUCTURE.md`: briefing for the interop test suite —
  the open Governikus OSCI-Manager test intermediary
  (gov.test.osci.de, no registration; endpoint terms, verified
  certificate paths in the library repo, rosci wiring) and the
  walk-through for obtaining DOI/V-PKI sender certificates (test env
  via the TeleSec DOI portal incl. the exact RA email subject, and
  production). Mission rule 4 now names this as the single sanctioned
  opt-in exception (`ROSCI_INTEROP=1`, never in `make test`/`check`).

### Fixed
- **`selection_mode: BY_RECENT_MODIFICATION` crashed the bridge.** The
  constant exists in the library, but `FetchRequestAbstract
.setSelectionMode` throws `IllegalArgumentException` for it — so that
  request died with a stack trace (exit 6) instead of a clean protocol
  error. Found during the standard-compliance comparison
  (docs/STANDARD-COMPLIANCE.md §7); the mapping is removed, the mode
  now fails like any unknown one, and the mapping matrix is pinned by
  `OsciOpsTest`. docs/PROTOCOL.md corrected.
- **Fetch warnings were treated as rejections.** A successful fetch
  whose response carries the spec's §6.6.10 warning 3800 „Es liegen
  weitere Zustellungen für diesen Client vor" alongside a success
  receipt (0801) was rejected with exit 4 — and the delivered message
  was discarded. The bridge now tolerates the 3800 indicator (spec §5:
  „Erfolgsmeldung oder Warnung" means the order was executed) while
  still failing loudly on everything else — including 3707, which
  lives in the warning class but is a hard rejection. Unit tests pin
  the classification matrix.
- **DER certificate files failed with a UTF-8 riddle.** `--intermediary-cert`,
  `--to cert:…` and `--tls-ca` read their files as UTF-8 text, so a
  DER-encoded `.cer` (OpenSSL's favorite export format) died with
  `stream did not contain valid UTF-8` — despite the API docs promising
  "PEM or DER". All three now share one reader
  (`osci::read_certificate_file`): PEM/UTF-8 passes through, binary DER
  is base64-wrapped for the bridge (which accepts bare DER), and binary
  that is neither is rejected at config parse with the file and its
  first byte named. Verified live against gov.test.osci.de with DER on
  both hops.
- **`make` was unusable from inside sandboxed app trees** (e.g. the ZCode
  app): such launchers set `PR_SET_NO_NEW_PRIVS` on their whole process
  tree; the flag is inherited and silently disables setuid elevation, so
  rootless podman's `newuidmap` got EPERM writing the `uid_map`
  ("Operation not permitted" on every container target, Error 125). The
  Makefile now detects the flag and, when it is set, routes podman through
  the user-level API service (`podman.socket`, exec'd by the user manager
  without the flag) as a remote client — no capabilities needed locally.
  Scoped so it cannot misfire: rootless podman only (root and docker never
  needed `newuidmap`), only when `CONTAINER_HOST` is not already set, with
  an actionable parse-time error if the socket is not listening.

## [0.3.1] — 2026-10-04 — code-review fixes

A second full review (ledger: `docs/REVIEW.md`, section F) found three
P1 functional defects, eight P2 security/robustness gaps and a batch of
P3 polish items. All P1/P2 items fixed and tested.

### Fixed
- **Intermediary feedback text reached no user**: the library's feedback
  rows are `[lang, code, text]`, but they were forwarded raw while the
  protocol (and the CLI renderer) expected `[text, code]` — a rejection
  printed `[1050] de` instead of the actual reason. The bridge now maps
  rows to the documented two-column shape.
- **Fetched inline content was corrupted**: the bridge re-encoded the
  library's lossy UTF-8 string interpretation of `Base64Content` back to
  bytes, destroying any non-UTF-8 payload. Fetched content is now read
  as a stream — byte-exact, contract restored.
- **Release layout was broken from the CLI** (regression of review
  finding B1): `--bridge-jar`'s cwd-relative default defeated the
  exe-relative `../lib/osci-bridge.jar` lookup. The argument is now
  optional and the library's resolution (env → exe-relative → cwd) runs.
- `--insecure-transport` loopback guard: URL *userinfo* (`http://127.0.0.1:8080@evil.example/`)
  was read as the host — the guard passed while the bridge connected to
  the attacker host. Userinfo is now stripped before host parsing.
- PIN handling matches the audit claim: `Identity`/`IdentityMsg` hold
  pins in `Zeroizing`; AUDIT.md now states precisely which copies are
  scrubbed and which are irreducible (the wire JSON line, the JVM).
- The `ping` handshake validates the bridge protocol version (a v2 jar
  can no longer fail confusingly mid-flow).
- `rosci fetch` no longer overwrites existing files or follows pre-planted
  symlinks; collisions get numbered siblings (`m.xta`, `m-1.xta`).
- Bridge request bodies stream with `setFixedLengthStreamingMode` instead
  of buffering on-heap behind a silently-ignored `Content-Length` header.
- OSCI dialogs close on error paths too (`finally`); fetch decryption
  failures of *our own* key material surface as `crypto` errors instead
  of masquerading as the message subject; a killed bridge is reaped
  (no more zombies for library consumers).
- `make coverage` fails when the e2e suite fails (coverage data is still
  emitted first).
- Docs/build: README env table gained `OSCI_TLS_CA` and the new jar
  default; LOCK.md gained the cargo-llvm-cov row and the observed
  base-image digest; `.cache/` and `/.zcode/` gitignored, the committed
  session plan file untracked; `hooks/pre-push` no longer executes its
  own backticks; REVIEW C4 status corrected.

### Known issues filed, not fixed
P3 batch (F17–F29 in `docs/REVIEW.md`): exit-code taxonomy for mid-flow
crypto failures, fetch subject mapping, TLS timeout validation, bridge
stdin write timeouts, `insecure_transport` wire polarity (protocol v2
item), license/notice aggregation for the shaded jar, and the rest of
the ledger.

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
