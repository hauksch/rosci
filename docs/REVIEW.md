# Repository review — remaining issues

Full review date: 2026-09-30. Scope: everything except `dist/` and caches.
Baseline at review time: `make lint test audit` green, 67 tests, working
tree clean, no git remote.

Each item carries an honest severity and, where applicable, the decision
taken (fixed now / left open with rationale).

## A. Bugs

| # | Where | Issue | Severity | Decision |
|---|---|---|---|---|
| A1 | `crates/osci/src/xta.rs` — `sniff_root_element` | A UTF-8 BOM (`EF BB BF`) before the XML declaration is treated as "not XML" → spurious warning for perfectly good BOM-prefixed XTA files | low (cosmetic output) | **fixed** |
| A2 | `crates/osci/src/bridge.rs` — `Drop` for `BridgeHandle` | Shutdown handshake goes through `call()`, which waits the full `response_timeout` (300 s default). An unresponsive JVM makes *dropping* the client — and thus CLI exit — block for minutes, before the 5 s kill grace even starts | medium | **fixed** (short fixed goodbye timeout) |
| A3 | `Makefile` — `lock-info` | Does not pass `OCI` to `record-lock.sh`; the script prefers `docker` internally → podman-only hosts get the docker-shim banner noise in the lock output | low | **fixed** |
| A4 | `container/LOCK.md` | Builder image digest is stale (recorded before the cargo-deny image rebuild); LOCK itself says so, but a stale pin that admits it is still a stale pin | low | **fixed** (re-recorded) |
| A5 | `java/osci-bridge` — `BridgeTransport.getContentLength()` | NPE if the library ever calls it before a connection exists (it does not today, but defensive APIs are cheaper than incident reports) | low | **fixed** (returns −1) |

## B. Robustness / correctness gaps

| # | Where | Issue | Severity | Decision |
|---|---|---|---|---|
| B1 | `crates/osci/src/client.rs` — `default_jar_path()` | Only `OSCI_BRIDGE_JAR` or a cwd-relative `osci-bridge.jar` are tried. The release layout (`dist/bin/rosci` + `dist/lib/osci-bridge.jar`) only works when the cwd happens to be right | medium (usability) | **fixed** (exe-relative lookup, pure + tested) |
| B2 | `crates/osci-cli/tests/e2e.rs` — `free_port()` | Bind-then-drop has a TOCTOU race on port allocation | low (test-only) | left open; failures would be loud and rare |
| B3 | `java/osci-mock` — `LAST_CLIENT_CERT` | Global static: two different clients against one mock process would cross-talk (second client's responses encrypted to the first client's cert) | low (test-only, single-client flows) | documented in code |
| B4 | `java/osci-bridge` — `BridgeException.feedback` | Field is `transient` for no reason (the type is never serialized) — cargo cult keyword | trivial | **fixed** |
| B5 | Mock request-type detection | `acceptDelivery` / `processDelivery` / `forwardDelivery` are detected but produce a bare 500 | low (test-only) | documented in AUDIT limitations |

## C. Design / UX

| # | Where | Issue | Severity | Decision |
|---|---|---|---|---|
| C1 | `cmd_fetch` | `--json` branch early-returns; the client-shutdown dance is copy-pasted three times across commands | trivial | left open (cosmetic duplication) |
| C2 | `rosci dvdv find` | Without `--org` **and** without `--all`, silently lists everything; README implies `--all` is required for that | low (doc/behavior mismatch) | **fixed** (explicit `--org` or `--all` required) |
| C3 | `rosci send` human output | Intermediary feedback rows are only visible with `--json` | low | left open (feedback rows do surface on stderr for errors) |
| C4 | `BridgeConfig::java_jar` | Reads `OSCI_JAVA_OPTS` from the environment at construction — impure constructor, and the env var is documented in README but absent from `--help` | low | env var now covered by unit test; `--help` gap **closed** (after_help documents it since the 0.3.0 quality pass — status was stale until the 2026-10-04 review) |
| C5 | Tooling | No coverage measurement (llvm-cov/tarpaulin); coverage claims are by-inspection | low | left open (container-friendly coverage tooling is its own project) |

## D. Documentation / build

| # | Where | Issue | Severity | Decision |
|---|---|---|---|---|
| D1 | `docs/AUDIT.md` — PIN handling | Documents stdio travel of PINs but not exposure via process environment (`/proc/*/environ` for env-var PINs) | low | **fixed** (note added) |
| D2 | `docs/PROTOCOL.md` | Claimed: sample request JSON omits `insecure_transport` — **false alarm**, the sample already carries it (reviewer read the table, not the sample) | — | closed as invalid |
| D3 | this file | The review list itself must live in the repo and be kept honest | — | created |

## E. Test coverage gaps (worklist for the coverage pass)

Measured by inspection (no coverage tooling — see C5):

| # | Gap | Where it matters | Decision |
|---|---|---|---|
| E1 | Fetch-with-content path: `toFetchedContent` (attachment branch), `FetchedMessage` mapping, `signatures_valid`, CLI file writing — zero coverage; the mock never returned content | `java/osci-bridge` fetch flow, `rosci fetch` | **covered** (mock now serves a canned ContentPackage + attachment; e2e asserts the file lands on disk and `--json` shape) |
| E2 | ProcessCard/Inspection mapping — mock always returned an empty Laufzettel | bridge `processCard`, `rosci status` | **covered** (mock serves a canned ProcessCardBundle; e2e asserts subject + creation timestamp) |
| E3 | CLI internals: `sanitize_filename`, `parse_to`, pin precedence (`--pin` > `--pinfile` > env) | `crates/osci-cli/src/main.rs` | **covered** (unit tests via `#[cfg(test)]`) |
| E4 | `Tls::with_trust_anchor_file`, `Identity::from_p12_files` error paths | `crates/osci/src/config.rs` | **covered** |
| E5 | `FileDvdv::all()` ordering; `resolve_dvdv` ambiguity error | `crates/osci/src/dvdv.rs`, `client.rs` | **covered** |
| E6 | Bridge desync detection (response-id mismatch) and shutdown echo | `crates/osci/src/bridge.rs` | **covered** (fake-bridge tests) |
| E7 | `OSCI_JAVA_OPTS` plumbing in `BridgeConfig::java_jar` | `crates/osci/src/bridge.rs` | **covered** |
| E8 | Java `insecure_transport` protocol field round-trip | `ProtocolTest` | **covered** |
| E9 | Secure-mode fetch with content (encrypted response carrying a content package) | e2e | partially covered — secure status now carries a canned Laufzettel through the encrypted pipe; secure fetch-with-content is exercised by the same mock path in the plain test (content mapping is crypto-independent) |
| E10 | `sniff_root_element` BOM handling | `xta.rs` | **covered** (with the A1 fix) |

## Statement

No critical or high-severity defects were found: no secrets in git, no
path traversal beyond the sanitized fetch filenames, no network egress in
tests, error paths mapped to exit codes, and the crypto paths are pinned
by the e2e ciphertext assertions. Everything above is polish, robustness,
or coverage — which is exactly where a project should be after its first
audit cycle. The bureaucracy would call this "reif für die Abnahme".

## Coverage pass result (2026-09-30)

All E-items addressed: 18 new tests (Rust 22→42 unit/integration incl. 4
new CLI unit tests and 3 bridge-lifecycle tests; Java +1 protocol test),
the mock now serves a canned ContentPackage with attachment on
fetchDelivery and a canned ProcessCardBundle on fetchProcessCard, and the
e2e suite asserts the fetched XTA byte-for-byte on disk, the `--json`
shape, and the Laufzettel fields through both plain and encrypted pipes.
Total: 67 → 85 tests, `make lint test audit` green.

## Quality pass result (2026-10-03)

The four quality tracks (measured coverage, crypto/logic parity, security
polish, gates & hygiene) are complete; `make check` is green end to end.
C5 (coverage tooling) closed by `make coverage` with recorded baselines;
C1/C4/B2 closed; the coverage E-items all covered. New findings from this
pass, for the record:

- The strict-compiler gate paid for itself immediately: missing
  `serialVersionUID`, a redundant cast, and usage of the library's
  deprecated PKCS#1 v1.5 constants (now unreachable — PSS is the only
  path). None of these were visible without `-Xlint:all -Werror`.
- JDK XML-DSig interop notes now documented in `ResponseSigner` (header
  doc): the JDK factory rejects rsa-sha256 `SignatureMethod` on this JVM
  (rsa-sha1 works for digest harvesting), and `Id` attributes must be
  registered via `setIdAttributeNS` for `#id` reference resolution.

## F. 2026-10-04 code review (full re-review, baseline 85 tests)

Second full review (scope: everything except caches and `dist/`). Known
A–E items excluded from the list below except where a "fixed" verdict had
regressed. Severity: P1 functional defect, P2 security/robustness,
P3 polish. Baseline: `cargo test` + `mvn test` green.

| # | Where | Issue | Sev | Decision |
|---|---|---|---|---|
| F1 | `OsciOps.java` — feedback passthrough | Library rows are `[lang, code, text]` (FeedbackObject/FeedbackBuilder), rows were forwarded raw while the protocol documents `[text, code]` — the CLI printed `[code] lang` and the rejection *text* never reached any user | P1 | **fixed** (bridge maps to `[text, code]`; `OsciOpsTest` pins it) |
| F2 | `OsciOps.toFetchedContent` — DATA branch | `getContentData()` is the library's lossy UTF-8 string decode; re-encoding corrupted every non-UTF-8 inline payload, violating the "opaque base64 bytes" contract | P1 | **fixed** (stream-based read with null guard; byte-exactness pinned) |
| F3 | `rosci --bridge-jar` | `default_value` made the arg always-`Some`, so the exe-relative release-layout lookup (B1) was dead code from the CLI: `dist/bin/rosci` failed everywhere except `cwd=dist/lib`. Test suites masked it (they set `OSCI_BRIDGE_CMD`/`OSCI_BRIDGE_JAR`) | P1 | **fixed** (arg optional; `osci::default_jar_path` exposed and used) |
| F4 | `rosci` — `url_host_is_loopback` | URL *userinfo* read as host: `http://127.0.0.1:8080@evil.example/entry` passed the `--insecure-transport` loopback guard while the bridge connected to `evil.example` (Java `URI` parses userinfo correctly) | P2 sec | **fixed** (userinfo stripped; guard tests cover both userinfo forms) |
| F5 | `osci::Identity` | AUDIT claimed Rust-side PIN copies are zeroized; the pins were plain `String`s held for the client lifetime | P2 sec | **fixed** (`Zeroizing` in `Identity`/`IdentityMsg`; AUDIT wording now states exactly what is and is not scrubbed) |
| F6 | `OsciClientBuilder::build` | Handshake checked only that `versions` existed — a protocol-v2 jar would pass and fail confusingly later | P2 | **fixed** (`PROTOCOL_VERSION` const, enforced; tests for wrong/missing version) |
| F7 | `rosci fetch` file writing | `fs::write` clobbered existing files (`.bashrc` survives sanitization), followed pre-planted symlinks, and merged same-name contents silently | P2 sec | **fixed** (atomic `create_new`, numbered siblings; symlink tests) |
| F8 | `BridgeTransport.getConnection` | `Content-Length` set via `setRequestProperty` — silently ignored by `HttpURLConnection`; the entire request body was buffered on-heap | P2 | **fixed** (`setFixedLengthStreamingMode`; transport test) |
| F9 | `OsciOps.fetch/processCard` | `exitDialogQuietly` ran only on success — any rejection abandoned an open dialog at the intermediary | P2 | **fixed** (moved to `finally`) |
| F10 | `OsciOps.fetch` — decrypt catch | One `catch (Exception)` swallowed the bridge's own `BridgeException(CRYPTO)` (bad PKCS#12) into the "not decryptable" synthetic subject | P2 | **fixed** (own-crypto errors rethrown) |
| F11 | `BridgeHandle::drop` | `kill()` without `wait()` left a zombie per dropped unresponsive bridge — a leak for library consumers | P2 | **fixed** (bounded reap after SIGKILL) |
| F12 | `make coverage` | e2e exit status discarded (`\|\| true`); a red suite still produced a green coverage number | P2 | **fixed** (status captured, target fails after emitting coverage) |
| F13 | `container/LOCK.md` | cargo-llvm-cov missing from the tool table — A4 recurrence via doc drift | P2 | **fixed** (row added; builder digest marked pending re-record) |
| F14 | `Dockerfile.builder` | Base image pinned by mutable tag (`21-jdk-jammy`); "pins every input" overclaims | P2 | **partially fixed** — observed amd64 digest recorded in LOCK; Dockerfile digest-pin needs the next container rebuild (this session's sandbox cannot run OCI runtimes) |
| F15 | shaded `osci-bridge.jar` | Uber-jar redistributes gson/BC/osci-lib with no license/notice aggregation (`ApacheLicenseResourceTransformer` etc.) | P2 | left open (jar is meant to be shipped as a unit) |
| F16 | README env table | `OSCI_TLS_CA` exists (`main.rs`) but was absent from the table | P2 | **fixed** |
| F17 | `OsciOps` send/fetch/processCard | Mid-flow content-crypto failures (`EncryptedDataOSCI.encrypt`, `coco.sign`) map to `osci` (exit 4) instead of `crypto` (exit 5) | P3 | left open |
| F18 | `signaturesValidQuietly` | Verify *error* returns `false` (= "tampered") with zero logging — no third state | P3 | left open |
| F19 | `OsciOps.fetch` | `subject` never populated on success; the CLI prints `<no subject>` even when the response carries one | P3 | left open |
| F20 | TLS timeouts | 0/negative = wait forever; > 2³¹−1 breaks gson (`Integer` vs Rust `u64`); one hung op deafens the single-threaded bridge | P3 | left open |
| F21 | `CryptoMaterial.P12Signer` | `getAlgorithm()` can return an unmapped constant; `JCA_JCE_MAP.get` unguarded → NPE as `internal` | P3 | left open |
| F22 | `BridgeHandle::call` | id-less responses consumed as the answer to any request (desync misattributed); offending line embedded verbatim in error text | P3 | left open |
| F23 | bridge stdin writes | `write_all`/`flush` unbounded — a stalled JVM hangs the CLI past every documented timeout on multi-MB requests | P3 | left open |
| F24 | `insecure_transport` wire polarity | `false` means insecure — consistent double negative on both sides, rename at protocol v2 | P3 | left open (documented) |
| F25 | `Bridge` catch-all | `getSimpleName + ": " + getMessage()` renders `"...: null"`; non-`Exception` Throwables skip the JSON response entirely | P3 | left open |
| F26 | mock `ResponseSigner.parse` | Default `DocumentBuilderFactory` without XXE hardening (input is mock-generated; defense-in-depth only) | P3 | left open |
| F27 | mock CLI/handling | Last-arg `--key` silently ignored; sequential executor; mid-body write failure re-sends 500 headers | P3 | left open (test-only) |
| F28 | `rosci dvdv` exit codes | File/parse errors exit 3 ("lookup failed") — indistinguishable from a miss for scripts | P3 | left open (arguable) |
| F29 | hygiene batch | `.cache/` not gitignored (**fixed**); `.zcode/` plan file tracked (**fixed**, untracked); `pre-push` backticks executed inside double quotes (**fixed**); CHANGELOG "22 findings" vs grown ledger (reconciled in 0.3.1); `make fuzz` unpinned tooling (**fixed** 2026-10-04: pinned `nightly-2026-10-03` + cargo-fuzz 0.13.2, `|| true` removed); rustup `curl \| sh` unpinned (**fixed** 2026-10-04: checksummed rustup-init 1.29.1, digest-pinned base image); `make clean` incomplete, `deny.toml` bans unchecked, `verify-deps` ignores extra artifacts — left open | P3 | mixed |

Protocol cross-check (independent, both languages): `docs/PROTOCOL.md` ↔
`protocol.rs` ↔ `Protocol.java` fully consistent; exit codes match README
and PROTOCOL everywhere; test count claims verified exact at review time.
Transport crypto in the mock is sound (fresh IV, AEAD, RSA-OAEP); no XXE
in the bridge's main path, no traversal, no redirect following, no weak
RNG.
