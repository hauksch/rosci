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
| C4 | `BridgeConfig::java_jar` | Reads `OSCI_JAVA_OPTS` from the environment at construction — impure constructor, and the env var is documented in README but absent from `--help` | low | env var now covered by unit test; `--help` gap left open |
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
