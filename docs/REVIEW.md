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
| F29 | hygiene batch | `.cache/` not gitignored (**fixed**); `.zcode/` plan file tracked (**fixed**, untracked); `pre-push` backticks executed inside double quotes (**fixed**); CHANGELOG "22 findings" vs grown ledger (reconciled in 0.3.1); `make fuzz` unpinned tooling (**fixed** 2026-10-04: pinned `nightly-2026-10-03` + cargo-fuzz 0.13.2, `|| true` removed); rustup `curl \| sh` unpinned (**fixed** 2026-10-04: checksummed rustup-init 1.29.1, digest-pinned base image); `make clean` incomplete (**fixed** 2026-10-04: full `clean` target incl. `.deps`/`.rustup`/coverage/fuzz trees, plus `clean-image`), `deny.toml` bans unchecked (**left open**), `verify-deps` ignores extra artifacts (**left open**) | P3 | mixed |

Protocol cross-check (independent, both languages): `docs/PROTOCOL.md` ↔
`protocol.rs` ↔ `Protocol.java` fully consistent; exit codes match README
and PROTOCOL everywhere; test count claims verified exact at review time.
Transport crypto in the mock is sound (fresh IV, AEAD, RSA-OAEP); no XXE
in the bridge's main path, no traversal, no redirect following, no weak
RNG.


## G — full file-by-file review (2026-10-05, third pass)

**Method.** All 139 tracked files reviewed after ~9,100 changed lines
since F (0.3.1). Five independent fresh-eyes reviewers, one per cluster
(Rust library, Rust CLI+tests, Java bridge, mock+harness, docs+configs),
each with the changed-since-F list and the known-open findings (F15–F29,
AUDIT limitations, STANDARD-COMPLIANCE §7) so nothing was blindly
re-filed. Every P1/P2 was then independently verified against the code
by the lead before entering the ledger below; the full file-by-file
ledger follows the findings tables — every file accounted for, clean or
otherwise.

**Result: 1 × P1, 8 × P2, 41 × P3. 42 fixed with tests/verification, 8
left open (all P3, listed).** Cross-mirror checks re-run after F's
verdict: `PROTOCOL.md` ↔ `protocol.rs` ↔ `Protocol.java` remain 1:1
including the new `attachments`/`chunk_size_kb`/`metadata_*` fields;
exit-code tables consistent; README flags match the CLI (synopsis drift
fixed as G27); test-count claims now match reality everywhere (G8, G47).

### G findings — P1/P2 (all fixed)

| # | Where | Issue | Sev | Decision |
|---|---|---|---|---|
| G1 | `java/…/OsciOps.java` — chunked send | The reassembled StoreDelivery's verdict arrives as **inside feedback** on the last chunk's response — a separate field from the per-chunk header feedback, which *was* classified. A rejected reassembly therefore returned `ok:true` with the rejection folded into `result.feedback`; the plain send path fails loudly on the identical verdict. Unreachable-by-test today (mock has no chunk handling), so live-verified reasoning: per EFFI the complete-message verdict lives only in the inside feedback. | P1 | **fixed** — inside feedback now runs through `checkFeedbackRows` before mapping; classification matrix pinned in `OsciOpsTest` |
| G2 | `java/…/OsciOps.java` — `send()` | No `finally { exitDialogQuietly(dialog); }` — unlike fetch/process-card. Every send (success or failure, including chunk 3 of 5 dying) abandoned an open dialog (ConversationId, SequenceNumber) at the intermediary for the lifetime of the sidecar. | P2 | **fixed** — `finally` added; the orphaned-partial-chunks residue at the manager (timeout-purged) is now documented in the method. Verification bonus: the newly surfaced ExitDialog requests exposed the mock's schema-non-conform ConversationId (see finding 7 in STANDARD-COMPLIANCE §7), also fixed |
| G3 | `java/…/OsciOps.java` — `fetch()` encrypted branch | `signatures_valid` was computed only for plain containers. Since the default is sign+encrypt, essentially every real fetch printed „signatures valid: unknown" — the check was simply never performed on the common path (adjacent to, but distinct from, F18's third-state question). | P2 | **fixed** — `signaturesValidQuietly(inner)` after decrypt |
| G4 | `container/osv-java.sh` — attribution loop | Per-artifact re-query swallowed curl failures (`|| true` → empty → `continue`): any mid-loop network error converted a flagged artifact into "clean". A security gate that fails open. | P2 | **fixed** — query failures are recorded as `(query-failed)` unresolved results and fail the gate |
| G5 | `java/…/mock/MockIntermediary.java` — inner dump | `request-N.inner.xml` was decoded UTF-8 then written ISO-8859-1: non-ASCII envelope content became mojibake with a declaration still claiming utf-8 (spurious xmllint failures; silent loss above U+00FF). Latent — e2e fixtures are ASCII. | P2 | **fixed** — byte-exact `dumpBytes` for the inner envelope; Latin-1 roundtrip kept only for raw transport dumps where it is a bijection |
| G6 | `crates/osci` — `Identity`/`Tls`/`IdentityMsg`/`TlsMsg` + `OsciClient` Debug | zeroize 1.9.0's derived `Debug` **prints the inner value**, so the derived impls put every PIN on the log under `{:?}` — an unscrubbed copy that outlives zeroization, contradicting config.rs's own claim. Latent (nothing logs these types today). | P2 | **fixed** — hand-written redacting Debug impls (lengths, `<redacted>`); `OsciClient` Debug now reports `tls_configured` instead of the struct |
| G7 | `crates/osci` — `OsciClient::shutdown` | `shutdown()` → `bridge.wait()` blocks **unboundedly** if the JVM acks shutdown but never exits; Drop's grace-then-kill never runs because the client is stuck before drop. The explicit path was less defensive than drop. | P2 | **fixed** — `BridgeHandle::shutdown_and_wait()` mirrors Drop's grace/kill/reap; `shutdown()` uses it |
| G8 | `docs/AUDIT.md` — test inventory | Row claimed `osci` unit/integration (50); actual is 53 (28 lib + 25 integration incl. 3 proptests). Table contradicted README's 117 total. | P2 | **fixed** — (53, incl. 3 proptest) |
| G9 | `docs/STANDARD-COMPLIANCE.md` — §3.4 vs §7/§8 | Internal contradiction: §3.4 called the schema-conformance harness „planned … Not built yet" while §7 item 6 and the CHANGELOG describe it as built. Pre-harness draft residue. | P2 | **fixed** — §3.4/§8 now past tense; §7 obligation 2 marked closed |

### G findings — P3 (filed; trivial ones fixed in the same pass)

| # | Where | Issue | Decision |
|---|---|---|---|
| G10 | `OsciOps.java` chunk math + CLI | `chunk_size_kb` 0 silently disabled chunking; ≥ 2^21 overflowed the int multiply into a crash | **fixed** (CLI range 1..=2_097_151 + long arithmetic in Java) |
| G11 | `OsciOps.java` — totalKb | floor-truncated KB announced to the intermediary (0 for a 500-byte message) | **fixed** (ceiling) |
| G12 | `OsciOps.java` — attachments loop | `[null]` / missing `data` dereferenced unguarded → INTERNAL instead of a named PROTOCOL error | **fixed** (`require`) |
| G13 | `OsciOps.java` — MsgSize | counted only the main payload, not attachments | **fixed** (sum) |
| G14 | `OsciOps.java` — main content | `content.content_type` silently ignored (only attachments honored it) | **fixed** |
| G15 | `Bridge.java` — missing-op error | dropped the correlation id | **fixed** |
| G16 | `OsciOps.java` — chunked send | mid-sequence failure leaves orphaned partial chunks at the manager until timeout — now documented in the method | **fixed (doc)** |
| G17 | `OsciOps.java` — chunked fetch | intermediary-controlled `totalChunkNumbers` drives an unbounded loop; no assembled-size cap | left open |
| G18 | `BridgeTransport.java` | HTTP error statuses surface as transport IOExceptions; fault body never read | left open |
| G19 | `bridge.rs` — `call()` | after a timeout the late response stays queued; every later call fails with misleading id-mismatch errors | left open (related F22) |
| G20 | `bridge.rs` — reader thread | `lines()` has no length cap; a runaway bridge grows memory unboundedly | left open (related F23) |
| G21 | `bridge.rs` — `spawn` | reader-thread spawn failure orphaned the JVM (no kill/reap on that path) | **fixed** |
| G22 | `OsciClientBuilder::build` | no URL-scheme check (unlike the DVDV path) — `file://` surfaces JVM-side | **fixed** |
| G23 | `Identity::from_p12_files` | decrypter p12/pin accepted in any combination; mismatch fails far away JVM-side | **fixed** (both-or-neither) |
| G24 | `xta.rs` — root warning | prefixed roots (`<xta:XTA>`) always triggered the "not XTA" warning | **fixed** (prefix stripped) |
| G25 | `main.rs` — fetch | `--all` + `--message-id` silently ignored `--all` | **fixed** (`conflicts_with`) |
| G26 | `main.rs` — send/fetch | `--chunk-size-kb 0` silently disabled chunking | **fixed** (value range) |
| G27 | `README.md` — synopsis | missing `--tls-client-pin`/`--insecure-transport`; status/fetch lines omitted required connection flags | **fixed** |
| G28 | `interop.rs` — `gate()` | fixture checksum verification ran after the network preflight (tampering undetected when offline) | **fixed** (verify first) |
| G29 | `e2e.rs` — metadata assertion | asserted only the generic header name, not the author identifier | **fixed** |
| G30 | `xsd-validate.sh` — Auftrag scan | `PartialStoreDelivery` contains `StoreDelivery`; unordered token scan could pick the wrong schema | **fixed** (anchored match) |
| G31 | `interop.rs` — `fetch --all` leg | depends on alice's shared public postbox staying empty | left open (documented) |
| G32 | `conn_tls` | zero test coverage for the new TLS flag logic | **fixed** (4 unit tests) |
| G33 | `cli.rs` — help test | name promised exit codes, body asserted `--to` | **fixed** (root help asserted) |
| G34 | `Makefile` — fuzz | `| tail -12` masked the fuzzer's exit status | **fixed** (pipefail) |
| G35 | `Makefile` — clean | missed `fuzz/artifacts` (crash artifacts survived) | **fixed** |
| G36 | `xsd-validate.sh` — response path | unanchored `request-` substitution broke in dirs containing "request-" | **fixed** (anchored) |
| G37 | `xsd-validate.sh` — empty dir | 0 validated / 0 skipped exited 0 | **fixed** (dir check + empty guard) |
| G38 | `MockIntermediary.java` — error path | double `sendResponseHeaders` on post-header failures; exchange lingers | left open (local-only) |
| G39 | `tests/gen-pki.sh` | stale comment, swallowed openssl errors, loose umask | **fixed** |
| G40 | `.github/dependabot.yml` | fuzz crate uncovered | **fixed** |
| G41 | `.github/workflows/ci.yml` | no `permissions:` block, no concurrency cancel | **fixed** |
| G42 | `container/record-lock.sh` | base image hardcoded instead of derived from the Dockerfile | **fixed** |
| G43 | `container/Dockerfile.builder` | cargo registry dead weight in the image; single layer for two tools | left open |
| G44 | `Makefile` — bind mount | no SELinux `:Z` label (Fedora/RHEL podman trap), undocumented | left open (documented in ledger) |
| G45 | `CHANGELOG.md` — 0.4.0 | internally inconsistent artifact counts (77 vs 80; manifest now 90) | **fixed** (count qualified) |
| G46 | `README.md` — audit line | under-described `make audit` (OSV scan invisible) | **fixed** |
| G47 | `docs/STANDARD-COMPLIANCE.md` | interop suite „9 tests" → 11 | **fixed** |
| G48 | `docs/AUDIT.md` — coverage | JaCoCo 0.8.13 → 0.8.15 | **fixed** |
| G49 | `docs/AUDIT.md` — limitation 3 | conflated `--dvdv-file` (send) and `--file` (dvdv find) | **fixed** |
| G50 | `docs/STANDARD-COMPLIANCE.md` — §3.4 | interop test count and harness status drift (with G9) | **fixed** |

### Rejected findings (reported by reviewers, not reproducible / duplicates)

- „fetch subject never populated" (Java bridge) — this is known-open **F19**, not a new finding; remains open.
- „chunk overflow" reported independently by two reviewers — merged into G10.
- „Empty DER file returns Ok("")" — accepted behavior; fails JVM-side with a clean error, not worth code (recorded in non-findings).



**Rust library — `crates/osci/`**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `crates/osci/Cargo.toml` | — | clean | — |
| `crates/osci/src/bridge.rs` | yes | findings | G6 G19 G20 G21 |
| `crates/osci/src/client.rs` | yes | findings | G6 G7 |
| `crates/osci/src/config.rs` | yes | findings | G6 G23 |
| `crates/osci/src/dvdv.rs` | — | clean | — |
| `crates/osci/src/error.rs` | — | clean | — |
| `crates/osci/src/lib.rs` | yes | clean | — |
| `crates/osci/src/protocol.rs` | yes | findings | G6 |
| `crates/osci/src/xta.rs` | — | findings | G24 |
| `crates/osci/tests/bridge_lifecycle.rs` | yes | clean | — |
| `crates/osci/tests/client_flows.rs` | — | clean | — |
| `crates/osci/tests/proptests.proptest-regressions` | — | clean | — |
| `crates/osci/tests/proptests.rs` | — | clean | — |

**Rust CLI — `crates/osci-cli/`**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `crates/osci-cli/Cargo.toml` | yes | clean | — |
| `crates/osci-cli/src/main.rs` | yes | findings | G25 G26 G32 |
| `crates/osci-cli/tests/cli.rs` | — | findings | G33 |
| `crates/osci-cli/tests/e2e.rs` | yes | findings | G29 |
| `crates/osci-cli/tests/fixtures/interop/SHA256SUMS` | new | clean | — |
| `crates/osci-cli/tests/fixtures/interop/alice_signature_4096.p12` | new | clean | — |
| `crates/osci-cli/tests/fixtures/interop/bob_cipher_4096.p12` | new | clean | — |
| `crates/osci-cli/tests/fixtures/interop/bob_cipher_4096.pem` | new | clean | — |
| `crates/osci-cli/tests/fixtures/interop/bob_signature_4096.p12` | new | clean | — |
| `crates/osci-cli/tests/fixtures/interop/carol_cipher_4096.p12` | new | clean | — |
| `crates/osci-cli/tests/fixtures/interop/osci_manager_cipher_4096.pem` | new | clean | — |
| `crates/osci-cli/tests/interop.rs` | new | findings | G31 |

**Java bridge — `java/osci-bridge/`**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `java/osci-bridge/DEPENDENCY_MANIFEST.sha256` | yes | clean | — |
| `java/osci-bridge/pom.xml` | yes | clean | — |
| `java/osci-bridge/src/main/java/de/deshittifier/osci/bridge/Bridge.java` | — | findings | G15 |
| `java/osci-bridge/src/main/java/de/deshittifier/osci/bridge/BridgeException.java` | — | clean | — |
| `java/osci-bridge/src/main/java/de/deshittifier/osci/bridge/BridgeTransport.java` | — | findings | G18 |
| `java/osci-bridge/src/main/java/de/deshittifier/osci/bridge/CryptoMaterial.java` | — | clean | — |
| `java/osci-bridge/src/main/java/de/deshittifier/osci/bridge/OsciOps.java` | yes | findings | G1 G2 G10 G12 G13 G14 G16 |
| `java/osci-bridge/src/main/java/de/deshittifier/osci/bridge/Protocol.java` | yes | clean | — |
| `java/osci-bridge/src/test/java/de/deshittifier/osci/bridge/BridgeLoopTest.java` | — | clean | — |
| `java/osci-bridge/src/test/java/de/deshittifier/osci/bridge/BridgeTransportTest.java` | — | clean | — |
| `java/osci-bridge/src/test/java/de/deshittifier/osci/bridge/CryptoMaterialTest.java` | — | clean | — |
| `java/osci-bridge/src/test/java/de/deshittifier/osci/bridge/OsciOpsTest.java` | yes | clean | — |
| `java/osci-bridge/src/test/java/de/deshittifier/osci/bridge/ProtocolTest.java` | — | clean | — |

**Java mock — `java/osci-mock/`**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `java/osci-mock/pom.xml` | yes | clean | — |
| `java/osci-mock/src/main/java/de/deshittifier/osci/mock/MockIntermediary.java` | — | findings | G5 |
| `java/osci-mock/src/main/java/de/deshittifier/osci/mock/ResponseSigner.java` | — | clean | — |
| `java/osci-mock/src/main/java/de/deshittifier/osci/mock/TransportCrypto.java` | — | clean | — |

**Schemas — `schema/` (vendored; provenance + conformance sampling, not line-read)**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `schema/AcceptDelivery.xsd` | new | clean | — |
| `schema/ChunkInfo.xsd` | new | clean | — |
| `schema/EFFI.xsd` | new | clean | — |
| `schema/ExitDialog.xsd` | new | clean | — |
| `schema/FetchDelivery.xsd` | new | clean | — |
| `schema/FetchProcessCard.xsd` | new | clean | — |
| `schema/ForwardDelivery.xsd` | new | clean | — |
| `schema/GetMessageId.xsd` | new | clean | — |
| `schema/InitDialog.xsd` | new | clean | — |
| `schema/MediateDelivery.xsd` | new | clean | — |
| `schema/PROVENANCE.md` | new | clean | — |
| `schema/PartialFetchDelivery.xsd` | new | clean | — |
| `schema/PartialFetchDeliveryOldNS.xsd` | new | clean | — |
| `schema/PartialStoreDelivery.xsd` | new | clean | — |
| `schema/PartialStoreDeliveryOldNS.xsd` | new | clean | — |
| `schema/ProcessDelivery.xsd` | new | clean | — |
| `schema/ResponseToAcceptDelivery.xsd` | new | clean | — |
| `schema/ResponseToExitDialog.xsd` | new | clean | — |
| `schema/ResponseToFetchDelivery.xsd` | new | clean | — |
| `schema/ResponseToFetchProcessCard.xsd` | new | clean | — |
| `schema/ResponseToForwardDelivery.xsd` | new | clean | — |
| `schema/ResponseToGetMessageId.xsd` | new | clean | — |
| `schema/ResponseToInitDialog.xsd` | new | clean | — |
| `schema/ResponseToMediateDelivery.xsd` | new | clean | — |
| `schema/ResponseToPartialFetchDelivery.xsd` | new | clean | — |
| `schema/ResponseToPartialFetchDeliveryOldNS.xsd` | new | clean | — |
| `schema/ResponseToPartialStoreDelivery.xsd` | new | clean | — |
| `schema/ResponseToPartialStoreDeliveryOldNS.xsd` | new | clean | — |
| `schema/ResponseToProcessDelivery.xsd` | new | clean | — |
| `schema/ResponseToStoreDelivery.xsd` | new | clean | — |
| `schema/StoreDelivery.xsd` | new | clean | — |
| `schema/catalog.xml` | new | clean | — |
| `schema/extern/XMLSchema.dtd` | new | clean | — |
| `schema/extern/datatypes.dtd` | new | clean | — |
| `schema/extern/soap-envelope.xsd` | new | clean | — |
| `schema/extern/xenc-schema-11.xsd` | new | clean | — |
| `schema/extern/xenc-schema.xsd` | new | clean | — |
| `schema/extern/xml.xsd` | new | clean | — |
| `schema/extern/xmldsig-core-schema.xsd` | new | clean | — |
| `schema/order.xsd` | new | clean | — |
| `schema/order_zusatz.xsd` | new | clean | — |
| `schema/oscienc.xsd` | new | clean | — |
| `schema/oscisig.xsd` | new | clean | — |
| `schema/soapAcceptDelivery.xsd` | new | clean | — |
| `schema/soapExitDialog.xsd` | new | clean | — |
| `schema/soapFetchDelivery.xsd` | new | clean | — |
| `schema/soapFetchProcessCard.xsd` | new | clean | — |
| `schema/soapForwardDelivery.xsd` | new | clean | — |
| `schema/soapGetMessageId.xsd` | new | clean | — |
| `schema/soapInitDialog.xsd` | new | clean | — |
| `schema/soapMediateDelivery.xsd` | new | clean | — |
| `schema/soapMessageEncrypted.xsd` | new | clean | — |
| `schema/soapMessageFault.xsd` | new | clean | — |
| `schema/soapPartialFetchDelivery.xsd` | new | clean | — |
| `schema/soapPartialStoreDelivery.xsd` | new | clean | — |
| `schema/soapProcessDelivery.xsd` | new | clean | — |
| `schema/soapResponseToAcceptDelivery.xsd` | new | clean | — |
| `schema/soapResponseToExitDialog.xsd` | new | clean | — |
| `schema/soapResponseToFetchDelivery.xsd` | new | clean | — |
| `schema/soapResponseToFetchProcessCard.xsd` | new | clean | — |
| `schema/soapResponseToForwardDelivery.xsd` | new | clean | — |
| `schema/soapResponseToGetMessageId.xsd` | new | clean | — |
| `schema/soapResponseToInitDialog.xsd` | new | clean | — |
| `schema/soapResponseToMediateDelivery.xsd` | new | clean | — |
| `schema/soapResponseToPartialFetchDelivery.xsd` | new | clean | — |
| `schema/soapResponseToPartialStoreDelivery.xsd` | new | clean | — |
| `schema/soapResponseToProcessDelivery.xsd` | new | clean | — |
| `schema/soapResponseToStoreDelivery.xsd` | new | clean | — |
| `schema/soapStoreDelivery.xsd` | new | clean | — |

**Harness — `container/`, `tests/`, `fuzz/`, `.github/`**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `.github/dependabot.yml` | new | findings | G40 |
| `.github/workflows/ci.yml` | new | findings | G41 |
| `container/Dockerfile.builder` | yes | findings | G43 |
| `container/LOCK.md` | yes | clean | — |
| `container/jacoco-summary.sh` | — | clean | — |
| `container/osv-java.sh` | new | findings | G4 |
| `container/record-lock.sh` | yes | findings | G42 |
| `container/xsd-validate.sh` | new | findings | G30 G36 G37 |
| `fuzz/Cargo.lock` | yes | clean | — |
| `fuzz/Cargo.toml` | — | clean | — |
| `fuzz/fuzz_targets/bridge_response_parse.rs` | — | clean | — |
| `tests/gen-pki.sh` | — | findings | G39 |

**Docs — `docs/`**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `docs/AUDIT.md` | yes | findings | G8 G47 G48 G49 |
| `docs/PROTOCOL.md` | yes | clean | — |
| `docs/REVIEW.md` | yes | clean | — |
| `docs/STANDARD-COMPLIANCE.md` | new | findings | G9 G47 |
| `docs/TEST-INFRASTRUCTURE.md` | yes | clean | — |

**Root configs**

| File | Δ since F | Verdict | Findings |
|---|---|---|---|
| `.editorconfig` | — | clean | — |
| `.gitattributes` | — | clean | — |
| `.gitignore` | yes | clean | — |
| `CHANGELOG.md` | yes | findings | G45 |
| `Cargo.lock` | yes | clean | — |
| `Cargo.toml` | yes | clean | — |
| `LICENSE` | — | clean | — |
| `Makefile` | yes | findings | G34 G35 |
| `README.md` | yes | findings | G27 G46 |
| `deny.toml` | — | clean | — |
| `rust-toolchain.toml` | new | clean | — |
