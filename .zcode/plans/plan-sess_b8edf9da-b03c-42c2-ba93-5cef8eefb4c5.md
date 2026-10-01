# Quality pass: measured coverage, full crypto parity, security polish, gates

Five phases, committed per phase. Continues the mission rules (containers, no traces,
no push). Baseline: 85 tests green, `make lint test audit` clean.

## Phase A — Measured coverage (foundation: measure before building)

1. **cargo-llvm-cov** (pinned version, installed into the builder image like cargo-deny).
   New `make coverage` target: `cargo llvm-cov --workspace --lcov` → prints line summary,
   writes `coverage/lcov.info` (gitignored). e2e excluded (needs the jar; note in output).
2. **JaCoCo** for `java/osci-bridge` (pinned plugin version in pom) — `mvn verify` emits
   `java/osci-bridge/target/site/jacoco/` summary; `make coverage` prints its totals too.
3. **Record baselines** in `docs/AUDIT.md` (a small table: crate/line-%, bridge/line-%)
   with the honest note that e2e coverage isn't in the number.
4. **proptest** (dev-dep, pinned): protocol `Response` parsing never panics on arbitrary
   strings; `sanitize_filename` idempotence + charset closed under composition;
   `sniff_root_element` invariants (BOM × declaration × comment × whitespace compositions
   still yield the root or None, never panic).
5. **cargo-fuzz** smoke: `fuzz/` crate with one target (arbitrary bytes →
   `serde_json::from_str::<Response>` path used by the bridge reader). `make fuzz`
   runs a 60-second smoke inside the container; NOT part of the default gate.

## Phase B — Crypto/logic parity (closes the last AUDIT limitation)

6. **Encrypted fetch content**: extract reusable wrap/encrypt helpers in
   `TransportCrypto`; mock's canned fetchDelivery message gains an
   `xenc:EncryptedData` part encrypted to the client's cipher cert alongside the plain
   content. Exercises the bridge's `EncryptedDataOSCI.decrypt(Reader)` path and
   `encrypted_contents` mapping. E2e asserts the decrypted payload matches the canned
   secret through `fetch --json`.
7. **Signed responses (the big one)**: study the client's own `ds:Signature` header
   structure from request dumps + `OSCISignatureBuilder`/verification sources; mock
   signs response envelopes with `intermed-sign` using the JDK's
   `javax.xml.crypto.dsig` (XMLSignatureFactory, exclusive c14n, references over
   Body/ControlBlock Ids — mirrored from the wire format, same iterative method as the
   transport-encryption round). Bridge verifies supplier signatures when present and
   reports `transport_signature_valid` in the protocol response. E2e: secure test
   asserts signature valid; one tampered-signature scenario asserts the failure is
   surfaced, not swallowed. AUDIT limitation #1 → closed. *Fallback if c14n interop
   refuses to converge after a real effort: keep the asterisk, document precisely why.*
8. **Large-payload probe**: e2e sending a generated ~5 MB XTA through both plain and
   secure transports. If the library demands chunking (`PartialStoreDelivery`) above a
   threshold: document the threshold in AUDIT/README and implement chunked send via the
   library's chunk helpers as a stretch goal; timeboxed to probe + document otherwise.

## Phase C — Security polish

9. **Loopback guard**: `--insecure-transport` refuses non-loopback intermediary hosts
   unless the equally-honest `--insecure-transport-any-host` is also given. Pure host
   classifier (localhost/127.0.0.1/::1) + unit tests for it.
10. **PIN zeroization (Rust side)**: `zeroize` crate for pin storage in `Identity`;
    document the irreducible JVM-side string residency in AUDIT honestly.
11. **Jar fingerprint**: bridge `ping` computes the SHA-256 of its own jar →
    `versions["jar_sha256"]`; `rosci version` prints it. E2e asserts a 64-hex value.
    Additive protocol field — PROTOCOL.md wording updated to say additive optional
    fields don't bump the version (breaking changes do).

## Phase D+E — Gates & hygiene

12. **Rust lints**: `[lints]` in `osci` crate — `missing_docs = "deny"`, clippy
    `unwrap_used`/`expect_used` = warn (lib only; tests exempt). **Java**: compiler
    `-Xlint:all` + `failOnWarning` in both poms.
13. **Review leftovers**: dedupe the three shutdown dances (C1); document
    `OSCI_JAVA_OPTS` in `rosci --help` footer (C4); `free_port` retry ×3 (B2).
14. **Reproducible jar**: `project.build.outputTimestamp` in the bridge pom →
    byte-identical jars across builds; verify by building twice and comparing SHA-256s;
    record the experiment in AUDIT.md.
15. **`make check`**: aggregate target (lint + test + audit + verify-deps + git-guard).
16. **CHANGELOG.md**: backfilled from git history (W1–W7, rosci rename, crypto mock,
    review + coverage pass, this pass), Keep-a-Changelog format.

## Order & acceptance

A → B → C → D+E, one commit per phase (plus REVIEW.md updates as findings appear).
Final gate: `make check` green, coverage numbers recorded, all prior tests still pass,
no new git remote. PROTOCOL.md gains the additive-fields rule; AUDIT.md limitation #1
closed (or precisely documented fallback); REVIEW.md updated with new findings from
this pass.