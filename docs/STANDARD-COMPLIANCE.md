# Standard compliance — where OSCI 1.2 is defined and how rosci compares

Answers two questions: **where the standard normatively lives**, and
**how rosci is measured against it**. Status lines are as of
2026-10-04; the interop evidence they cite is
docs/TEST-INFRASTRUCTURE.md.

## 1. Where the standard is defined

Normative set (xoev.de,
[Versionsübersicht](https://www.xoev.de/osci-xta/standard-osci-transport-1-2/osci-versionsuebersicht-23217)):

| Artifact | URL (under www.xoev.de) | Role |
|---|---|---|
| OSCI-Transport 1.2 – Spezifikation (de, FINAL 2002-06-06) | `/sixcms/media.php/13/osci_spezifikation_1_2_deutsch.pdf` | the normative text |
| same, English | `/sixcms/media.php/13/osci-specification_1_2_english.pdf` | translation |
| **Korrigenda 1–10** (zip) + K8/K9/K10 individually (2024-01-12 / 2025-05-26 / 2026-02-13) | `/sixcms/media.php/13/OSCI_Korrigenda.zip`, `Korrigenda_8.pdf`, `Korrigenda_9.pdf`, `Korrigenda_10.pdf` | individually **authoritative corrections** |
| OSCI-Transport 1.2 XML-Schema incl. K1–10 (2026-05-07) | zip on the same page | **normative wire vocabulary** |
| Ergänzung: Effiziente Übertragung großer Datenmengen | same page | normative extension (chunking) |
| Ergänzung: Neuer Laufzettel (2026-04-28) | same page (spec + schema zip) | normative extension |
| „mit integrierten Korrigenda 1–10" | `/sixcms/media.php/13/OSCI-1.2_mit_Korrigenda.pdf` | **nicht-normativ** consolidation — but the only practical full text; §5/§6.6.9/§6.6.10/§7 quotes elsewhere in this repo reference it |

Mirrored and machine-usable: the reference implementation
[governikus/osci/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java)
(tag 2.6.1 = the artifact rosci wraps) carries the complete schema set
in `osci-bibliothek-lib/osci-schema/src/main/resources/schema/` — every
Auftrag as `*.xsd` plus `soap*.xsd` wrappers, `order.xsd` (content,
SelectionRule, attachments), `oscisig.xsd`/`oscienc.xsd` (crypto), and
the W3C externals (xmldsig, xenc, SOAP). De-facto normative context:
BSI TR-02102 crypto parameters (operators enforce them, e.g. RSA
≥ 3072 bit since 2024) and DVDV (addressing — a separate standard).
**OSCI 2.0 and XTA 2 are successor standards, explicitly out of scope
here.**

## 2. What conformance means (spec §7 — the catalog)

A conforming system must (1) use the prescribed namespaces, (2) produce
schema-conform XML, and (3) follow the reaction rules of chapter 5 and
use its feedback codes. Decisively: **„Softwaresysteme für
Intermediäre müssen alle Auftragstypen unterstützen. Softwaresysteme
für Benutzer und Dienstanbieter brauchen nur Unterstützung für die
jenigen Auftragstypen, die sie für ihren Einsatzzweck benötigen."** —
rosci is Benutzer software (sender + fetching recipient), so
conformance is judged against the order types it claims, not against
all ten.

## 3. How rosci is compared (the method)

1. **Inherited wire conformance.** The bridge embeds
   `de.osci:osci-bibliothek:2.6.1` — the standard's reference
   implementation, pinned by hash in the build. Message construction,
   crypto and dialog handling are conformant *by provenance*; rosci's
   job is to expose them without getting in their way.
2. **Behavioral conformance.** `make interop` (9 tests, live against
   the reference intermediary product) proves the messages rosci
   produces are accepted, responses verified, feedback classified.
   The spec cannot be executed; the reference intermediary accepting
   our traffic is the strongest practical check.
3. **Feature completeness** — the matrices below: every order type and
   mechanism, who owns it (library / bridge / CLI), status, evidence.
4. **Schema conformance (planned).** The mock intermediary dumps
   decrypted OSCI messages; a harness validating those dumps with
   `xmllint --schema` against the `osci-schema` XSDs (catalog.xml
   resolves the W3C externals) would close §7 obligation (2) with a
   test. Not built yet.
5. **Feedback-code conformance.** Classification tests pin the §5
   behavior (0xxx success, 3800 warning tolerated, 9xxx/3707 fail);
   deviations documented in §5 below.

## 4. Order-type matrix (spec chapter 6.6 / XSD inventory)

| Auftrag (XSD) | Who owns it in rosci | Status | Evidence |
|---|---|---|---|
| InitDialog | library + bridge (one per operation) | full | e2e + interop |
| GetMessageId | library + bridge (internal to send) | full | interop `send_secure…` |
| StoreDelivery | bridge `send` + CLI | full (single content + subject; no multi-attachment) | interop: three send variants live |
| FetchDelivery | bridge `fetch` + CLI | full for BY_MESSAGE_ID and ALL (spec rule 3); BY_DATE_OF_RECEPTION bridge-mapped but CLI-unexposed; BY_RECENT_MODIFICATION was a latent crash, fixed | interop: by-id round trip, `--all`, isolation |
| FetchProcessCard | bridge `status` + CLI | partial (BY_MESSAGE_ID only; this manager retains no cards — 9804 live) | interop: structured rejection |
| ExitDialog | bridge (implicit `exitDialogQuietly`) | partial by design — dialogs are one-shot (init → one Auftrag → exit); no exposed operation, no cross-request dialog reuse | e2e (dialog closed on error paths) |
| ForwardDelivery | — | **none** — sender variant addressing a service provider by URL; N/A for the user-to-user scope rosci claims | — |
| MediateDelivery | — | **none** — Abwicklungsauftrag (synchronous service-provider scenario) | — |
| ProcessDelivery | — | **none** — supplier side of a service provider | — |
| AcceptDelivery | — | **none** — supplier side (the mock plays intermediary/backend; rosci does not act as Dienstanbieter) | — |
| PartialStore/FetchDelivery, ChunkInfo (EFFI) | library has it; bridge/CLI do not use it | **none — documented loud failure** for large payloads (~2 MB regression case) | e2e large-payload test |

Forward/Mediate/Process/Accept being absent is **conformant** (§7
license) — but it means rosci cannot speak to service providers
(Dienstanbieter scenarios) nor *be* one. That is a scope statement, not
a gap; revisit if a use case demands it.

## 5. Feedback & reaction rules (spec chapter 5)

- Outcome rule „letzte Rückmeldung Erfolgsmeldung **oder Warnung** ⇒
  Auftrag ausgeführt": rosci is **stricter** — any feedback row outside
  0xxx fails the request, with exactly one tolerated exception: 3800
  „weitere Zustellungen liegen vor" (§6.6.10), pinned by
  `OsciOpsTest`. Reason: intermediaries use the 3-class for hard
  rejections too (3707 „Certificate is selfsigned" refuses the
  delivery), so blanket warning-tolerance would launder real
  rejections. Documented deviation, conservative direction.
- Feedback codes observed live and classified: 0800/0801 (success),
  3800 (warning, tolerated), 3707 (rejection), 9803/9804 (rejection).
  The full §5.2 code table is **not** exhaustively mapped — unknown
  codes fail loudly (exit 4) with the mapped text, which is the safe
  default; extend the classification only on evidence.
- Exit codes: `4` transport/OSCI rejection, `5` crypto, `2` config —
  mapped per docs/PROTOCOL.md.

## 6. Security mechanisms (spec chapter 4 / oscisig·oscienc)

| Mechanism | Status | Notes |
|---|---|---|
| Order/content signatures | full via library (RSA-PSS, SHA-256+), `--no-sign` exposes the toggle | beyond the 2002 baseline (SHA-1/rsa-sha1/1024-bit) that BSI TR-02102 deprecates |
| Content + transport encryption | full via library (RSA-OAEP + AES-256-GCM; AES-GCM per Korrigenda 5), `--no-encrypt` toggle | fetch-side decryption live-verified byte-exact |
| Response signature verification (supplier) | full, automatic (`response_signed` surfaced) | live-verified |
| Challenge/Response, ConversationId, SequenceNumber | full via library; dialogs one-shot | no cross-request dialog reuse |
| MessageId / duplicate-submission protection | full via library (GetMessageId before every StoreDelivery) | |
| TLS client authentication | bridge-capable, **CLI does not expose it** (`--tls-ca` only) | exposure gap, not a conformance gap |
| Timestamps / process cards | partial — see FetchProcessCard row; „Neuer Laufzettel" Ergänzung (2026) unsupported | |
| DVDV addressing | separate standard; rosci: local extract only (documented mission decision) | |

## 7. Deviations & gaps summary (the actionable list)

1. **Chunking (EFFI)** — the one spec-relevant gap with operational
   impact: intermediaries that require PartialStoreDelivery for large
   messages are out of reach. Loud failure by design. *(Fix candidate:
   expose the library's existing PartialStoreDelivery.)*
2. **TLS client-auth flag** missing in the CLI (bridge supports it).
3. **Single-content send** — the standard allows multiple content
   blocks/attachments per Zustellung; rosci sends exactly one opaque
   XTA file (fetch side parses attachments fine).
4. **Ergänzungen unsupported:** Neuer Laufzettel (2026),
   MessageMetaData. EFFI as above.
5. **Warnings are hard failures** (except 3800) — stricter than §5,
   conservative direction, documented.
6. **Schema-validation harness** for captured wire traffic — the one
   missing *verification* instrument (§3.4 above).

Fixed during this comparison: the bridge accepted `BY_RECENT_MODIFICATION`
as a selection mode but the library's `setSelectionMode` rejects that
value with `IllegalArgumentException` — the request crashed the bridge
instead of returning a clean protocol error. The mapping is removed;
unknown modes fail cleanly (see `OsciOpsTest.selectionModeMapping`).

## 8. Re-verification procedure

- `make interop` — behavioral conformance against the reference
  intermediary (never in `make test`/`check`).
- `make test` — local conformance: crypto, feedback classification,
  dialog lifecycle, single-content semantics.
- After bumping `de.osci:osci-bibliothek`: re-run both, re-hash the
  reproducible jar, and re-check this matrix's „library" rows against
  the new version's changelog.
- When the XSD harness lands (§3.4): one e2e exchange asserted
  schema-valid per §7 obligation (2).
