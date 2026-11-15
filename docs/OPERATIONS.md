# Operations — running roscid for real business flows

The runbook for using `roscid` as the transport leg of a production
integration (e.g. xMeld 602.1 „Einfache Melderegisterauskunft" to a
Meldebehörde). Division of labor, stated once and load-bearing:
**the Fachanwendung owns the fachlich payload (xMeld XML); rosci owns
the OSCI ceremony** — signing, encryption, addressing, receipts,
fetching, Laufzettel. The payload crosses rosci as opaque bytes in an
XTA file and is never parsed.

## 0. Prerequisites — pin these down before touching config

Every item below is a startup fact someone outside the repo owns.
Get them in writing from your intermediary contract / Meldebehörde:

| Fact | Feeds |
|---|---|
| Intermediary entry URL (test + production) | `OSCI_INTERMEDIARY` |
| Intermediary cipher certificate (PEM / base64-DER) | `OSCI_INTERMEDIARY_CERT` |
| TLS CA if the endpoint uses a non-public PKI | `OSCI_TLS_CA` |
| Whether your identity has **separate signature vs. cipher certs** (DOI/V-PKI typically does; the „Meldewesen" sub-domain exists for xMeld — see TEST-INFRASTRUCTURE.md §5) | `OSCI_DECRYPTER_CERT` |
| The recipient Meldebehörde's **cipher certificate** (public — per request body) | `to.cert` |
| XTA envelope version + subject convention the intermediary expects | `subject`, payload wrapping |

The classic failure is the fourth row: when answers are encrypted to a
cipher certificate that differs from your signing certificate and no
separate decrypter bundle is configured, fetched messages surface as
`<not decryptable with the supplied identity>` — config error at the
worst possible layer, the postbox. Sort the pairing out before go-live.

Payload wrapping note: rosci sniffs the XTA root element as a courtesy
and warns but still sends if it isn't `<XTA>`. Whatever envelope and
subject syntax your intermediary mandates is a contract between you and
it — confirm it explicitly.

## 1. Deployment

`deployment/roscid.service` + `deployment/roscid.env.example` are the
templates. Non-negotiables:

- PIN via `OSCI_PINFILE` at `0600`, not the environment.
- Bind loopback unless there is a real reason not to; a network bind
  requires `OSCI_API_KEY` and roscid **exits 2 without one** — that
  refusal is the feature, do not design around it.
- `OSCI_RESPONSE_TIMEOUT_SECS` set deliberately (default 300): a wedged
  intermediary must surface as HTTP 504, not a held-open connection.
- Health wiring: `/healthz` (liveness, unauthenticated) for probes;
  `/readyz` after every boot before accepting business traffic — it
  parses the keystores and pings the intermediary, and it is where a
  wrong PIN or trust anchor shows up as 503 instead of a runtime
  surprise mid-request.

## 2. The business flow, end to end

Using 602.1 as the concrete example — the shape is identical for any
OSCI-carried message:

1. **Send**: Fachanwendung renders the xMeld request XML → XTA file.
   `POST /v1/send` with `to.cert` = the Meldebehörde's cipher
   certificate, `content.data` = base64 payload, `subject` per
   convention, `metadata_author`/`metadata_reader` if the intermediary
   requires MessageMetaData identifiers. Store the returned
   `message_id`: it is the Aktenzeichen of the message.
2. **Status**: `GET /v1/messages/{id}/status` returns the Laufzettel
   (creation, forwarding, reception, inspection stamps). Poll it when
   you need delivery evidence; the answer itself does **not** arrive as
   a reply to this id.
3. **Fetch**: the Auskunft comes back as a **new incoming delivery**.
   `POST /v1/fetch` with `{"all": true}` (oldest pending) or
   `{"message_id": …}`. Content arrives decrypted (via the configured
   decrypter identity) with a `signatures_valid` verdict per message —
   the author-signature check inside the payload, worth logging.
4. **Correlate**: match answer to request in your own bookkeeping (the
   stored send `message_id` + your subject convention). OSCI has no
   reply threading; pretending otherwise is how register requests get
   filed under the wrong Aktenzeichen.

## 3. Validation ladder — climb in order, each rung gates the next

1. **Identity gate**: roscid with your real keystores against
   gov.test.osci.de (the intermediary this stack's interop suite is
   verified against) → `/readyz` must answer 200. Proves PIN, keystore
   parse, and trust-anchor config.
2. **Transport round-trip**: `POST /v1/send` a synthetic XTA, fetch it
   back, check `response_signed: true`, successful decryption, a sane
   `signatures_valid`, and a process card for the message id. Proves
   the certificate pairing end to end — before any real authority is
   involved.
3. **Fachlich end-to-end**: real 602.1 Anfrage from the Fachanwendung
   to the test-fähige Meldebehörde, fetch the Auskunft, hand it back to
   the Fachanwendung for parsing. Envelope/subject convention fixes
   happen here, where they are cheap.

## 4. Error semantics for the application team

| HTTP | kind | Meaning | Action |
|---|---|---|---|
| 400 | `config`/`bad-request` | roscid or request misconfigured | fix the body/config |
| 401 | `unauthorized` | missing/wrong `Authorization: Bearer` | fix the key |
| 404 | `not-found`/`dvdv` | unknown route or DVDV miss | — |
| 422 | `osci`/`crypto` | the intermediary rejected the operation | read `error.feedback` rows — they are the intermediary's verdict verbatim |
| 502 | `transport`/`protocol`/`bridge-death` | intermediary unreachable or bridge died | retry with backoff; 502s are not your payload's fault |
| 504 | `timeout` | operation exceeded `OSCI_RESPONSE_TIMEOUT_SECS` | raise the bound or investigate the intermediary |
| 500 | `internal` | roscid's own failure | check logs, file it |

## 5. Known limitations (state these in any integration design)

- Laufzettel: `BY_MESSAGE_ID` only; the 2026 „Neuer Laufzettel"
  Ergänzung is unsupported (STANDARD-COMPLIANCE.md §6).
- REST bodies cap at 256 MiB; larger flows belong in the CLI's chunked
  path.
- Addressing is by inline certificate only (`to.org`/DVDV answers 501;
  the CLI covers DVDV flows from a local extract).
- No online DVDV lookup by design — extracts are files you obtain and
  refresh.
- rosci is Benutzer software: it sends and fetches, it cannot act as a
  service provider (Forward/Mediate/Process/AcceptDelivery).
