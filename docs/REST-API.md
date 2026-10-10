# REST API — normative contract for roscid

`roscid` exposes the same OSCI operations as the CLI over HTTP/JSON.
This document is the normative description of that surface, the same
way docs/PROTOCOL.md is normative for the bridge's stdio line protocol.
The OSCI wire itself (OSCI-Transport 1.2) is untouched — the server is
a transport for the library, not a new dialect.

## Ground rules

- **Auth**: every route except `GET /healthz` requires
  `Authorization: Bearer <key>` when the server has an API key
  (`--api-key` / `OSCI_API_KEY`). Comparison is constant-time. A
  non-loopback bind without an API key is refused at startup.
- **Errors** use one envelope:
  `{"error": {"kind": string, "message": string, "feedback": [[text, code], ...]?}}`
  `feedback` appears when the intermediary rejected the request (the
  same two-column rows the CLI prints). Status codes: 400 config/parse,
  401 auth, 404 dvdv miss, 422 intermediary rejection or crypto, 502
  transport/bridge, 504 timeout, 500 internal.
- **Base64**: all content fields are standard base64, decoded to opaque
  bytes server-side. The server never parses your payload.

## Endpoints

### GET /healthz

200 `{"status":"ok"}` — no auth. Liveness only; does not touch the
bridge.

### GET /readyz

Requires auth. Pings the bridge (`ping` op, builds it if cold). 200
`{"status":"ready"}` or 503 with the error envelope.

### GET /v1/version

Requires auth. Returns the version handshake map (bridge, JVM, OSCI
library, BouncyCastle, protocol version) — the same data `rosci version
--require-bridge` prints.

### POST /v1/send

Request (all fields mirror the CLI's send flags):

```json
{
  "to": {"cert": "-----BEGIN CERTIFICATE-----…"},
  "subject": "XTA 2.4 Anzeige",
  "content": {"filename": "meldung.xta", "data": "<base64>"},
  "attachments": [{"filename": "anhang.txt", "data": "<base64>"}],
  "chunk_size_kb": 1024,
  "sign": true,
  "encrypt": true
}
```

- `to` is addressed by **inline certificate** (PEM or base64 DER) in
  v1. `to.org` (DVDV org key) is accepted by the schema but answers 501
  until the server can resolve it through its own configured
  intermediary.
- `chunk_size_kb` opts into EFFI chunked transfer.
- Response 200: the `Receipt` — `{"message_id", "response_signed",
  "feedback"?}`. `response_signed: true` is the whole verification chain
  in one boolean.

### POST /v1/fetch

```json
{"message_id": "osci_test_…"}
```

or `{"all": true}` — exactly one of the two. Requires auth. Returns the
fetched messages as a JSON array (`contents`, `encrypted_contents`,
`subject`, `signatures_valid`). Content `data` is base64, byte-exact
with what was sent.

### GET /v1/messages/{id}/status

Requires auth. Returns the process card (Laufzettel) array for the
message id. Against real managers this may 422 with the manager's
feedback — some retain no cards for every id.

### GET /v1/version

Requires auth. Returns the version handshake map (bridge, JVM, OSCI
library, BouncyCastle, protocol version).

## Bridge lifecycle

roscid keeps **one** bridge JVM warm for the process lifetime and
serializes operations through it (the intermediary serializes them
anyway). If the JVM dies, the supervisor rebuilds it on the next
operation and retries once — failures that survive that surface as
502/`bridge-death`. SIGTERM/SIGINT shut the bridge down politely; the
JVM is never orphaned.
