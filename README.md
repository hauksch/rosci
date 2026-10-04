# osci-deshittifier

> **`rosci` — the curl of OSCI.** Send an arbitrary XTA message to any OSCI
> recipient, resolved by recipient certificate or via DVDV, without first
> filing a request in triplicate.

A clean, modern Rust API and CLI wrapped around the Governikus
OSCI-Transport-1.2 Java library (`de.osci:osci-bibliothek` — aging, but it
knows where the bodies are buried, cryptographically speaking). The Java
side runs as a sidecar process speaking one-line JSON over stdio; the Rust
side owns the ergonomics. Everybody sticks to their Bundesland.

## Why?

Because in the year 2026, the reference implementation for legally-binding
German administration messaging still has the ergonomics of a fax machine
that went to Verwaltungsschule. Integrating it normally means a JVM, four
keystores, a funktionsbeschreibung.pdf, and a prayer. This project wraps
that entire Zwischenbericht-zwischen-Zwischenbericht experience behind one
honest binary:

```sh
# from a DVDV extract (see below)
rosci send meldung.xta --to dvdv:02411000012345 \
     --cert client.p12 --subject "XMeld 2.4 Anzeige"

# or address the recipient certificate directly
cat meldung.xta | rosci send - --to cert:empfaenger.cer \
     --intermediary https://osci.example/entry \
     --intermediary-cert intermediar.cer \
     --cert client.p12
```

The XTA file is treated as opaque bytes. You worry about the content;
`osci` worries about the ceremony.

## Install / build

Everything builds inside a pinned container; the host stays Java-free
(it has suffered enough).

```sh
make setup     # build the builder image
make build     # Java bridge + mock jars, Rust workspace
make test      # all 117 tests, incl. e2e against the local mock intermediary
make check     # lint + test + audit + verify-deps in one command (CI runs it too)
make lint      # rustfmt + clippy -D warnings + mvn verify
make audit     # cargo-deny: licenses, advisories, crate sources
make release   # dist/bin/rosci + dist/lib/osci-bridge.jar + SHA256SUMS
```

Requirements: `docker` or `podman`, `make`, `git`. Nothing else touches
the host. See `container/LOCK.md` for the exact pinned toolchain.

## Usage

```
rosci send [-|<file.xta>] --to <cert:<path>|dvdv:<org-key>[:<category>]>
          [--intermediary URL --intermediary-cert FILE]
          [--cert FILE] [--decrypter-cert FILE] [--subject TEXT]
          [--attachment FILE] [--chunk-size-kb KB]
          [--metadata-author ID] [--metadata-reader ID]
          [--no-sign] [--no-encrypt] [--tls-ca FILE]
          [--tls-client-cert FILE] [--json]
rosci fetch [--message-id ID | --all] [--chunk-size-kb KB] [--out DIR] [--json]
rosci status <message-id> [--json]
rosci dvdv find --org KEY [--category CAT | --all] [--file dvdv.json] [--json]
rosci version [--require-bridge]
```

Configuration comes from flags and `OSCI_*` environment variables only —
no config files, no state, no traces:

| env | meaning |
|---|---|
| `OSCI_CERT_PIN` | PKCS#12 PIN (or `--pinfile`, or `--pin` if you like living dangerously) |
| `OSCI_CERT` / `OSCI_DECRYPTER_CERT` | identity bundles |
| `OSCI_INTERMEDIARY` / `OSCI_INTERMEDIARY_CERT` | intermediary |
| `OSCI_TLS_CA` | extra TLS trust anchor for the intermediary connection |
| `OSCI_TLS_CLIENT_CERT` / `OSCI_TLS_CLIENT_PIN` | mutual-TLS client bundle (PKCS#12) for the intermediary connection |
| `OSCI_BRIDGE_JAR` | where the sidecar jar lives (default: `../lib/osci-bridge.jar` next to the `rosci` binary, else `./osci-bridge.jar`) |
| `OSCI_DVDV_FILE` | DVDV extract for `--to dvdv:…` (default `dvdv.json`) |
| `OSCI_JAVA_OPTS` | extra JVM flags (debugging hatch) |

Exit codes: `0` ok · `2` usage/config · `3` DVDV miss · `4` transport/OSCI
rejection · `5` crypto · `6` bridge/internal. Shell scripts may finally
branch on something other than hope.

Certificate files — `--intermediary-cert`, `--to cert:…`, `--tls-ca` —
may be **PEM or binary DER**: OpenSSL's favorite `.cer` export works
as-is (binary DER is base64-wrapped for the bridge, which accepts bare
DER). A file that is neither fails at config parse (exit 2) with the
file named and its first byte reported — not with a UTF-8 riddle.

Two things about `fetch` on real intermediaries: it authenticates as
the message's **recipient**, and it returns **one message per call**.
`--all` is spec §6.6.9 rule 3 — the oldest pending delivery — and the
intermediary warns with 3800 „weitere Zustellungen liegen vor" when
more remain; `--message-id <id>` selects a specific message
deterministically.

## DVDV

The DVDV (Deutsches Verwaltungsdiensteverzeichnis — a directory of
directories, because one Verzeichnis wasn't verzeichnis enough) resolves
organization keys to OSCI endpoints and certificates. The online FITKO
REST service requires OAuth client credentials and would leave online
traces, so `osci` consumes a local JSON extract:

```json
[{
  "org_key": "02411000012345",
  "name": "Katasteramt Musterstadt",
  "intermediary_url": "https://osci.musterstadt.de/entry",
  "intermediary_cipher_cert": "-----BEGIN CERTIFICATE-----…",
  "recipient_cipher_cert": "-----BEGIN CERTIFICATE-----…"
}]
```

`rosci dvdv find --org 02411000012345` lists entries; `--to dvdv:…` sends
through them. The `DvdvDirectory` trait in `crates/osci` is the seam for a
native online client when credentials-based lookup is acceptable.

## Architecture

```
┌─────────┐  spawn    ┌──────────────────┐
│ rosci   │◄─JSON────►│ osci-bridge.jar  │  (de.osci library inside)
│ (Rust)  │  stdio    │  JVM sidecar     │
└─────────┘           └────────┬─────────┘
        flags/env only          │ OSCI 1.2 SOAP, sign+encrypt
                               ▼
                        intermediary ──► recipient postbox
```

- `crates/osci` — the library: `OsciClient` builder, bridge process
  management, error taxonomy, DVDV trait, XTA passthrough.
- `crates/osci-cli` — the binary. Clap, exit codes, JSON output.
- `java/osci-bridge` — the sidecar: send / fetch / process-card ops,
  TLS-configurable transport, one JSON line at a time
  ([protocol spec](docs/PROTOCOL.md)).
- `java/osci-mock` — a mock intermediary that really performs the OSCI
  transport crypto (RSA-OAEP key transport + AES-256-GCM, both
  directions); localhost only, never shipped.

## Testing

117 tests: Java unit (28), Rust unit/integration/CLI (82), e2e (7),
plus the opt-in live interop suite (11; `make interop`),
proptest invariants and doctests. The e2e suite runs the real binary +
real jar against the mock intermediary with a per-run generated throwaway
PKI — and every response is *signed* by the mock (XML-DSIG supplier
signature, RSA-PSS), so the client's automatic signature verification runs
in every scenario; a tamper mode proves one flipped byte fails loudly.
Transport encryption is asserted at the byte level: raw wire dumps must be
ciphertext (no subject, no XTA payload, not even element names), the
mock's decrypted inner envelopes must contain them, and responses must
come back encrypted. Content encryption — including a sealed
`xenc:EncryptedData` block in the canned fetch message — is asserted as a
second layer on top. No test ever leaves localhost. Measured coverage via
`make coverage` (Rust 88.0 %, bridge 71.4 %); `make fuzz` smokes the
response parser with libFuzzer. Details and the honest limitations list:
[docs/AUDIT.md](docs/AUDIT.md).

For testing against a *real* intermediary: `make interop` runs the opt-in
interop suite against the open Governikus OSCI-Manager instance
(gov.test.osci.de — the only sanctioned network departure). Details,
wire-verified evidence, and how to obtain real DOI/V-PKI sender
certificates: [docs/TEST-INFRASTRUCTURE.md](docs/TEST-INFRASTRUCTURE.md).

Where the OSCI 1.2 standard normatively lives and how rosci measures up
against it (order-type matrix, security mechanisms, deviations): 
[docs/STANDARD-COMPLIANCE.md](docs/STANDARD-COMPLIANCE.md).

## Ground rules

1. Everything lives in this directory — caches, Maven repo, cargo home.
2. All building happens via `make`, inside pinned containers; CI runs
   the identical commands on GitHub Actions.
3. Tests talk to localhost by default. The single sanctioned exception
   is the opt-in interop suite against the public Governikus test
   intermediary (gated behind `ROSCI_INTEROP=1`, never part of
   `make test`/`make check`/CI) — see
   [docs/TEST-INFRASTRUCTURE.md](docs/TEST-INFRASTRUCTURE.md).
4. Run `make check` before submitting anything; all gates run in CI.
5. Comments may grumble about bureaucracy. Gently. It's not the Beamte's
   fault — they also just wanted to go home at 16:29.

## License

MIT (see `LICENSE`). The wrapped OSCI library is dual-licensed
EUPL-1.2/MIT by Governikus — thank you, sincerely, for open-sourcing it.
