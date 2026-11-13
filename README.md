# rosci

[![ci](https://github.com/hauksch/rosci/actions/workflows/ci.yml/badge.svg)](https://github.com/hauksch/rosci/actions/workflows/ci.yml)
[![audit](https://github.com/hauksch/rosci/actions/workflows/audit.yml/badge.svg)](https://github.com/hauksch/rosci/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![deps: cargo-deny](https://img.shields.io/badge/dependencies-cargo--deny%20%2B%20SBOM-success.svg)](deny.toml)

> **`rosci` — the curl of OSCI.** Send an arbitrary XTA message to any OSCI
> recipient, resolved by recipient certificate or via DVDV, without first
> filing a request in triplicate.

A clean, modern Rust API and CLI implementing OSCI-Transport-1.2 natively
on the [oscirs](https://github.com/hauksch/oscirs) stack — dialogs, all
message kinds, signing, encryption and EFFI chunked transfer, with no JVM,
no jars, no keystores beyond the one identity bundle. Verified
byte-level against the reference implementation's output and live against
gov.test.osci.de (11/11 interop, EFFI included).

## Why?

Because in the year 2026, the reference implementation for legally-binding
German administration messaging still has the ergonomics of a fax machine
that went to Verwaltungsschule. Integrating it normally means a JVM, four
keystores, a funktionsbeschreibung.pdf, and a prayer. This project puts
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
`rosci` worries about the ceremony.

## Install / build

Everything builds inside a pinned container; the host stays toolchain-free.

```sh
make setup     # build the builder image
make build     # Rust workspace
make test      # unit/integration/e2e against the in-process mock intermediary
make check     # lint + test + audit in one command (CI runs it too)
make lint      # rustfmt + clippy -D warnings
make audit     # cargo-deny: licenses, advisories, crate sources
make release   # dist/bin/{rosci,roscid} + SHA256SUMS
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
          [--tls-client-cert FILE [--tls-client-pin PIN]] [--json]

Test-mode escape hatch (local mock intermediaries only; refuses
non-loopback hosts unless --insecure-transport-any-host is also given):
`--insecure-transport` disables SOAP-transport encryption/signatures —
content-level signing/encryption stay on.
rosci fetch [--message-id ID | --all] [--chunk-size-kb KB]
           [--out DIR] [--json]          # + connection flags below
rosci status <message-id> [--json]       # + connection flags below
rosci dvdv find --org KEY [--category CAT | --all] [--file dvdv.json] [--json]
rosci version
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
| `OSCI_DVDV_FILE` | DVDV extract for `--to dvdv:…` (default `dvdv.json`) |

Exit codes: `0` ok · `2` usage/config · `3` DVDV miss · `4` transport/OSCI
rejection · `5` crypto · `6` internal. Shell scripts may finally branch on
something other than hope.

Certificate files — `--intermediary-cert`, `--to cert:…`, `--tls-ca` —
may be **PEM or binary DER**: OpenSSL's favorite `.cer` export works
as-is. A file that is neither fails at config parse (exit 2) with the
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
traces, so `rosci` consumes a local JSON extract:

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
┌─────────┐  OSCI 1.2 SOAP, sign+encrypt   ┌──► recipient postbox
│ rosci   │ ──────────────────────────────►│ intermediary
│ (Rust)  │   oscirs stack: dialogs, all   │
└─────────┘   message kinds, EFFI, TLS    └──► Laufzettel/status
```

- `crates/osci` — the library: `OsciClient` builder, the native stack
  wiring, error taxonomy, DVDV trait, XTA passthrough.
- `crates/osci-cli` — the binaries. Clap, exit codes, JSON output.
- `crates/testsupport` — the in-process mock intermediary the e2e
  suites drive (real OSCI transport crypto, signed responses, wire
  dumps); localhost only, never shipped.

## Testing

The workspace runs unit/integration suites, propTests, doctests, the CLI
e2e suite (7: real binary against the in-process mock intermediary with a
per-run generated throwaway PKI) and the roscid REST e2e suite (4). Every
mock response is *signed* (XML-DSIG supplier signature, RSA-PSS) so the
client's automatic signature verification runs in every scenario; a
tamper mode proves one flipped byte fails loudly. Transport encryption is
asserted at the byte level: raw wire dumps must be ciphertext, the mock's
decrypted inner envelopes must contain the plaintexts, and responses must
come back encrypted. Content encryption — including a sealed
`xenc:EncryptedData` block in the canned fetch message — is asserted as a
second layer on top. No test ever leaves localhost. Measured coverage via
`make coverage` (cargo-llvm-cov, lcov in coverage/); `make fuzz` smokes
the JSON response parser with libFuzzer.

For testing against a *real* intermediary: `make interop` runs the opt-in
interop suite against the open Governikus OSCI-Manager instance
(gov.test.osci.de — the only sanctioned network departure; 11 tests,
EFFI chunked transfer included). Details, wire-verified evidence, and how
to obtain real DOI/V-PKI sender certificates:
[docs/TEST-INFRASTRUCTURE.md](docs/TEST-INFRASTRUCTURE.md).

Where the OSCI 1.2 standard normatively lives and how rosci measures up
against it (order-type matrix, security mechanisms, deviations):
[docs/STANDARD-COMPLIANCE.md](docs/STANDARD-COMPLIANCE.md).

## Ground rules

1. Everything lives in this directory — caches, cargo home.
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

## REST server

`roscid` is a second binary in this workspace: a REST server over the
same native library, for applications that prefer HTTP over a CLI.
Loopback-bound by default (non-loopback binds require an API key),
endpoints mirror the CLI 1:1 (`/v1/send`, `/v1/fetch`, `/v1/messages/
{id}/status`, `/v1/version`). Contract and runbook:
[docs/REST-API.md](docs/REST-API.md), machine-readable:
[docs/openapi.yaml](docs/openapi.yaml).

## Security & supply chain

`cargo deny` fails the build on vulnerable or yanked dependencies,
license violations and unknown crate registries; the audit workflow
attaches a CycloneDX SBOM as an artifact and runs weekly so new RustSec
advisories surface without commit activity. Dependency updates arrive
as Dependabot pull requests only — nothing is auto-merged. Found
something sensitive? Please use GitHub's *private* vulnerability
reporting instead of opening a public issue
([SECURITY.md](SECURITY.md)).

## Ecosystem

- [oscirs](https://github.com/hauksch/oscirs) — the native OSCI 1.2
  stack rosci is built on (dialogs, signing, encryption, EFFI).
- [safedir](https://github.com/hauksch/safedir) — SAFE directory
  resolution: the counterpart to rosci's DVDV extract. rosci moves the
  message, safedir decides *where and to whom*.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — the short version: build in
the container, keep the tests honest, `make check` green before
submitting. Security reports go through
[SECURITY.md](SECURITY.md) (private GitHub reporting, please — not
public issues).

## License

MIT (see `LICENSE`). The reference implementation whose behavior rosci's
native stack is differentially verified against is dual-licensed
EUPL-1.2/MIT by Governikus — thank you, sincerely, for open-sourcing it.
