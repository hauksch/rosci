# Audit kit

Everything an auditor (or a future, more rested you) needs to verify this
build from scratch. Reproducibility is a checksum, not a vibe.

## Verify the build environment

```sh
make setup            # builds the pinned builder image
make lock-info        # prints the exact tool versions recorded below
```

Pins (also in `container/Dockerfile.builder` and `container/LOCK.md`):

| component | pin |
|---|---|
| base image | `docker.io/library/ubuntu:22.04@sha256:8a2321a9…` (digest-pinned, see LOCK.md) |
| rust | 1.98.1 via checksummed rustup-init 1.29.1 (`sha256:dda72343…`, pinned in the Dockerfile) |
| OSCI stack | oscirs, git-pinned by rev (EUPL-1.2/MIT per crate; the native implementation) |
| Rust deps | `Cargo.lock`, reviewed licenses via `make audit` |
| fuzz toolchain | `nightly-2026-10-03` + cargo-fuzz 0.13.2 (dev-time only, pinned in the Makefile) |

Rust dependency licensing is enforced with cargo-deny (`deny.toml`):

```sh
make audit   # cargo deny check licenses advisories sources
```

## Verify the release artifacts

```sh
make release
cd dist && sha256sum -c SHA256SUMS
```

`dist/` contains `bin/rosci` and `bin/roscid` — self-contained, no sidecar.

## Verify the tests

```sh
make test   # Java unit tests + Rust unit/integration + e2e against the local mock
```

Test inventory:

| suite | what it proves |
|---|---|
| `rosci` unit/integration (94, incl. 3 proptest invariants) | PKCS#12 identity handling, TLS client-bundle wiring, DVDV resolution, XTA sniffing, loopback guard, error taxonomy |
| `osci-cli` + `roscid` unit | argument plumbing, output shape, exit codes, fetch write safety |
| e2e (7) | the real binary + the in-process mock intermediary: send/status/fetch (incl. attachments); **transport-encrypted send + status with ciphertext assertions**; failure exit codes; large payload; tampered supplier signature; **schema validation of captured wire traffic** |
| `roscid` REST e2e (4) | REST surface over the same stack: exposure/auth guards, Bearer enforcement (positive + negative), healthz vs readiness split, readiness 503 on a broken identity, send→status→fetch round trip incl. sealed-content decryption |
| interop (11, opt-in, live) | the real binary + the OSCI-Manager test intermediary at gov.test.osci.de: send/fetch round trips (incl. attachments and MessageMetaData), **EFFI chunked transfer byte-exact (3 MB, 3 chunks)**, postbox isolation, `--all` warning semantics |

The e2e suite generates its own throwaway PKI per run (`tests/gen-pki.sh`)
and talks only to `127.0.0.1`. No test touches any external service; the
Governikus public test intermediary is deliberately excluded here — the
opt-in interop suite covers it (docs/TEST-INFRASTRUCTURE.md).

### Measured coverage (`make coverage`)

| component | instrument | report |
|---|---|---|
| Rust workspace (unit/integration/CLI) | cargo-llvm-cov 0.9.1, pinned in builder image | `coverage/lcov.info` (`make coverage`) |

Caveats, honestly: the Rust number excludes the e2e suite (it drives the
built binary, not instrumented test builds). Baselines recorded
2026-10-01; re-baseline with the 0.5.0 native tree pending.

Property-based tests (proptest) pin the invariants of the response parser,
the filename sanitizer and the XML sniffer; a libFuzzer target
(`make fuzz`, 60 s smoke) threw 2.1 million inputs at the JSON response
parser with zero crashes on its latest run.

### Large payloads

A manual probe verified a **5 MB XTA** through both the plain and the
fully-encrypted (transport + content signature + content encryption)
paths without chunking; a ~2 MB regression case runs in the e2e suite.
EFFI chunked transfer (`PartialStoreDelivery`, the standard's answer for
intermediary-specific size thresholds) is implemented as an **opt-in**:
`rosci send --chunk-size-kb N` serializes the fully built StoreDelivery,
ships it in N-KB chunks and lets the intermediary reassemble
(live-verified byte-exact against the OSCI-Manager test instance,
docs/TEST-INFRASTRUCTURE.md). `rosci fetch --chunk-size-kb N` pulls
chunked-stored messages via PartialFetchDelivery for intermediaries that
only serve chunks — the OSCI-Manager serves them reassembled via plain
fetch instead (its partial-fetch variant answered 9811; see
docs/TEST-INFRASTRUCTURE.md). Without the flag, oversized payloads fail
loudly rather than silently truncate.

### Binary reproducibility

With the Java side gone, the only shipped artifacts are two statically
linked Rust binaries. Rust release builds are reproducible within a
fixed toolchain (the pinned builder image provides exactly that); the
property that holds is: **the recorded `dist/SHA256SUMS` matches the
artifacts shipped** — verify against it. "What ran is what the sources
say" is enforced by the pinned toolchain + `Cargo.lock`.

The Rust release binary IS deterministic within the pinned container
(same tree, same toolchain, same bytes).

### Strict compilers

Both Java modules compile with `-Xlint:all` and fail on warnings (the
gate's first catches: a missing `serialVersionUID`, a redundant cast, use
of deprecated PKCS#1 v1.5 constants — the PSS-only path is now the only
path). The Rust library denies `missing_docs` and warns on
`unwrap`/`expect` in library code.

### What the transport-encryption e2e actually proves

The mock intermediary is a real cryptographic peer: it decrypts incoming
transport packages with the intermediary key (RSA-OAEP key unwrap,
AES-256-GCM — an AEAD tag failure would be loud), extracts the client's
cipher certificate from the decrypted envelope, and encrypts every
response back to it. The test then asserts on the byte-exact wire dumps:

- raw requests carry `soapMessageEncrypted.xsd`/`EncryptedKey` markers and
  contain **no** plaintext (not the subject, not the XTA payload, not even
  the message-type element names like `storeDelivery`),
- the mock's decrypted inner envelopes do contain subject and message
  structure (decryption provably happened),
- the XTA payload stays content-encrypted even *inside* the decrypted
  transport envelope (layer two of the crypto onion),
- responses are encrypted on the wire (the plaintext feedback text does
  not appear in response dumps),
- every exchange is recorded as `transport_encrypted: true` in per-request
  meta files.

## Honest security notes

An audit that only lists virtues is a brochure. Known limits, in the open:

1. **Transport signatures on responses — closed (2026-10-03).** The mock
   now signs every response with the intermediary's signature key
   (`ResponseSigner`: inclusive-C14N part digests via the JDK XML-DSig
   engine, RSA-PSS/SHA-256 over the SignedInfo, attachments as `cid:`
   references, `IntermediaryCertificates` header carrying the signing
   cert). The client library's automatic verification runs on every e2e
   exchange, and a dedicated tamper test (`--tamper-signature`) proves a
   one-byte SignatureValue flip fails loudly (exit 4). The e2e mock arms
   signing by default, so every transport-encrypted, content-encrypted
   and large-payload test also carries verified supplier signatures.
   `--insecure-transport` remains for focused content-level tests.
2. **PIN handling.** PKCS#12 PINs travel as strings from flags/env/file
   into the library. They are never written to disk or logs. Every
   *stored* copy is wrapped in `Zeroizing` and scrubbed on drop
   (`zeroize` crate: the CLI's input handling and the `Identity` values
   held by the library). What cannot be scrubbed, honestly: transient
   copies the crypto layer makes while unwrapping keys, and the
   environment variable itself (readable from `/proc/<pid>/environ` by
   the same user for the process lifetime). If your threat model
   includes core dumps or process introspection, file a feature request
   (or a patch; patches age better than requests).
3. **DVDV is file-based.** Recipient resolution uses a local JSON extract
   (`--dvdv-file`, `rosci dvdv find`) rather than the online FITKO REST
   service, which requires OAuth client credentials and would leave
   online traces. The `DvdvDirectory` trait is the seam for a native
   online client; `resolve_dvdv` is already wired through it.
4. **Mock intermediary coverage.** The mock speaks the happy path of
   Get­MessageId → StoreDelivery and InitDialog → Fetch/FetchProcessCard →
   ExitDialog, in both plain and transport-encrypted dialects. It does not
   exercise intermediaries that reject, chunk, or forward messages — those
   paths are covered by library code and the library's own conformance,
   not ours.
5. **Supply chain.** The OSCI stack is git-pinned by commit and
   reviewed on every bump (`make check` runs cargo-deny over licenses,
   advisories and crate sources; the fuzz toolchain is dated-pinned).
   The builder image pins base digest + checksummed rustup-init + the
   two cargo tools it carries.

## Repository hygiene rules

- Tests never talk to the network by default; the opt-in interop suite is the single sanctioned exception (docs/TEST-INFRASTRUCTURE.md).
- Secrets (PINs, real PKI) never committed; `.gitignore` blocks the usual
  extensions. Test PKI is generated per-run and dies with the tempdir.
- All builds run inside the pinned container; the host Java-free policy is
  a feature, not an accident.
