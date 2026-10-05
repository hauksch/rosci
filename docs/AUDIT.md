# Audit kit

Everything an auditor (or a future, more rested you) needs to verify this
build from scratch. Reproducibility is a checksum, not a vibe.

## Verify the build environment

```sh
make setup            # builds the pinned builder image, pins the builder image
make verify-deps      # sha256-checks every maven artifact against the committed manifest
make lock-info        # prints the exact tool versions recorded below
```

Pins (also in `container/Dockerfile.builder` and `container/LOCK.md`):

| component | pin |
|---|---|
| base image | `docker.io/library/eclipse-temurin:21-jdk-jammy@sha256:bc46d736…` (digest-pinned, see LOCK.md) |
| rust | 1.98.1 via checksummed rustup-init 1.29.1 (`sha256:dda72343…`, pinned in the Dockerfile) |
| maven | 3.9.11 (tarball, sha512-verified in the Dockerfile) |
| OSCI library | `de.osci:osci-bibliothek:2.6.1` (Maven Central; EUPL-1.2/MIT) |
| BouncyCastle | bcprov 1.85.2 (managed by the library's BOM), bcpkix 1.85 (test-only) |
| gson | 2.13.2 |
| Rust deps | `Cargo.lock`, reviewed licenses via `make audit` |
| fuzz toolchain | `nightly-2026-10-03` + cargo-fuzz 0.13.2 (dev-time only, pinned in the Makefile) |
| Java tree CVEs | OSV scan of every manifest artifact (`make audit` → `container/osv-java.sh`) |

Rust dependency licensing is enforced with cargo-deny (`deny.toml`):

```sh
make audit   # cargo deny check licenses advisories sources
```

## Verify the release artifacts

```sh
make release
cd dist && sha256sum -c SHA256SUMS
```

`dist/` contains `bin/rosci` and `lib/osci-bridge.jar` — keep them together
or set `OSCI_BRIDGE_JAR`.

## Verify the tests

```sh
make test   # Java unit tests + Rust unit/integration + e2e against the local mock
```

Test inventory:

| suite | what it proves |
|---|---|
| `osci-bridge` JUnit (28) | JSON contract, PKI parsing, sign/verify + decrypt round-trips, request loop, feedback-row mapping (incl. 3800-warning tolerance), selection-mode mapping, byte-exact fetch content, streamed request transport |
| `osci` unit/integration (53, incl. 3 proptest invariants) | protocol serde, bridge lifecycle (timeout/garbage/death/desync), client flows incl. protocol-version handshake, DVDV resolution, XTA sniffing, TLS client bundle wiring |
| `osci-cli` (29) | argument plumbing, output shape, exit codes, jar resolution, loopback guard, fetch write safety |
| e2e (7) | the real binary + real jar + mock intermediary: plain-transport send/status/fetch; **transport-encrypted send + status with ciphertext assertions**; failure exit codes; large payload; tampered supplier signature; attachments; **schema validation of captured wire traffic** |
| interop (11, opt-in, live) | the real binary + real jar + the OSCI-Manager test intermediary: send/fetch round trips (incl. attachments and MessageMetaData), EFFI chunked transfer byte-exact, postbox isolation, `--all` warning semantics |

The e2e suite generates its own throwaway PKI per run (`tests/gen-pki.sh`)
and talks only to `127.0.0.1`. No test touches any external service; the
Governikus public test intermediary is deliberately excluded here — the
opt-in interop suite covers it (docs/TEST-INFRASTRUCTURE.md).

### Measured coverage (`make coverage`)

| component | instrument | line coverage |
|---|---|---|
| Rust workspace (unit/integration/CLI) | cargo-llvm-cov, pinned in builder image | 88.0% |
| Java bridge, unit tests only | JaCoCo 0.8.13 (maven plugin) | 27.5% |
| Java bridge, e2e only | JaCoCo agent attached via `OSCI_JAVA_OPTS` during the e2e suite | 68.2% |
| Java bridge, **combined** | jacococli merge of both runs | **71.4%** |

Caveats, honestly: the Rust number excludes the e2e suite (it drives the
built binary, not instrumented test builds); the Java numbers exclude
`Bridge.main`'s process plumbing that only the real jar exercises. The
agent trick works because the bridge honors `OSCI_JAVA_OPTS` — the same
debugging hatch documented in the README. Baselines recorded 2026-10-01.

Property-based tests (proptest) pin the invariants of the response parser,
the filename sanitizer and the XML sniffer; a libFuzzer target
(`make fuzz`, 60 s smoke) threw 5.6 million inputs at the response parser
with zero crashes on its first run.

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

### Jar reproducibility — honest status: not fully reproducible

`java/*/pom.xml` pins `project.build.outputTimestamp`, so entry
timestamps are fixed — but the shaded jar is **not** byte-stable across
build environments. Observed on 2026-10-04, same sources: four distinct
hashes across cache/target states (`0e3a11b3…`, `434eef4f…`,
`847b5fdf…`, `e8f9dd7f…`), while repeated builds in a *fixed* state
were stable (verified twice each for two of them). The maven-shade
plugin's archive ordering/input set evidently varies with cache state.
Re-recorded after the rosci rename (2026-10-05): clean builds of the
renamed tree are stable at `0dd6bb79…` (verified twice).

Consequences, honestly stated:
- The property that holds is: **the recorded `dist/SHA256SUMS` matches
  the artifacts shipped** — verify against it, not against a
  cross-environment golden hash.
- "What ran is what the sources say" is enforced by the pinned
  toolchain + checksummed dependency manifest, not by jar-byte
  reproducibility.
- A true fix would be a normalization post-process (repack the shaded
  jar with sorted entries and fixed metadata) — proposed, not
  implemented.

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
   into the bridge via stdio JSON. They are never written to disk or logs,
   and the bridge process lives exactly as long as the CLI. On the Rust
   side, every *stored* copy is wrapped in `Zeroizing` and scrubbed on
   drop (`zeroize` crate: the CLI's input handling and the `Identity`
   values held by the library). What cannot be scrubbed, honestly: the
   serialized JSON request line on the pipe (a wire-format necessity —
   the bridge reads a JSON line, the line contains the PIN), the
   JVM-side string residency inside the bridge, and the environment
   variable itself (readable from `/proc/<pid>/environ` by the same user
   for the process lifetime). If your threat model includes core dumps or
   process introspection, file a feature request (or a patch; patches age
   better than requests).
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
5. **Supply chain.** Maven artifacts are pinned by version and verified by
   committed per-artifact sha256s (`make manifest` regenerates,
   `make verify-deps` enforces). Rust is pinned by `Cargo.lock`. The
   builder image pins base + toolchain. Releases on Maven Central are
   additionally GPG-signed upstream (`.asc` files) — we verify checksums;
   signature keys live in Governikus' KEYS file if you want to go deeper.

## Repository hygiene rules

- Tests never talk to the network by default; the opt-in interop suite is the single sanctioned exception (docs/TEST-INFRASTRUCTURE.md).
- Secrets (PINs, real PKI) never committed; `.gitignore` blocks the usual
  extensions. Test PKI is generated per-run and dies with the tempdir.
- All builds run inside the pinned container; the host Java-free policy is
  a feature, not an accident.
