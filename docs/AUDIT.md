# Audit kit

Everything an auditor (or a future, more rested you) needs to verify this
build from scratch. Reproducibility is a checksum, not a vibe.

## Verify the build environment

```sh
make setup            # builds the pinned builder image, wires the no-push hook
make verify-deps      # sha256-checks every maven artifact against the committed manifest
make lock-info        # prints the exact tool versions recorded below
```

Pins (also in `container/Dockerfile.builder` and `container/LOCK.md`):

| component | pin |
|---|---|
| base image | `docker.io/library/eclipse-temurin:21-jdk-jammy` |
| rust | 1.98.1 (rustup, image build time) |
| maven | 3.9.11 (tarball, sha512-verified in the Dockerfile) |
| OSCI library | `de.osci:osci-bibliothek:2.6.1` (Maven Central; EUPL-1.2/MIT) |
| BouncyCastle | bcprov 1.85.2 (managed by the library's BOM), bcpkix 1.85 (test-only) |
| gson | 2.13.2 |
| Rust deps | `Cargo.lock`, reviewed licenses via `make audit` |

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
| `osci-bridge` JUnit (18) | JSON contract, PKI parsing, sign/verify + decrypt round-trips, request loop |
| `osci` unit/integration (42) | protocol serde, bridge lifecycle (timeout/garbage/death), client flows, DVDV resolution, XTA sniffing |
| `osci-cli` (20) | argument plumbing, output shape, exit codes |
| e2e (3) | the real binary + real jar + mock intermediary: plain-transport send/status/fetch; **transport-encrypted send + status with ciphertext assertions**; failure exit codes |

The e2e suite generates its own throwaway PKI per run (`tests/gen-pki.sh`)
and talks only to `127.0.0.1`. No test touches any external service; the
Governikus public test intermediary is deliberately never used, because the
mission leaves no online traces.

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
Chunked transfer (`PartialStoreDelivery`, required by the OSCI standard
beyond an intermediary-specific threshold) is **not implemented** in the
bridge — payloads beyond what a plain `StoreDelivery` accepts would fail
loudly rather than silently truncate. The threshold is
intermediary-specific and untested beyond 5 MB; if your use case needs
more, that is the feature request to file.

### Reproducible jars

`java/*/pom.xml` pin `project.build.outputTimestamp`; two clean builds of
the same tree produce **byte-identical** bridge jars (verified 2026-10-03:
`bce430b77806a706878a41fbc19efe12ceba9f2fb73536b40bfa83f3f9f8ebc1` twice).
The Rust release binary is deterministic within a pinned container for the
same reason: same tree, same toolchain, same bytes. What ran is what the
sources say — the checksum proves it after the fact.

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
   and the bridge process lives exactly as long as the CLI. Rust-side
   copies are zeroized on drop (`zeroize` crate); what cannot be scrubbed
   is the JVM-side string residency inside the bridge and the environment
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

- No git remote, ever. Enforced by `make git-guard` and `hooks/pre-push`.
- Secrets (PINs, real PKI) never committed; `.gitignore` blocks the usual
  extensions. Test PKI is generated per-run and dies with the tempdir.
- All builds run inside the pinned container; the host Java-free policy is
  a feature, not an accident.
