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

`dist/` contains `bin/osci` and `lib/osci-bridge.jar` — keep them together
or set `OSCI_BRIDGE_JAR`.

## Verify the tests

```sh
make test   # Java unit tests + Rust unit/integration + e2e against the local mock
```

Test inventory:

| suite | what it proves |
|---|---|
| `osci-bridge` JUnit (17) | JSON contract, PKI parsing, sign/verify + decrypt round-trips, request loop |
| `osci` unit/integration (29) | protocol serde, bridge lifecycle (timeout/garbage/death), client flows, DVDV resolution, XTA sniffing |
| `osci-cli` (16) | argument plumbing, output shape, exit codes |
| e2e (2) | the real binary + real jar + mock intermediary: full send/status/fetch dialogue, envelope contents, failure exit codes |

The e2e suite generates its own throwaway PKI per run (`tests/gen-pki.sh`)
and talks only to `127.0.0.1`. No test touches any external service; the
Governikus public test intermediary is deliberately never used, because the
mission leaves no online traces.

## Honest security notes

An audit that only lists virtues is a brochure. Known limits, in the open:

1. **`--insecure-transport` test mode.** The e2e suite runs with
   SOAP-transport encryption and transport signatures disabled, because the
   local mock intermediary cannot perform the challenge/certified-response
   cryptography a real intermediary does. Content-level signing and content
   encryption (CMS/XML-Enc to the recipient certificate) remain fully
   active in these tests and are asserted (encrypted XTA bytes must NOT
   appear in the envelope dump; plaintext mode must show them). The
   production default is full transport encryption; the flag is named
   honestly and documented as "only against endpoints you own".
2. **PIN handling.** PKCS#12 PINs travel as strings from flags/env/file
   into the bridge via stdio JSON. They are never written to disk or logs,
   and the bridge process lives exactly as long as the CLI — but they are
   not zeroized memory. If your threat model includes core dumps, file a
   feature request (or a patch; patches age better than requests).
3. **DVDV is file-based.** Recipient resolution uses a local JSON extract
   (`--dvdv-file`, `osci dvdv find`) rather than the online FITKO REST
   service, which requires OAuth client credentials and would leave
   online traces. The `DvdvDirectory` trait is the seam for a native
   online client; `resolve_dvdv` is already wired through it.
4. **Mock intermediary coverage.** The mock speaks the happy path of
   Get­MessageId → StoreDelivery and InitDialog → Fetch/FetchProcessCard →
   ExitDialog. It does not exercise intermediaries that reject, chunk, or
   forward messages — those paths are covered by library code and the
   library's own conformance, not ours.
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
