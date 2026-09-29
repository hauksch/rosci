# Mission: `osci` — the curl of OSCI (a.k.a. the OSCI-Deshittifier)

Wrap the aging Governikus OSCI-Transport-1.2 Java library in a modern, testable, containerized
Rust CLI that takes an arbitrary XTA message and sends it to a recipient (optionally resolved via
DVDV). Everything reproducible via `make`, built in containers, contained in this directory,
never pushed anywhere.

**Decisions (user-approved):** sidecar JSON bridge (Rust ⇄ Java subprocess) · MIT license.
Comment style: lovingly grumbly about German bureaucracy (fax-machine jokes, Verzeichnis-of-Verzeichnisse
wisecracks) — family friendly, never mean.

## Recon facts (verified)
- Library: `de.osci:osci-bibliothek-lib` **2.6.1** (2026-08-20) on Maven Central; source at
  gitlab.opencode.de/governikus/osci/osci-bib-java; **EUPL-1.2/MIT dual** → MIT downstream is clean.
  Java 11 bytecode, BouncyCastle crypto, `osci-bibliothek-sample` sources available as reference.
- API surface (per funktionsbeschreibung.md): `DialogHandlerClient(originator, intermediary, transport)`,
  `InitDialog`, `GetMessageID`, `StoreDelivery`, `FetchDelivery`, `FetchProcessCard`, `Content`/`ContentContainer`,
  `Signer`/`Decrypter` SPIs. XTA rides as opaque `Content` — zero XTA parsing.
- DVDV: FITKO `dvdv-bibliothek-java` (`dvdv-api`/`dvdv-impl`, `DVDVManager`) against the DVDV REST API
  (Keycloak or cert auth); artifacts from git.fitko.de Maven package registry.
- Host: docker + podman + rust + make + git. **No Java on host — it stays that way.**

## Repository layout
```
osci-deshittifier/
├── Makefile                  # every target runs inside OCI container (docker|podman autodetect)
├── README.md                 # mission statement, usage, gentle rant
├── LICENSE                   # MIT
├── .gitignore / .gitattributes / .editorconfig
├── hooks/pre-push            # hard-blocks any push (core.hooksPath wired by `make setup`)
├── container/Dockerfile.builder + entrypoint.sh   # pinned temurin JDK, maven, rust, openssl; uid-remap
├── container/LOCK.md         # image tags + digests, tool versions (the audit trail)
├── java/osci-bridge/         # Maven project (committed mvnw, .m2-repo inside workspace)
├── crates/osci/              # Rust lib: bridge process, protocol, OsciClient, DVDV trait
├── crates/osci-cli/          # the `osci` binary (clap)
├── fixtures/                 # self-authored XTA samples, canned SOAP, JSON goldens
├── tests/                    # e2e: mock OSCI intermediary + CLI scenarios
└── docs/                     # PROTOCOL.md (bridge JSON), AUDIT.md (checksums, verify steps)
```

## Workstreams

### W1 — Groundwork
`git init` (no remote, ever — enforced by pre-push hook + `make git-guard`). `.gitignore`: `target/`,
`java/**/target/`, `.m2-repo/`, `.cargo-home/`, `dist/`, `*.p12`, `*.pem`, `.env`, generated certs,
IDE droppings. Commit secrets never; test certs are generated per-run in-container.

### W2 — Container & Make
Builder image: `eclipse-temurin:21-jre`-based multi-stage (Maven+JDK stage, slim runtime stage),
Rust via pinned `rust-toolchain.toml`. `entrypoint.sh` remaps uid so artifacts aren't root-owned.
Make targets: `setup` (build image, wire hooks), `build`, `test`, `lint` (clippy `-D warnings`,
rustfmt --check, `mvn verify`), `release` (dist/osci + osci-bridge.jar + SHA256SUMS),
`verify-deps` (sha256 the resolved .m2 tree against committed MANIFEST), `clean`, `git-guard`.
All containerized: `OCI ?= $(shell command -v docker || command -v podman)`; `CARGO_HOME=$PWD/.cargo-home`,
`-Dmaven.repo.local=$PWD/.m2-repo` — nothing leaves this directory.

### W3 — Java sidecar bridge (`java/osci-bridge`, artifact `osci-bridge.jar`)
Thin, logic-free shim over `de.osci:osci-bibliothek-lib:2.6.1` (+ FITKO `dvdv-api`/`dvdv-impl`,
vendored with sha256s; if the fitko registry is gated → fallback: native Rust REST client, documented).
Protocol (docs/PROTOCOL.md, versioned): newline-delimited JSON over stdio:
`{"op":"send", "ref":"...", "xta_b64":"...", "recipient":{...}, "intermediary":"https://...",
 "identity":{...}}` → `{"ok":true,"message_id":"...","process_card":{...}}`; ops `send`, `fetch`,
`process-card`, `dvdv-find`, `ping` (returns lib + JVM + jar-checksum version info for `osci version`).
Wiring per `osci-bibliothek-sample`: PKCS#12 → Signer/Decrypter impls, DialogHandlerClient flow.
Unit tests: JSON contract goldens, crypto wiring smoke test with generated certs.

### W4 — Rust library (`crates/osci`)
`BridgeChild` (spawn jar, locate via `OSCI_BRIDGE_JAR` or dist layout; env, timeouts, stderr → tracing).
`OsciClient::builder().intermediary(..).identity(P12{..}).trust_anchors(..).build()`,
`send_xta(Xta::from_path|from_stdin).recipient(Recipient::Postfach(..)|Dvdv{org_key,category}).submit()`.
`DvdvDirectory` trait → `BridgeDvdv` impl (swappable for a future native client). Errors via thiserror,
exit-code classes. XTA sniff: peek root element, warn if not XTA namespace (still send — it's *arbitrary*).
Tests: protocol round-trips (proptest), fake-bridge-binary tests for lifecycle/timeout/malformed-JSON paths.

### W5 — CLI (`crates/osci-cli`, binary `osci`)
```
osci send [-|file.xta] --to <postfach:ID|dvdv:ORGKEY[:CAT>] [--subject S] [--json]
          --intermediary URL --cert client.p12 [--passenv VAR] [--fetch-receipt] [-v..]
osci fetch [--json]           # fetch deliveries + write content out
osci status <message-id>      # ProcessCard / Laufzettel
osci dvdv find --org KEY [--category CAT] [--json]
osci version                  # bridge, lib, jar sha256, JIT of the bureaucracy you're fighting
```
Config via flags + `OSCI_*` env only (no config files — leave no traces). curl-style: `-` = stdin,
`--json` output, `-v` tracing, documented exit codes (0 ok; 2 usage/config; 3 DVDV miss; 4 transport;
5 crypto). Tests: assert_cmd matrix, golden stdout/stderr, stdin piping, env handling.

### W6 — Mock intermediary + e2e (the "no online traces" guarantee)
Never touch the public Governikus test intermediary. `tests/mock_intermediary/`: hyper-based local
HTTPS server speaking just enough OSCI SOAP (InitDialog challenge → GetMessageID → StoreDelivery →
FetchDelivery/ProcessCard) with canned responses; ephemeral self-signed certs via a deterministic
openssl script run in-container. e2e scenarios: happy-path send (assert envelope recipient fields,
message ids, JSON output, exit 0), fetch, Laufzettel, intermediary-down, TLS failure, bad identity,
oversized XTA. Honest limit: content is CMS-encrypted with a random session key, so e2e asserts
metadata/envelope structure; Java-side unit tests assert pre-encryption Content equality with the
original XTA bytes.

### W7 — Docs & audit kit
README (usage + the rant), docs/PROTOCOL.md, docs/AUDIT.md (pinned versions, checksums, verify
commands), `cargo deny` config (licenses/ADVISORIES), final `make lint test release` gate.

## Privacy / traces policy
Passive dependency fetches only (crates.io, Maven Central, docker registries, fitko registry —
no accounts, no posting). Tests hit only localhost. Repo never gets a remote; pre-push hook aborts
any push attempt. Host stays Java-free.

## Acceptance criteria
`make setup lint test release` all green inside the container from a clean checkout; SHA256SUMS in
dist; `osci version` reproducible; every test offline-after-`make setup`; git log tells the story;
comments make a tired Beamte smile instead of cry.

## Order of execution
W1 → W2 → W3 (+sample-informed wiring) → W4 → W5 → W6 → W7, committing per workstream.