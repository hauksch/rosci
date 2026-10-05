# Contributing

Thanks for looking under the hood. This project has strong opinions so
you don't have to — the short version: build in the container, run the
gates, keep the tests honest.

## Getting started

Requirements: `docker` or `podman`, `make`, `git`. Nothing else touches
your host — the host stays Java-free by design.

```sh
make setup    # build the pinned builder image
make build    # Java bridge + mock jars, Rust workspace
make test     # the full local suite
make check    # lint + test + audit + verify-deps — run before submitting
```

Everything runs inside the pinned builder container
([container/Dockerfile.builder](container/Dockerfile.builder),
[container/LOCK.md](container/LOCK.md) records the toolchain). CI runs
the identical commands via GitHub Actions.

## Code expectations

- **Rust:** `cargo fmt` clean, `cargo clippy --all-targets -D warnings`
  clean. The library (`crates/osci`) denies `missing_docs`.
- **Java:** compiled with `-Xlint:all` and `-Werror` — warnings fail the
  build.
- **PINs and key material** are held in `Zeroizing`/zeroized on drop
  where the language allows, and never committed. The interop fixtures
  in `crates/osci-cli/tests/fixtures/interop/` are Governikus' *public*
  demo keystores (PIN `123456`) — the documented exception, not a
  precedent.
- **Negative tests are features.** A fix that only proves the happy
  path is half a fix; the suite deliberately includes garbage-input,
  tamper, and loud-failure cases.

## Tests

- `make test` must stay green and must never touch the network — the
  e2e suite runs against a local mock intermediary only.
- The live interop suite (`make interop`) is opt-in
  (`ROSCI_INTEROP=1`) and never runs in CI; see
  [docs/TEST-INFRASTRUCTURE.md](docs/TEST-INFRASTRUCTURE.md) before
  touching it.
- New behavior needs a test that fails without it. Bug fixes need a
  regression test that pins the bug shut.

## Dependencies

Any dependency change (Rust or Maven) requires `make manifest` (commit
the refreshed `DEPENDENCY_MANIFEST.sha256`) and a green `make audit`
(cargo-deny + OSV scan). The allowlist stays empty; move versions
rather than accept advisories.

## Submitting

Small, focused changes read best. Subject line in the imperative mood
matching the history (e.g. `effi: opt-in chunked transfer —
live-verified`), body explaining *why*. `make check` green, then open
the PR — CI runs the same gates.

## License

MIT — by contributing you agree your work is released under the
repository's [LICENSE](LICENSE).
