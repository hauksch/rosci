# osci-deshittifier

> **`osci` — the curl of OSCI.** Send an arbitrary XTA message to any OSCI recipient,
> resolved by postbox or via DVDV, without first filing a request in triplicate.

A clean, modern Rust API and CLI wrapped around the Governikus OSCI-Transport-1.2
Java library (`de.osci:osci-bibliothek-lib` — aging, but it knows where the bodies
are buried, cryptographically speaking).

## Why?

Because in the year 2026, the reference implementation for legally-binding German
administration messaging still has the ergonomics of a fax machine that went to
Verwaltungsschule. Integrating it normally means a JVM, four keystores, a
funktionsbeschreibung.pdf, and a prayer. We wrap that entire
Zwischenbericht-zwischen-Zwischenbericht experience behind one honest binary:

```
osci send meldung.xta --to dvdv:02411000012345 --subject "XMeld" \
     --intermediary https://intermediary.example/osci --cert client.p12
```

The XTA file is treated as opaque bytes — you worry about the content,
`osci` worries about the ceremony.

## Mission rules

1. Everything lives in this directory. Build caches, Maven repo, cargo home — all local.
2. All building happens via `make`, inside pinned containers. The host stays Java-free
   (it has suffered enough).
3. This repo is never pushed anywhere. A pre-push hook enforces it; see `hooks/pre-push`.
4. Tests only ever talk to a mock intermediary on localhost. No online traces.
5. Comments may grumble about bureaucracy. Gently. It's not the Beamte's fault.

## Status

See `make help`. Current workstreams: bridge (Java), library + CLI (Rust),
mock intermediary (e2e tests), audit kit.

## License

MIT (see `LICENSE`). The wrapped OSCI library is dual-licensed EUPL-1.2/MIT by
Governikus — thank you, sincerely, for open-sourcing it.
