# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | yes |
| < 0.4 | no |

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting** (Repository →
Security → Report a vulnerability). Do not open a public issue for
anything you believe is exploitable — reports stay private until a fix
is released, and you will be credited in the changelog if you wish.

Include what you can of: affected command and flags, a reproduction
(minimal payload or dump), and the release/build you tested against
(`rosci version` prints the binary and bridge-jar state).

## Scope

**In scope:** the `rosci` CLI (`crates/osci-cli`) and the Java bridge
(`java/osci-bridge`) — how they parse bridge responses and fetched
messages, how they handle keys/PINs, what they put on the wire, and the
local files they read and write.

**Out of scope:**
- The wrapped [`de.osci` library](https://gitlab.opencode.de/governikus/osci/osci-bib-java)
  (report upstream to Governikus) — rosci inherits its crypto and XML
  handling; known inherited limitations are documented in
  [docs/AUDIT.md](docs/AUDIT.md).
- `java/osci-mock` — a local-only test intermediary bound to
  127.0.0.1, never shipped.
- The public OSCI-Manager test instance used by the opt-in interop
  suite — that is Governikus' infrastructure.

## Known, documented limitations

Security-relevant limitations (unremovable PIN copies in the JSON pipe
line and JVM heap, non-reproducible jar bytes, DVDV offline-only) are
kept honestly in [docs/AUDIT.md](docs/AUDIT.md) rather than in this
file — read both before relying on rosci for anything sensitive.
