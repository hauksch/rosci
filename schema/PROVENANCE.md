# Schema provenance

Vendored from [governikus/osci/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java),
tag **2.6.1**, path `osci-bibliothek-lib/osci-schema/src/main/resources/schema/`
(retrieved 2026-10-04). These are the normative OSCI-Transport 1.2 wire
schemas (Korrigenda 1–10 integrated) as shipped by the reference
implementation; the same set is published on
[xoev.de](https://www.xoev.de/osci-xta/standard-osci-transport-1-2/osci-versionsuebersicht-23217)
as „XML-Schema incl. Korrigenda 1-10".

Deviation from the upstream files (required for libxml2, which — unlike
Java's Xerces — refuses to resolve a QName with trailing whitespace):

- `order.xsd` line 472: `type="xsd:dateTime "` → `type="xsd:dateTime"`
  (trailing space removed from the `RecentModification` element
  declaration; whitespace-only, no semantic change).

Used by `container/xsd-validate.sh` (wire-traffic conformance checks,
docs/STANDARD-COMPLIANCE.md §3.4). Re-vendor + re-apply the deviation
when bumping the library version.
