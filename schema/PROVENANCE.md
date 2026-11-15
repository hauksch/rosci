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

Deviation from the upstream files (required for libxml2 ≥ 2.13, whose
schema processor enforces deterministic content models — the Ubuntu
runner images ship it since the ubuntu-26 migration; upstream's
`##other` wildcard overlaps the osci namespace there):

- `soapGetMessageId.xsd`, `soapFetchDelivery.xsd`,
  `soapFetchProcessCard.xsd`, `soapExitDialog.xsd`: in the redefined
  SOAP `Header`, the trailing extension wildcard
  `namespace="##other"` → `namespace="http://www.osci.eu/ws/2014/10/transport"`
  (the XTA MessageMetaData namespace). Upstream's `##other` also matched
  osci-namespace elements, so the optional `NonIntermediaryCertificates`
  was ambiguous against it — a defect in the 2002-era upstream schemas,
  tolerated by libxml2 ≤ 2.9 and by Xerces. Wire acceptance changes only
  for extension headers in namespaces other than MessageMetaData, which
  OSCI-Transport 1.2 does not define. Sixteen further soap schemas share
  the defect but are never selected by the gate (rosci is Benutzer
  software — STANDARD-COMPLIANCE.md §4 — and responses are counted, not
  validated); patch them the same way if that ever changes.

Used by `container/xsd-validate.sh` (wire-traffic conformance checks,
docs/STANDARD-COMPLIANCE.md §3.4). Re-vendor + re-apply the deviation
when bumping the library version.
