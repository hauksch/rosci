# Real-network test infrastructure

Briefing for whoever implements the interop test suite. Everything below
was verified against primary sources on 2026-10-04; the few assumptions
are marked. Read §1 before writing a single line of test code — it is
the difference between "useful" and "mission-rule violation".

## 1. Ground rules

- The project's default posture is *never leave localhost* (README,
  mission rule 4). The interop suite against the live test intermediary
  is the **single sanctioned exception**: it must be **opt-in only**,
  e.g. gated on `ROSCI_INTEROP=1` in the environment (and/or `#[ignore]`
  tests driven by a dedicated `make interop` target). It must never run
  as part of `make test`, `make check`, or CI.
- The intermediary's operator terms: **functional tests only** — load
  tests are forbidden. There is **no availability guarantee**; the
  instance may restart at any time. A test suite must therefore *skip*
  (not fail) when the endpoint is unreachable.
- Do not commit private keys. The repo `.gitignore` already blocks
  `*.p12 *.pfx *.jks *.pem *.key *.crt *.csr`; note it does **not**
  block `*.cer`, so vendoring the public certificates (§3) is fine and
  preferred (reproducible tests, no fetch step). Pin the SHA-256 of any
  vendored cert in the test so silent replacement is noticed.

## 2. The open test intermediary (Governikus OSCI-Manager)

The one real, registration-free OSCI 1.2 test intermediary. It runs the
**OSCI-Manager** — Governikus's production intermediary product — and is
documented in the README of the very library this project wraps
([governikus/osci/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java),
section „Beispiele und Test-Infrastruktur"). The xoev.de
[intermediaries page](https://www.xoev.de/osci-xta/standard-osci-transport-1-2/osci-hilfsmittel/osci-transport-1-2-intermediaere-23213)
points there ("Governikus stellt eine Testinstanz bereit"); there is no
complete nationwide list of intermediaries, and the Länder intermediaries
(e.g. Sachsen's) are closed clubs for their own participants — this one
is the open door.

| What | Value |
|---|---|
| Client entry | `http://gov.test.osci.de/osci-manager-entry/externalentry` |
| Backend-Enabler entry | `http://gov.test.osci.de/osci-backend-entry/externalentry` |
| Registration | none |
| Terms | functional tests only, no load tests, no availability guarantee |
| Max message size | 500 MB (packets 1–50 MB) |
| Retention | 4 / 3 days, deletion after 30 days |
| Transport | plain HTTP (documented) |

Notes:

- The endpoint is machine-to-machine; a plain `GET` is answered with
  "I don't speak GET". Send OSCI POSTs, not browsers.
- **Plain HTTP is the documented mode**, and that is by design: OSCI 1.2
  carries its security in the message (transport-envelope encryption +
  XML-DSIG), not the socket. Keep `--insecure-transport` **off** — the
  envelope crypto against the intermediary's 4096-bit key and the
  automatic verification of the OSCI-Manager's response signature are
  the whole point of the exercise. (The HTTPS variant presents a
  self-signed certificate — observed 2026-10-04; don't use it, so no
  `--tls-ca` is needed either.)
- What it offers: synchronous request/response against a **passive OSCI
  recipient** that acknowledges receipt / returns an empty message —
  see `PassiveRecipient.java` in the library repo for the addressing.
- What it does **not** offer: message pickup. `rosci fetch`/`status`
  against this instance is out of scope — the async
  StoreDelivery→FetchDelivery lifecycle remains covered by the local
  mock intermediary only.

## 3. Certificates (paths verified via the GitLab API, 2026-10-04)

Prefix for all paths:
`osci-bibliothek-lib/osci-bibliothek/src/test/resources/de/osci/osci12/samples/zertifikate/`
in [governikus/osci/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java);
raw URL pattern: `https://gitlab.opencode.de/governikus/osci/osci-bib-java/-/raw/master/<path>`.

| Role | File |
|---|---|
| Intermediary cipher cert → `--intermediary-cert` | `osci_manager_cipher_4096.cer` |
| Intermediary signature cert (response-signature pinning, optional) | `osci_manager_signature_4096.cer` |
| Recipient cipher cert → `--to cert:…` | `bob_cipher_4096.cer` (likewise `alice_`, `carol_`, `dave_`) |
| Demo PKCS#12 keystores for two-sided local emulation | same stems, `.p12` |
| Legacy (do not use) | `alt/test_osci-manager_cypher.*` |

Caveat: the GitLab docs tree is tagged 2.4.3 while this project depends
on `de.osci:osci-bibliothek:2.6.1` — the paths above were verified
against `master` on 2026-10-04, but re-verify the filenames at
implementation time in case the demo PKI has rotated since.

## 4. rosci wiring

```sh
export OSCI_CERT_PIN=…            # DOI test certificate PIN
rosci send meldung.xta \
  --intermediary http://gov.test.osci.de/osci-manager-entry/externalentry \
  --intermediary-cert osci_manager_cipher_4096.cer \
  --cert doi-test.p12 \
  --to cert:bob_cipher_4096.cer \
  --subject "interop smoke"
```

Assertions for the happy path: exit code `0`, `response_signed: true`
(real RSA-PSS response signature from a foreign implementation), clean
Laufzettel/receipt, exit-code taxonomy intact for the negative paths
(e.g. a rejected message → exit `4` with the mapped feedback text, not
`[1050] de`).

## 5. Obtaining sender certificates (DOI / Verwaltungs-PKI)

The sender identity for real OSCI traffic is an X.509 certificate from
the **DOI-CA** ("Deutschland-Online-Infrastruktur"), operated by the
**Telekom Security GmbH trust center** on behalf of the federal
**Verwaltungs-PKI (V-PKI)**. The product you request is a certificate in
the sub-domain **„DOI-OSCI"** (sub-domain „Meldewesen" exists for XMeld
specifically). This is the de-facto standard issuer for OSCI 1.2
endpoint certificates inside the V-PKI world.

### 5.1 Test environment (free)

Portal: <https://doi.test.telesec.de/doi> — **no self-registration**;
the login is issued by the Registrierungsstelle (RA):

1. One-time email to the RA „Öffentliche Verwaltung",
   <smc-berlin.tsi@telekom.de> (or the RA your Land/Verbund is
   contractually bound to), with the **exact subject line**
   „Zugangsdaten für Zertifikat in der DOI-Testumgebung" — mandated
   verbatim so it cannot be confused with a paid production order. No
   special body required. Credentials arrive once and are reusable for
   all future test-certificate requests.
2. In the portal: *Software-Zertifikat beantragen* → Sub-Domäne
   **DOI-OSCI** → type **Gruppen-/Funktions-Zertifikat** (the only type
   offered there; CN must start with `GRP:`, e.g. `GRP: Musterbehörde
   XY`; the Schlüsselverantwortlicher must be a natural person).
3. Keep the defaults (SHA-256, 3-year validity), set the Sperrpasswort;
   Abrechnungsdaten are mandatory fields even though the certificate is
   free (same workflow as production).
4. Download the generated PDF application, **sign and seal** it
   (Unterschreiben und Siegeln; identification through the
   siegelführende Stelle), submit to the RA.
5. After release, download from the portal: you receive a **PKCS#12**.
   There is **no CSR** — the trust center generates the keypair
   (central key generation; the CSR's two jobs — carrying the public
   key and proof-of-possession — are moot in that model). Only **3
   download attempts** (then the certificate is blocked), and the trust
   center deletes the PKCS#12 and private key after your download
   confirmation: no permanent escrow.

Source: FITKO,
[Anleitung Beantragung DOI-Zertifikat für DVDV-Testsystem](https://docs.fitko.de/dvdv/Kundentestsystem/Anleitung_Beantragung_DOI-Zertifikat_f%C3%BCr_DVDV-Testsystem).

### 5.2 Production (paid)

Same flow at <https://doi.telesec.de/doi/ee/>; the signed application's
**page 1 goes to the RA by post** (TeleSec DOI-Portal
[FAQ](https://doi.telesec.de/doi/public/faq-contact/index.html)). RA
contact as above; pricing is contract-dependent.

### 5.3 Constraints relevant to this project

- Order the **Software-Zertifikat**, never the Smartcard variant:
  the bridge loads `PKCS12` keystores only
  (`java/osci-bridge/.../CryptoMaterial.java`); there is no PKCS#11/HSM
  support anywhere in the repo.
- The delivered PKCS#12 + PIN is a **bearer secret** — anyone holding
  both *is* that identity on the wire. Treat accordingly (the repo
  already gitignores all key material and zeroizes the PIN Rust-side;
  JVM-side string residency remains, see AUDIT.md limitation 2).
- Eligibility: the RA issues credentials to **Behörden or Dienstleister
  contracted by them**. A private project without such a mandate may be
  declined by the catch-all RA; in that case the certificate must be
  requested through a sponsoring authority.
- **The DOI certificate is not DVDV access.** It is your OSCI
  message-level identity and, once registered, *content* of a DVDV
  entry. Querying the DVDV is a separate pair of doors: the classic
  DVDV2 SOAP API authenticates via TLS client certificate, the newer
  FITKO REST API via OAuth 2.0 with `jwt-bearer` client assertions
  (certificate-backed under the hood). The DVDV Kundentestsystem
  documents **no REST interface** — cert + SOAP is the whole documented
  story (as of 2026-10-04). rosci needs none of this for the interop
  suite: `--to cert:` + `--intermediary-cert` bypasses the DVDV
  entirely.

## 6. Open items for the implementing agent

Marked assumptions — verify, then update this section:

- **Sender acceptance:** does gov.test.osci.de accept a DOI test
  certificate as sender identity? (Assumed yes — the instance is open
  and unregistered — but unverified.)
- **Passive-recipient addressing:** extract the exact recipient
  address/subject conventions from `PassiveRecipient.java` in the
  library repo; `bob_cipher_4096.cer` as content-encryption target is
  the plausible default but not confirmed.
- **Skip vs. fail:** unreachable endpoint must skip. Decide the
  mechanism (`ROSCI_INTEROP=1` env gate, `#[ignore]`, `make interop`)
  and wire it into the Makefile *without* touching `make test` /
  `make check`.

## 7. Sources

- Governikus OSCI library + test infrastructure:
  <https://gitlab.opencode.de/governikus/osci/osci-bib-java> (README
  „Beispiele und Test-Infrastruktur"; certificate tree verified via
  GitLab API)
- xoev.de, OSCI-Transport 1.2 Intermediäre:
  <https://www.xoev.de/osci-xta/standard-osci-transport-1-2/osci-hilfsmittel/osci-transport-1-2-intermediaere-23213>
- FITKO, DOI-Zertifikat beantragen (DVDV-Testsystem):
  <https://docs.fitko.de/dvdv/Kundentestsystem/Anleitung_Beantragung_DOI-Zertifikat_f%C3%BCr_DVDV-Testsystem>
- TeleSec DOI portals: <https://doi.test.telesec.de/doi> (test),
  <https://doi.telesec.de/doi/ee/> (production),
  <https://doi.telesec.de/doi/public/faq-contact/index.html> (FAQ)
- FITKO DVDV documentation (Kundentestsystem, no REST documented):
  <https://docs.fitko.de/dvdv>
- FIT-Connect evaluation of the DVDV REST API (OAuth/jwt-bearer,
  production ecosystem):
  <https://git.fitko.de/fit-connect/planning/-/issues/705>
