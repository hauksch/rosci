//! Configuration value types: intermediary, identity, TLS knobs.

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::Error;

/// The intermediary (Kommunikationsserver) everything is sent through.
#[derive(Debug, Clone, Default)]
pub struct Intermediary {
    /// Entry URL, e.g. `https://ks.example.de/osci-manager-entry/externalentry`.
    pub url: String,
    /// The intermediary's cipher certificate (PEM or base64 DER).
    pub cipher_cert: String,
    /// Optional signature certificate. Responses carry it anyway.
    pub signature_cert: Option<String>,
}

impl Intermediary {
    /// An intermediary from its entry URL and cipher certificate.
    pub fn new(url: impl Into<String>, cipher_cert: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cipher_cert: cipher_cert.into(),
            signature_cert: None,
        }
    }
}

/// Sender identity: a signature PKCS#12 and (optionally) a separate
/// cipher PKCS#12. In the wild these are often two files; the OSCI world
/// never met a certificate it couldn't split into two more.
///
/// PINs are held in `Zeroizing` so every copy this crate makes is scrubbed
/// on drop. What stays unscrubbable, honestly: the serialized JSON request
/// line on the pipe and the JVM-side strings past it (docs/AUDIT.md).
#[derive(Clone, Default)]
pub struct Identity {
    signer_p12_b64: String,
    signer_pin: Zeroizing<String>,
    decrypter_p12_b64: Option<String>,
    decrypter_pin: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Identity {
    // zeroize's derived Debug prints the inner value, so the derived impl
    // would put every PIN on the log — hand-rolled redaction instead.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("signer_p12_b64_len", &self.signer_p12_b64.len())
            .field("signer_pin", &"<redacted>")
            .field(
                "decrypter_p12",
                &self.decrypter_p12_b64.as_ref().map(|p| p.len()),
            )
            .field("decrypter_pin", &"<redacted>")
            .finish()
    }
}

impl Identity {
    /// Identity from PKCS#12 file(s). The signer bundle must contain a
    /// private key; the decrypter bundle, when given, must too.
    pub fn from_p12_files(
        signer_p12: &std::path::Path,
        signer_pin: &str,
        decrypter_p12: Option<&std::path::Path>,
        decrypter_pin: Option<&str>,
    ) -> Result<Self, Error> {
        use base64::Engine as _;
        let read_b64 = |p: &std::path::Path| -> Result<String, Error> {
            let buf = std::fs::read(p)
                .map_err(|e| Error::Config(format!("cannot read {}: {e}", p.display())))?;
            Ok(base64::engine::general_purpose::STANDARD.encode(&buf))
        };
        Ok(Self {
            signer_p12_b64: read_b64(signer_p12)?,
            signer_pin: Zeroizing::new(signer_pin.to_string()),
            decrypter_p12_b64: match decrypter_p12 {
                Some(p) => Some(read_b64(p)?),
                None => None,
            },
            decrypter_pin: decrypter_pin.map(|p| Zeroizing::new(p.to_string())),
        })
    }

    /// Identity from in-memory PKCS#12 bytes (the native client's path —
    /// no temp files on disk, the bytes are base64'd once and scrubbed on
    /// drop like the file-based variant).
    pub fn from_p12_b64(
        signer_p12_b64: impl Into<String>,
        signer_pin: &str,
        decrypter_p12_b64: Option<String>,
        decrypter_pin: Option<&str>,
    ) -> Result<Self, Error> {
        let signer_p12_b64 = signer_p12_b64.into();
        if signer_p12_b64.is_empty() {
            return Err(Error::Config("empty signer PKCS#12".into()));
        }
        Ok(Self {
            signer_p12_b64,
            signer_pin: Zeroizing::new(signer_pin.to_string()),
            decrypter_p12_b64,
            decrypter_pin: decrypter_pin.map(|p| Zeroizing::new(p.to_string())),
        })
    }

    /// The signer keystore, base64-decoded, and its PIN. Accepts both
    /// standard and MIME-wrapped base64 (the Java decoder was lenient; the
    /// native one must read the same files).
    pub(crate) fn signer_material(&self) -> Result<(Vec<u8>, String), Error> {
        let der = decode_lenient_base64(&self.signer_p12_b64)
            .map_err(|e| Error::Config(format!("signer PKCS#12 base64: {e}")))?;
        Ok((der, self.signer_pin.clone().to_string()))
    }

    /// The decrypter keystore, base64-decoded, and its PIN — falling back
    /// to the signer bundle when no separate decrypter was configured
    /// (the Java bridge's same fallback).
    pub(crate) fn decrypter_material(&self) -> Result<(Vec<u8>, String), Error> {
        match (&self.decrypter_p12_b64, &self.decrypter_pin) {
            (Some(p12), Some(pin)) => {
                let der = decode_lenient_base64(p12)
                    .map_err(|e| Error::Config(format!("decrypter PKCS#12 base64: {e}")))?;
                Ok((der, pin.clone().to_string()))
            }
            _ => self.signer_material(),
        }
    }
}

/// TLS knobs for the native transport: trust anchors and mutual-TLS
/// client identity, parsed and applied at builder time.
#[derive(Clone, Default)]
pub struct Tls {
    /// Trust anchors (PEM or base64 DER). Non-empty REPLACES the default
    /// root set — for intermediaries under a self-managed CA.
    pub trust_anchors: Vec<String>,
    /// TLS client authentication bundle (base64 PKCS#12); its leaf
    /// certificate chain and private key become the client identity.
    pub client_p12_b64: Option<String>,
    /// PIN for the TLS client bundle.
    pub client_pin: Option<Zeroizing<String>>,
    /// TCP connect timeout in milliseconds (reserved; the native
    /// transport applies one global request timeout).
    pub connect_timeout_ms: Option<u64>,
    /// Socket read timeout in milliseconds (reserved; ditto).
    pub read_timeout_ms: Option<u64>,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls")
            .field("trust_anchors", &self.trust_anchors.len())
            .field(
                "client_p12_b64",
                &self.client_p12_b64.as_ref().map(|p| p.len()),
            )
            .field("client_pin", &"<redacted>")
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("read_timeout_ms", &self.read_timeout_ms)
            .finish()
    }
}

impl Tls {
    /// Adds a trust anchor from a file (PEM or DER; see
    /// [`read_certificate_file`]).
    pub fn with_trust_anchor_file(mut self, path: &std::path::Path) -> Result<Self, Error> {
        let raw = read_certificate_file(path, "TLS trust anchor")?;
        self.trust_anchors.push(raw);
        Ok(self)
    }

    /// Sets a TLS client-authentication bundle from a PKCS#12 file. The
    /// bridge base64-decodes it into a KeyStore and presents it via a
    /// KeyManagerFactory; parsing (and PIN errors) happen JVM-side.
    pub fn with_client_p12_file(
        mut self,
        path: &std::path::Path,
        pin: &str,
    ) -> Result<Self, Error> {
        use base64::Engine as _;
        let buf = std::fs::read(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        self.client_p12_b64 = Some(base64::engine::general_purpose::STANDARD.encode(&buf));
        self.client_pin = Some(Zeroizing::new(pin.to_string()));
        Ok(self)
    }
}

/// Base64 that tolerates line wrapping — the wire/keystore format was
/// MIME-flavoured for years and files in the wild carry the newlines.
fn decode_lenient_base64(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(clean.as_bytes())
        .map_err(|e| e.to_string())
}

/// Reads a certificate file for the bridge, which consumes PEM *or*
/// bare-base64-DER strings (`CryptoMaterial.parseCertificate`).
///
/// UTF-8 text passes through unchanged (PEM, with or without headers).
/// Binary that starts like a DER SEQUENCE (`0x30`) is handed over as
/// base64 — an OpenSSL `.cer` works as-is, as this API has always
/// promised. Anything else binary is named as such; the days of
/// "stream did not contain valid UTF-8" as a diagnosis are over.
pub fn read_certificate_file(path: &Path, what: &str) -> Result<String, Error> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Config(format!("cannot read {what} {}: {e}", path.display())))?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(e) if e.as_bytes().first() == Some(&0x30) => {
            use base64::Engine as _;
            Ok(base64::engine::general_purpose::STANDARD.encode(e.as_bytes()))
        }
        Err(e) => Err(Error::Config(format!(
            "{what} {} is neither PEM nor DER (first byte is 0x{:02x})",
            path.display(),
            e.as_bytes().first().copied().unwrap_or(0)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_anchor_file_is_read_into_the_list() {
        let dir = tempfile::tempdir().unwrap();
        let pem = dir.path().join("ca.pem");
        std::fs::write(
            &pem,
            "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let tls = Tls::default().with_trust_anchor_file(&pem).unwrap();
        assert_eq!(tls.trust_anchors.len(), 1);
        assert!(tls.trust_anchors[0].contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn trust_anchor_missing_file_is_a_config_error() {
        let err = Tls::default()
            .with_trust_anchor_file(std::path::Path::new("/gibt-es-nicht/ca.pem"))
            .unwrap_err();
        assert!(matches!(err, Error::Config(ref c) if c.contains("cannot read")));
    }

    #[test]
    fn read_certificate_file_passes_pem_through() {
        let dir = tempfile::tempdir().unwrap();
        let pem = dir.path().join("r.pem");
        std::fs::write(
            &pem,
            "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let read = read_certificate_file(&pem, "recipient certificate").unwrap();
        assert!(read.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn read_certificate_file_hands_der_over_as_base64() {
        let dir = tempfile::tempdir().unwrap();
        let der = dir.path().join("r.cer");
        std::fs::write(&der, [0x30u8, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef]).unwrap();
        let read = read_certificate_file(&der, "recipient certificate").unwrap();
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&read)
            .expect("result is bare base64");
        assert_eq!(decoded, [0x30u8, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef]);
        assert!(
            !read.contains('\n'),
            "wire format is whitespace-free base64"
        );
    }

    #[test]
    fn read_certificate_file_names_other_binary_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("r.bin");
        std::fs::write(&junk, [0xff, 0xd8, 0xff, 0x00, 0x13]).unwrap(); // no 0x30 lead
        let err = read_certificate_file(&junk, "recipient certificate").unwrap_err();
        assert!(matches!(err, Error::Config(ref c) if c.contains("neither PEM nor DER")));
    }

    #[test]
    fn read_certificate_file_reports_missing_file_with_its_role() {
        let err = read_certificate_file(
            std::path::Path::new("/gibt-es-nicht/r.cer"),
            "intermediary certificate",
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Config(ref c) if c.contains("intermediary certificate") && c.contains("cannot read"))
        );
    }

    #[test]
    fn tls_client_p12_missing_file_is_a_config_error() {
        let err = Tls::default()
            .with_client_p12_file(std::path::Path::new("/gibt-es-nicht/client.p12"), "x")
            .unwrap_err();
        assert!(matches!(err, Error::Config(ref c) if c.contains("cannot read")));
    }

    #[test]
    fn identity_missing_p12_is_a_config_error() {
        let err = Identity::from_p12_files(
            std::path::Path::new("/kein/p12/hier.p12"),
            "123456",
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Config(ref c) if c.contains("cannot read")));
    }
}
