//! Configuration value types: intermediary, identity, TLS knobs.

use crate::error::Error;
use crate::protocol::{IdentityMsg, Party, TlsMsg};

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
    pub fn new(url: impl Into<String>, cipher_cert: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            cipher_cert: cipher_cert.into(),
            signature_cert: None,
        }
    }

    pub(crate) fn to_msg(&self) -> Party {
        Party {
            url: Some(self.url.clone()),
            cipher_cert: Some(self.cipher_cert.clone()),
            signature_cert: self.signature_cert.clone(),
        }
    }
}

/// Sender identity: a signature PKCS#12 and (optionally) a separate
/// cipher PKCS#12. In the wild these are often two files; the OSCI world
/// never met a certificate it couldn't split into two more.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    signer_p12_b64: String,
    signer_pin: String,
    decrypter_p12_b64: Option<String>,
    decrypter_pin: Option<String>,
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
            signer_pin: signer_pin.to_string(),
            decrypter_p12_b64: match decrypter_p12 {
                Some(p) => Some(read_b64(p)?),
                None => None,
            },
            decrypter_pin: decrypter_pin.map(str::to_string),
        })
    }

    pub(crate) fn to_msg(&self) -> IdentityMsg {
        IdentityMsg {
            signer_p12: Some(self.signer_p12_b64.clone()),
            signer_pin: Some(self.signer_pin.clone()),
            decrypter_p12: self.decrypter_p12_b64.clone(),
            decrypter_pin: self.decrypter_pin.clone(),
        }
    }
}

/// TLS knobs passed straight through to the bridge transport.
#[derive(Debug, Clone, Default)]
pub struct Tls {
    /// Additional trust anchors (PEM / base64 DER). Empty = system store.
    pub trust_anchors: Vec<String>,
    /// TLS client authentication bundle (PEM bytes of a PKCS#12, base64).
    pub client_p12_b64: Option<String>,
    pub client_pin: Option<String>,
    pub connect_timeout_ms: Option<u64>,
    pub read_timeout_ms: Option<u64>,
}

impl Tls {
    /// Adds a trust anchor from a file (PEM or DER).
    pub fn with_trust_anchor_file(mut self, path: &std::path::Path) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        self.trust_anchors.push(raw);
        Ok(self)
    }

    pub(crate) fn to_msg(&self) -> TlsMsg {
        TlsMsg {
            trust_anchors: if self.trust_anchors.is_empty() {
                None
            } else {
                Some(self.trust_anchors.clone())
            },
            client_p12: self.client_p12_b64.clone(),
            client_pin: self.client_pin.clone(),
            connect_timeout_ms: self.connect_timeout_ms,
            read_timeout_ms: self.read_timeout_ms,
        }
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

    #[test]
    fn tls_msg_omits_empty_trust_anchors() {
        let msg = Tls::default().to_msg();
        assert!(msg.trust_anchors.is_none());
        let msg = Tls {
            trust_anchors: vec!["CERT".into()],
            ..Tls::default()
        }
        .to_msg();
        assert_eq!(msg.trust_anchors.unwrap(), vec!["CERT".to_string()]);
    }
}
