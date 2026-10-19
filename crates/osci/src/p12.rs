//! PKCS#12 keystore parsing, feeding the oscirs crypto SPIs.
//!
//! The bridge protocol hands identities around as PKCS#12 bytes plus a
//! PIN; this module turns those into the `Signer`/`Decrypter`
//! implementations oscirs's dialog machinery consumes. oscirs itself
//! deliberately ships only PEM-file constructors — keystore parsing was
//! out of its scope, so it lives here, next to the code that owns the
//! identity wire format.
//!
//! The RSA plumbing itself (PSS parameters, v1.5 vs OAEP URI tables) is
//! NOT reimplemented here: both SPIs delegate to oscirs's `sign_rsa` and
//! `unwrap_session_key`, so behaviour stays byte-identical with the
//! cross-verified stack. This module only owns keystore parsing and the
//! trait wiring.

use rsa::pkcs8::DecodePrivateKey;

use oci::algorithms::{DEFAULT_KEY_TRANSPORT, KEY_TRANSPORT_RSA_1_5};
use oci::{Certificate, CryptoError};
use osci_crypto as oci;

pub use oci::software::{Decrypter, Signer};

use crate::error::Error;

/// A parsed PKCS#12 identity: RSA private key plus its certificate chain
/// (leaf first, like the keystore stores it).
#[derive(Clone)]
pub struct P12Keypair {
    key: rsa::RsaPrivateKey,
    /// Leaf certificate, as the oscirs crypto layer wants it.
    certificate: Certificate,
    /// The full chain from the keystore (leaf first).
    chain: Vec<Certificate>,
}

impl P12Keypair {
    /// Parses PKCS#12 DER bytes with the keystore password. Fails with
    /// [`Error::Config`] on wrong PIN, malformed input, or a non-RSA key —
    /// the same contracts the Java bridge's `CryptoMaterial` enforced.
    pub fn parse(der: &[u8], password: &str) -> Result<Self, Error> {
        let store = p12_keystore::KeyStore::from_pkcs12(
            der,
            password,
            p12_keystore::Pkcs12ImportPolicy::Relaxed,
        )
        .map_err(|e| Error::Config(format!("pkcs#12: {e}")))?;

        let (_, keychain) = store
            .private_key_chain()
            .ok_or_else(|| Error::Config("pkcs#12: no private key entry in keystore".into()))?;

        let key = rsa::RsaPrivateKey::from_pkcs8_der(keychain.key().as_der())
            .map_err(|e| Error::Config(format!("pkcs#12: private key: {e}")))?;

        let mut chain = Vec::new();
        for cert in keychain.certs() {
            chain.push(
                Certificate::from_der(cert.as_der())
                    .map_err(|e| Error::Config(format!("pkcs#12: certificate: {e}")))?,
            );
        }
        let certificate = chain.first().cloned().ok_or_else(|| {
            Error::Config("pkcs#12: keystore carries a key but no certificate".into())
        })?;

        Ok(Self {
            key,
            certificate,
            chain,
        })
    }

    /// The leaf certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// The certificate chain, leaf first.
    pub fn chain(&self) -> &[Certificate] {
        &self.chain
    }
}

/// PKCS#12-backed signer implementing oscirs's [`Signer`] SPI.
pub struct P12Signer {
    keypair: P12Keypair,
    preferred: Option<String>,
}

impl P12Signer {
    /// Wraps a parsed keystore; `preferred` overrides the signature
    /// method URI the dialog context would otherwise pick.
    pub fn new(keypair: P12Keypair, preferred: Option<String>) -> Self {
        Self { keypair, preferred }
    }
}

impl Signer for P12Signer {
    fn certificate(&self) -> &Certificate {
        self.keypair.certificate()
    }

    fn algorithm(&self) -> Option<String> {
        self.preferred.clone()
    }

    fn sign(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, CryptoError> {
        osci_crypto::software::sign_rsa(&self.keypair.key, data, algorithm)
    }
}

/// PKCS#12-backed decrypter implementing oscirs's [`Decrypter`] SPI:
/// RSAES-PKCS1-v1_5 and RSAES-OAEP session-key unwrapping.
pub struct P12Decrypter {
    keypair: P12Keypair,
}

impl P12Decrypter {
    /// Wraps a parsed keystore for session-key unwrapping.
    pub fn new(keypair: P12Keypair) -> Self {
        Self { keypair }
    }
}

impl Decrypter for P12Decrypter {
    fn certificate(&self) -> &Certificate {
        self.keypair.certificate()
    }

    fn decrypt_pkcs1v15(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        osci_crypto::software::unwrap_session_key(
            &self.keypair.key,
            data,
            KEY_TRANSPORT_RSA_1_5,
            None,
            None,
        )
    }

    fn decrypt_oaep(
        &self,
        data: &[u8],
        mgf_algorithm: &str,
        digest_algorithm: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        osci_crypto::software::unwrap_session_key(
            &self.keypair.key,
            data,
            DEFAULT_KEY_TRANSPORT,
            Some(mgf_algorithm),
            Some(digest_algorithm),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time SPI conformance — the round-trip contracts (v1.5 and
    // OAEP unwrap, wrong-PIN rejection) run against real openssl-built
    // keystores in the e2e suite, where the fixtures live.
    #[test]
    fn signer_and_decrypter_implement_spis() {
        fn assert_signer<T: Signer>() {}
        fn assert_decrypter<T: Decrypter>() {}
        assert_signer::<P12Signer>();
        assert_decrypter::<P12Decrypter>();
    }

    #[test]
    fn rejects_garbage_input() {
        let e = match P12Keypair::parse(b"\x00\x01\x02\x03", "pin") {
            Err(e) => e,
            Ok(_) => panic!("garbage parsed"),
        };
        assert!(matches!(e, Error::Config(_)));
    }

    #[test]
    fn rejects_empty_input() {
        let e = match P12Keypair::parse(b"", "pin") {
            Err(e) => e,
            Ok(_) => panic!("empty parsed"),
        };
        assert!(matches!(e, Error::Config(_)));
    }
}
