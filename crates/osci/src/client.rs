//! The public client: build once, send many, sleep well.

use std::path::Path;

use crate::config::{Identity, Intermediary, Tls};
use crate::dvdv::{DvdvDirectory, DvdvEntry};
use crate::error::Error;
use crate::native::NativeClient;
use crate::protocol::{FetchedMessage, ProcessCard, Receipt, VersionInfo};
use crate::xta::Xta;

/// A ready-to-use OSCI client, running the OSCI 1.2 stack natively
/// (oscirs) — no sidecar process, nothing to babysit.
///
/// Built via [`OsciClient::builder`]. Operations are independent: each one
/// runs its own OSCI dialog (open, work, close), so a failed send leaves
/// nothing wedged behind.
#[derive(Clone)]
pub struct OsciClient {
    native: NativeClient,
}

impl std::fmt::Debug for OsciClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsciClient")
            .field("native", &self.native)
            .finish_non_exhaustive()
    }
}

/// How to select messages when fetching.
#[derive(Debug, Clone)]
pub enum FetchQuery {
    /// Only the message with this OSCI message id.
    ByMessageId(String),
    /// Everything waiting in the postbox.
    All,
}

impl OsciClient {
    /// Starts the builder for a new client.
    pub fn builder() -> OsciClientBuilder {
        OsciClientBuilder::default()
    }

    /// Version handshake: library, stack, provider. Local — no dialog is
    /// opened for this.
    pub fn versions(&self) -> Result<VersionInfo, Error> {
        Ok(self.native.versions())
    }

    /// Starts a send flow for an XTA payload.
    ///
    /// ```no_run
    /// # use osci::{OsciClient, Xta, Recipient};
    /// # fn go(client: &mut OsciClient) -> Result<(), osci::Error> {
    /// let receipt = client.send_xta(Xta::from_path("m.xta")?)
    ///     .recipient(Recipient::from_cipher_cert_file("r.cer")?)
    ///     .subject("Anzeige")
    ///     .submit()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_xta(&mut self, xta: Xta) -> SendBuilder<'_> {
        SendBuilder {
            client: self,
            xta,
            attachments: Vec::new(),
            chunk_size_kb: None,
            metadata_author: None,
            metadata_reader: None,
            recipient: None,
            subject: None,
            sign: true,
            encrypt: true,
        }
    }

    /// Fetches messages from our postbox.
    pub fn fetch(&mut self, query: FetchQuery) -> Result<Vec<FetchedMessage>, Error> {
        self.fetch_with(query, None)
    }

    /// Fetch with EFFI partial fetch (KB per chunk) — for messages that
    /// were stored chunked. A message smaller than one chunk arrives as a
    /// plain fetch response on round one.
    pub fn fetch_with(
        &mut self,
        query: FetchQuery,
        chunk_size_kb: Option<u64>,
    ) -> Result<Vec<FetchedMessage>, Error> {
        let rule = match &query {
            FetchQuery::ByMessageId(id) => Some(id.clone()),
            FetchQuery::All => None,
        };
        self.native.fetch(rule.as_deref(), chunk_size_kb)
    }

    /// Fetches the Laufzettel (process card) for a message we sent.
    pub fn process_card(&mut self, message_id: &str) -> Result<Vec<ProcessCard>, Error> {
        self.native.process_card(message_id)
    }

    /// End-of-life convenience: with no child process to stop, this is a
    /// no-op kept for API compatibility.
    pub fn finish(&mut self) {}

    /// Nothing to shut down natively; always succeeds.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Builder for [`OsciClient`]. All knobs optional except the ones that
/// aren't (intermediary + identity), because OSCI without certificates is
/// just an expensive way to shout into the void.
#[derive(Debug, Clone)]
pub struct OsciClientBuilder {
    intermediary: Option<Intermediary>,
    identity: Option<Identity>,
    timeout: std::time::Duration,
    tls: Tls,
    insecure_transport: bool,
}

impl Default for OsciClientBuilder {
    fn default() -> Self {
        Self {
            intermediary: None,
            identity: None,
            timeout: std::time::Duration::from_secs(120),
            tls: Tls::default(),
            insecure_transport: false,
        }
    }
}

impl OsciClientBuilder {
    pub fn intermediary(mut self, intermediary: Intermediary) -> Self {
        self.intermediary = Some(intermediary);
        self
    }

    pub fn intermediary_url(mut self, url: impl Into<String>) -> Self {
        self.intermediary
            .get_or_insert_with(Intermediary::default)
            .url = url.into();
        self
    }

    pub fn intermediary_cipher_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.intermediary
            .get_or_insert_with(Intermediary::default)
            .cipher_cert = pem.into();
        self
    }

    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn signer_p12_file(mut self, path: impl AsRef<Path>, pin: &str) -> Result<Self, Error> {
        self.identity = Some(Identity::from_p12_files(path.as_ref(), pin, None, None)?);
        Ok(self)
    }

    /// Identity with a separate decrypter bundle — required when fetched
    /// content was encrypted to a cipher certificate that differs from the
    /// signing certificate.
    pub fn signer_and_decrypter_p12_files(
        mut self,
        signer: impl AsRef<Path>,
        signer_pin: &str,
        decrypter: impl AsRef<Path>,
        decrypter_pin: &str,
    ) -> Result<Self, Error> {
        self.identity = Some(Identity::from_p12_files(
            signer.as_ref(),
            signer_pin,
            Some(decrypter.as_ref()),
            Some(decrypter_pin),
        )?);
        Ok(self)
    }

    /// Bounds how long a single operation may take (the HTTP transport's
    /// global timeout) before the call fails. Services should set this
    /// explicitly: a wedged intermediary must surface as HTTP 504, not as
    /// a connection held open for the default two minutes.
    pub fn response_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn tls(mut self, tls: Tls) -> Self {
        self.tls = tls;
        self
    }

    /// Test mode: disable SOAP-transport encryption and transport
    /// signatures so a local mock intermediary can parse envelopes.
    /// Content signing/encryption stay on. Use only against endpoints
    /// you own; the flag is named honestly.
    pub fn insecure_transport(mut self) -> Self {
        self.insecure_transport = true;
        self
    }

    /// Validates the configuration and parses the keystores — fails loudly
    /// and early, the way incident reports wish they could.
    pub fn build(self) -> Result<OsciClient, Error> {
        let intermediary = self
            .intermediary
            .filter(|i| !i.url.is_empty() && !i.cipher_cert.is_empty())
            .ok_or_else(|| {
                Error::Config("intermediary (url + cipher certificate) is required".to_string())
            })?;
        let identity = self
            .identity
            .ok_or_else(|| Error::Config("identity (signer PKCS#12) is required".to_string()))?;

        // TLS: trust anchors REPLACE the default roots (self-managed
        // intermediary CAs); the client bundle becomes the mutual-TLS
        // identity. Parsed here, loudly, exactly like the identity.
        let mut tls_roots = Vec::new();
        for anchor in &self.tls.trust_anchors {
            let der = crate::native::certificate_der(anchor)
                .ok_or_else(|| Error::Config("unparseable TLS trust anchor".to_string()))?;
            tls_roots.push(der);
        }
        let mut tls_client_chain = Vec::new();
        let mut tls_client_key_pem = String::new();
        if let Some(p12_b64) = &self.tls.client_p12_b64 {
            let pin = self
                .tls
                .client_pin
                .as_ref()
                .ok_or_else(|| Error::Config("tls.client_pin is required with client_p12_b64".into()))?;
            let der = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                p12_b64.trim(),
            )
            .map_err(|e| Error::Config(format!("tls.client_p12_b64 is not base64: {e}")))?;
            let keypair = crate::p12::P12Keypair::parse(&der, pin.as_str())?;
            tls_client_chain = keypair
                .chain()
                .iter()
                .map(|c| c.der().to_vec())
                .collect();
            use rsa::pkcs8::EncodePrivateKey;
            let key_der = keypair
                .key()
                .to_pkcs8_der()
                .map_err(|e| Error::Config(format!("tls client key not PKCS#8-encodable: {e}")))?;
            tls_client_key_pem = pem_wrap("PRIVATE KEY", key_der.as_bytes());
        }

        let native = NativeClient::new(
            intermediary.clone(),
            &identity,
            self.timeout,
            self.insecure_transport,
            osci_transport::http::HttpTransportTls {
                root_certs: tls_roots,
                client_chain: tls_client_chain,
                client_key_pem: tls_client_key_pem,
            },
        )?;

        Ok(OsciClient { native })
    }
}

/// A recipient, addressed the only way OSCI truly respects: a cipher
/// certificate. (`DVDV entries resolve into one of these.)
#[derive(Debug, Clone)]
pub struct Recipient {
    /// The recipient's cipher certificate (PEM or base64 DER).
    pub cipher_cert: String,
    /// Optional signature certificate.
    pub signature_cert: Option<String>,
}

impl Recipient {
    /// Loads a recipient from a cipher certificate file (PEM or DER).
    pub fn from_cipher_cert_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let pem = crate::read_certificate_file(path, "recipient certificate")?;
        Ok(Self {
            cipher_cert: pem,
            signature_cert: None,
        })
    }

    /// Builds a recipient from a cipher certificate in PEM or base64 DER form.
    pub fn from_cipher_cert_pem(pem: impl Into<String>) -> Self {
        Self {
            cipher_cert: pem.into(),
            signature_cert: None,
        }
    }

    /// Resolves a DVDV entry into a recipient.
    pub fn from_dvdv_entry(entry: &DvdvEntry) -> Self {
        Self {
            cipher_cert: entry.recipient_cipher_cert.clone(),
            signature_cert: None,
        }
    }
}

/// Half-built send operation. Terminates in [`SendBuilder::submit`].
pub struct SendBuilder<'a> {
    client: &'a mut OsciClient,
    xta: Xta,
    attachments: Vec<Xta>,
    chunk_size_kb: Option<u64>,
    metadata_author: Option<String>,
    metadata_reader: Option<String>,
    recipient: Option<Recipient>,
    subject: Option<String>,
    sign: bool,
    encrypt: bool,
}

impl SendBuilder<'_> {
    /// Sets the recipient (required before submit).
    pub fn recipient(mut self, recipient: Recipient) -> Self {
        self.recipient = Some(recipient);
        self
    }

    /// Adds an additional content part riding in the same Zustellung —
    /// the standard's term for what everyone else calls an attachment.
    pub fn attachment(mut self, xta: Xta) -> Self {
        self.attachments.push(xta);
        self
    }

    /// Sends via EFFI chunked transfer with this many KB per chunk
    /// (spec „Effiziente Übertragung großer Datenmengen"). The fully
    /// composed+signed delivery is split and shipped as a
    /// PartialStoreDelivery sequence.
    pub fn chunk_size_kb(mut self, kb: u64) -> Self {
        self.chunk_size_kb = Some(kb);
        self
    }

    /// Sets the XTA MessageMetaData author identifier (Ergänzung; e.g.
    /// an AGS like `ags:NNNNNNNNNNN`).
    pub fn metadata_author(mut self, id: impl Into<String>) -> Self {
        self.metadata_author = Some(id.into());
        self
    }

    /// Sets the XTA MessageMetaData reader identifier.
    pub fn metadata_reader(mut self, id: impl Into<String>) -> Self {
        self.metadata_reader = Some(id.into());
        self
    }

    /// Sets the message subject.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Disable content signing. Bold move; OSCI lives on signatures.
    pub fn without_signature(mut self) -> Self {
        self.sign = false;
        self
    }

    /// Disable content encryption. The message travels as cleartext
    /// inside the (still signed) transport envelope.
    pub fn without_encryption(mut self) -> Self {
        self.encrypt = false;
        self
    }

    /// Sends the message and returns the intermediary's receipt.
    pub fn submit(self) -> Result<Receipt, Error> {
        let recipient = self.recipient.ok_or_else(|| {
            Error::Config("recipient (cipher certificate or DVDV entry) is required".into())
        })?;

        self.client.native.send_xta(crate::native::SendRequest {
            xta: &self.xta,
            attachments: &self.attachments,
            chunk_size_kb: self.chunk_size_kb,
            recipient_cipher_cert: &recipient.cipher_cert,
            subject: self.subject.as_deref(),
            metadata_author: self.metadata_author.as_deref(),
            metadata_reader: self.metadata_reader.as_deref(),
            sign: self.sign,
            encrypt: self.encrypt,
        })
    }
}

/// Resolves `--to dvdv:KEY[:CATEGORY]` through a directory into a fully
/// addressed send: intermediary + recipient, ready for the client builder.
pub fn resolve_dvdv<D: DvdvDirectory + ?Sized>(
    directory: &D,
    org_key: &str,
    category: Option<&str>,
) -> Result<(Intermediary, Recipient), Error> {
    let mut hits = directory.find(org_key, category)?;
    let entry = if hits.len() == 1 {
        hits.pop().ok_or_else(|| {
            Error::DvdvLookup(format!("org key {org_key}: entry vanished mid-resolution"))
        })?
    } else {
        return Err(Error::DvdvLookup(format!(
            "org key {org_key} is ambiguous: {} entries, ask for a category",
            hits.len()
        )));
    };
    crate::dvdv::validate_entry(&entry)?;
    let intermediary = Intermediary::new(
        entry.intermediary_url.clone(),
        entry.intermediary_cipher_cert.clone(),
    );
    Ok((intermediary, Recipient::from_dvdv_entry(&entry)))
}

/// Whether an intermediary URL points at the local machine — the same
/// machine this process runs on. Used to enforce fail-closed guards for
/// operations that are only safe against loopback peers (plain-transport
/// test mode; a REST server's exposure checks).
///
/// Recognizes: `localhost`, `::1`, bracketed IPv6 loopback, and
/// `127.0.0.0/8`. Strips userinfo first (`http://127.0.0.1:8080@evil.example`
/// must read as evil.example), then IPv6 brackets, then the port.
/// Everything ambiguous fails closed.
pub fn url_host_is_loopback(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let mut host_port = after_scheme.split(['/']).next().unwrap_or(after_scheme);
    // Userinfo (RFC 3986) precedes the host and may itself contain ':' and
    // dots — strip it before host parsing, or "127.0.0.1:8080@evil.example"
    // passes as loopback while the transport connects to evil.example.
    if let Some((_, rest)) = host_port.rsplit_once('@') {
        host_port = rest;
    }
    // IPv6 forms come bracketed; the port (if any) follows the bracket.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port)
    };
    if host.eq_ignore_ascii_case("localhost") || host.eq_ignore_ascii_case("::1") {
        return true;
    }
    // 127.0.0.0/8: four numeric labels, first one 127 — and nothing bolted
    // on afterwards ("127.0.0.1.evil.example" need not apply).
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() == 4
        && labels[0] == "127"
        && labels[1..]
            .iter()
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}


/// DER bytes as a single-line-label PEM document (the wire format the
/// TLS stack expects for client keys and anchors).
fn pem_wrap(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}


#[cfg(test)]
mod loopback_tests {
    use super::url_host_is_loopback;

    #[test]
    fn loopback_urls_are_recognized_in_all_their_forms() {
        for url in [
            "http://127.0.0.1:39471/entry",
            "http://localhost:8080/x",
            "http://localhost/x",
            "https://127.42.0.1:1/",
            "http://[::1]:9000/entry",
            "http://[::1]/",
            // Userinfo in front of a genuinely loopback host: the userinfo
            // is decoration, the host is what the transport connects to.
            "http://user:geheim@127.0.0.1:8080/x",
            "http://dienstlich@[::1]:9000/entry",
        ] {
            assert!(url_host_is_loopback(url), "{url} should be loopback");
        }
    }

    #[test]
    fn everything_else_is_not_loopback() {
        for url in [
            "http://gov.test.osci.de/osci-manager-entry/externalentry",
            "https://intermediary.example/entry",
            "http://10.0.0.1:1/",             // private, but not loopback
            "http://192.168.1.10/entry",      // same
            "http://127.0.0.1.evil.example/", // loopback as a subdomain — nice try
            // Loopback as *userinfo*: the guard must read the same host the
            // transport connects to.
            "http://127.0.0.1:8080@evil.example/entry",
            "http://[::1]@evil.example/entry",
            "http://user:geheim@10.1.2.3/x",
        ] {
            assert!(
                !url_host_is_loopback(url),
                "{url} must not pass as loopback"
            );
        }
    }
}
