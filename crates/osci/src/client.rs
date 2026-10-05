//! The public client: build once, send many, sleep well.

use std::path::Path;

use crate::bridge::{BridgeConfig, BridgeHandle};
use crate::config::{Identity, Intermediary, Tls};
use crate::dvdv::{DvdvDirectory, DvdvEntry};
use crate::error::Error;
use crate::protocol::{FetchedMessage, ProcessCard, Receipt, Request, VersionInfo};
use crate::xta::Xta;

/// A ready-to-use OSCI client backed by a live bridge process.
///
/// Built via [`OsciClient::builder`]. Dropping the client shuts the bridge
/// down politely (then impolitely, if the JVM insists).
pub struct OsciClient {
    bridge: BridgeHandle,
    intermediary: Intermediary,
    identity: Identity,
    tls: Tls,
    insecure_transport: bool,
}

impl std::fmt::Debug for OsciClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bridge handle owns OS resources and a live thread — we print
        // the identity-free facts and call it a day.
        f.debug_struct("OsciClient")
            .field("intermediary_url", &self.intermediary.url)
            .field("tls_configured", &self.tls.client_p12_b64.is_some())
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

    /// Version handshake: bridge, JVM, OSCI library, BouncyCastle.
    pub fn versions(&mut self) -> Result<VersionInfo, Error> {
        let rsp = self.bridge.call(base_request("ping"))?;
        let result = rsp.result.unwrap_or_default();
        Ok(result.versions.unwrap_or_default())
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
    /// were stored chunked. A smaller-than-chunk message arrives as a
    /// plain response.
    pub fn fetch_with(
        &mut self,
        query: FetchQuery,
        chunk_size_kb: Option<u64>,
    ) -> Result<Vec<FetchedMessage>, Error> {
        let (mode, rule) = match &query {
            FetchQuery::ByMessageId(id) => ("BY_MESSAGE_ID", Some(id.clone())),
            FetchQuery::All => ("ALL", None),
        };
        let mut req = self.dialog_request("fetch");
        req.chunk_size_kb = chunk_size_kb;
        req.selection_mode = Some(mode.to_string());
        req.selection_rule = rule;
        let rsp = self.bridge.call(req)?;
        let result = rsp.result.unwrap_or_default();
        Ok(result.messages.unwrap_or_default())
    }

    /// Fetches the Laufzettel (process card) for a message we sent.
    pub fn process_card(&mut self, message_id: &str) -> Result<Vec<ProcessCard>, Error> {
        let mut req = self.dialog_request("process-card");
        req.selection_mode = Some("BY_MESSAGE_ID".to_string());
        req.selection_rule = Some(message_id.to_string());
        let rsp = self.bridge.call(req)?;
        let result = rsp.result.unwrap_or_default();
        Ok(result.process_cards.unwrap_or_default())
    }

    /// End-of-life convenience: shuts the bridge down and swallows the
    /// error — at this point the work either succeeded or the real error
    /// was already reported. The one shutdown dance, in one place.
    pub fn finish(&mut self) {
        self.shutdown().ok();
    }

    /// Tells the bridge to exit and waits for it.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        // Bounded politeness-then-hammer, mirroring Drop: an explicit
        // shutdown must never hang where a drop would not.
        self.bridge.shutdown_and_wait().map(|_| ())
    }

    fn dialog_request(&self, op: &'static str) -> Request {
        let mut req = base_request(op);
        req.intermediary = Some(self.intermediary.to_msg());
        req.identity = Some(self.identity.to_msg());
        req.tls = Some(self.tls.to_msg());
        if self.insecure_transport {
            req.insecure_transport = Some(false);
        }
        req
    }
}

/// Builder for [`OsciClient`]. All knobs optional except the ones that
/// aren't (intermediary + identity), because OSCI without certificates is
/// just an expensive way to shout into the void.
#[derive(Debug, Clone)]
pub struct OsciClientBuilder {
    bridge: BridgeConfig,
    intermediary: Option<Intermediary>,
    identity: Option<Identity>,
    tls: Tls,
    insecure_transport: bool,
}

impl Default for OsciClientBuilder {
    fn default() -> Self {
        Self {
            bridge: BridgeConfig::java_jar(default_jar_path()),
            intermediary: None,
            identity: None,
            tls: Tls::default(),
            insecure_transport: false,
        }
    }
}

impl OsciClientBuilder {
    /// Launch command override (default `java -jar <jar>`), tests plug
    /// fakes in here.
    pub fn bridge_config(mut self, cfg: BridgeConfig) -> Self {
        self.bridge = cfg;
        self
    }

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

    /// Spawns the bridge and performs the `ping` handshake. Fails loudly
    /// and early, the way incidents reports wish they could.
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

        let mut bridge = BridgeHandle::spawn(&self.bridge)?;
        let rsp = bridge.call(base_request("ping"))?;
        let versions = rsp.result.and_then(|r| r.versions).ok_or_else(|| {
            Error::BridgeProtocol("bridge ping response carried no versions".into())
        })?;
        match versions.get("protocol").map(String::as_str) {
            Some(v) if v == crate::protocol::PROTOCOL_VERSION => {}
            Some(v) => {
                return Err(Error::BridgeProtocol(format!(
                    "bridge speaks protocol {v}, this library speaks {} — \
                     the wire format is versioned, mixing versions is not supported",
                    crate::protocol::PROTOCOL_VERSION
                )))
            }
            None => {
                return Err(Error::BridgeProtocol(
                    "bridge ping response carries no protocol version".into(),
                ))
            }
        }

        Ok(OsciClient {
            bridge,
            intermediary,
            identity,
            tls: self.tls,
            insecure_transport: self.insecure_transport,
        })
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
    /// (spec „Effiziente Übertragung großer Datenmengen"). Opt-in: the
    /// fully built StoreDelivery is serialized, split and shipped as a
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
    pub fn submit(mut self) -> Result<Receipt, Error> {
        let recipient = self.recipient.take().ok_or_else(|| {
            Error::Config("recipient (cipher certificate or DVDV entry) is required".into())
        })?;

        let mut req = self.client.dialog_request("send");
        req.recipient = Some(crate::protocol::Party {
            url: None,
            cipher_cert: Some(recipient.cipher_cert.clone()),
            signature_cert: recipient.signature_cert.clone(),
        });
        req.subject = self.subject.clone();
        req.content = Some(self.xta.to_payload());
        req.attachments = if self.attachments.is_empty() {
            None
        } else {
            Some(self.attachments.iter().map(|a| a.to_payload()).collect())
        };
        req.chunk_size_kb = self.chunk_size_kb;
        req.metadata_author = self.metadata_author.clone();
        req.metadata_reader = self.metadata_reader.clone();
        req.sign = Some(self.sign);
        req.encrypt = Some(self.encrypt);

        let rsp = self.client.bridge.call(req)?;
        let result = rsp.result.unwrap_or_default();
        let message_id = result.message_id.ok_or_else(|| {
            Error::BridgeProtocol("send succeeded but carried no message id".into())
        })?;
        Ok(Receipt {
            message_id,
            response_signed: result.response_signed,
            feedback: result.feedback,
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

fn base_request(op: &'static str) -> Request {
    Request {
        id: String::new(),
        op,
        intermediary: None,
        identity: None,
        recipient: None,
        subject: None,
        content: None,
        attachments: None,
        chunk_size_kb: None,
        metadata_author: None,
        metadata_reader: None,
        sign: None,
        encrypt: None,
        insecure_transport: None,
        tls: None,
        selection_mode: None,
        selection_rule: None,
    }
}

/// Where the jar lives by default: `OSCI_BRIDGE_JAR` wins, then the
/// release layout next to the running binary (`../lib/osci-bridge.jar`,
/// see `make release`), then a cwd-relative `osci-bridge.jar`.
pub fn default_jar_path() -> std::path::PathBuf {
    let env = std::env::var_os("OSCI_BRIDGE_JAR");
    let exe = std::env::current_exe().ok();
    resolve_jar_path(env.as_deref(), exe.as_deref())
}

/// Pure core of [`default_jar_path`]: env override wins, then the
/// exe-relative release layout, then a cwd-relative fallback.
fn resolve_jar_path(
    env: Option<&std::ffi::OsStr>,
    exe: Option<&std::path::Path>,
) -> std::path::PathBuf {
    if let Some(env) = env {
        return std::path::PathBuf::from(env);
    }
    let release = exe
        .and_then(|e| e.parent())
        .map(|dir| dir.join("../lib/osci-bridge.jar"))
        .filter(|p| p.is_file());
    if let Some(jar) = release {
        return jar;
    }
    std::path::PathBuf::from("osci-bridge.jar")
}

#[cfg(test)]
mod tests {
    use super::resolve_jar_path;
    use std::path::Path;

    #[test]
    fn env_override_wins_over_everything() {
        let p = resolve_jar_path(
            Some("/custom/bridge.jar".as_ref()),
            Some(Path::new("/opt/dist/bin/rosci")),
        );
        assert_eq!(p, Path::new("/custom/bridge.jar"));
    }

    #[test]
    fn release_layout_is_found_next_to_the_binary() {
        // dist/bin/rosci -> dist/lib/osci-bridge.jar
        let dist = tempfile::tempdir().unwrap();
        let bin = dist.path().join("bin");
        std::fs::create_dir_all(bin.join("../lib")).unwrap();
        std::fs::write(bin.join("../lib/osci-bridge.jar"), b"jar").unwrap();
        let p = resolve_jar_path(None, Some(&bin.join("rosci")));
        assert_eq!(p, bin.join("../lib/osci-bridge.jar"));
    }

    #[test]
    fn falls_back_to_cwd_relative_when_layout_is_absent() {
        let p = resolve_jar_path(None, Some(Path::new("/nowhere/bin/rosci")));
        assert_eq!(p, Path::new("osci-bridge.jar"));
    }
}
