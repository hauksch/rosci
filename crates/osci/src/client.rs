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
}

impl std::fmt::Debug for OsciClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bridge handle owns OS resources and a live thread — we print
        // the identity-free facts and call it a day.
        f.debug_struct("OsciClient")
            .field("intermediary_url", &self.intermediary.url)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

/// How to select messages when fetching.
#[derive(Debug, Clone)]
pub enum FetchQuery {
    ByMessageId(String),
    All,
}

impl OsciClient {
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
            recipient: None,
            subject: None,
            sign: true,
            encrypt: true,
        }
    }

    /// Fetches messages from our postbox.
    pub fn fetch(&mut self, query: FetchQuery) -> Result<Vec<FetchedMessage>, Error> {
        let (mode, rule) = match &query {
            FetchQuery::ByMessageId(id) => ("BY_MESSAGE_ID", Some(id.clone())),
            FetchQuery::All => ("ALL", None),
        };
        let mut req = self.dialog_request("fetch");
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

    /// Tells the bridge to exit and waits for it.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.bridge.shutdown();
        self.bridge.wait()?;
        Ok(())
    }

    fn dialog_request(&self, op: &'static str) -> Request {
        let mut req = base_request(op);
        req.intermediary = Some(self.intermediary.to_msg());
        req.identity = Some(self.identity.to_msg());
        req.tls = Some(self.tls.to_msg());
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
}

impl Default for OsciClientBuilder {
    fn default() -> Self {
        Self {
            bridge: BridgeConfig::java_jar(default_jar_path()),
            intermediary: None,
            identity: None,
            tls: Tls::default(),
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

    /// Spawns the bridge and performs the `ping` handshake. Fails loudly
    /// and early, the way incidents reports wish they could.
    pub fn build(self) -> Result<OsciClient, Error> {
        let intermediary = self
            .intermediary
            .filter(|i| !i.url.is_empty() && !i.cipher_cert.is_empty())
            .ok_or_else(|| {
                Error::Config(
                    "intermediary (url + cipher certificate) is required".to_string(),
                )
            })?;
        let identity = self
            .identity
            .ok_or_else(|| Error::Config("identity (signer PKCS#12) is required".to_string()))?;

        let mut bridge = BridgeHandle::spawn(&self.bridge)?;
        let rsp = bridge.call(base_request("ping"))?;
        if rsp.result.and_then(|r| r.versions).is_none() {
            return Err(Error::BridgeProtocol(
                "bridge ping response carried no versions".into(),
            ));
        }

        Ok(OsciClient {
            bridge,
            intermediary,
            identity,
            tls: self.tls,
        })
    }
}

/// A recipient, addressed the only way OSCI truly respects: a cipher
/// certificate. (`DVDV entries resolve into one of these.)
#[derive(Debug, Clone)]
pub struct Recipient {
    pub cipher_cert: String,
    pub signature_cert: Option<String>,
}

impl Recipient {
    pub fn from_cipher_cert_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let pem = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!("cannot read recipient certificate {}: {e}", path.display()))
        })?;
        Ok(Self {
            cipher_cert: pem,
            signature_cert: None,
        })
    }

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
    recipient: Option<Recipient>,
    subject: Option<String>,
    sign: bool,
    encrypt: bool,
}

impl SendBuilder<'_> {
    pub fn recipient(mut self, recipient: Recipient) -> Self {
        self.recipient = Some(recipient);
        self
    }

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
        req.sign = Some(self.sign);
        req.encrypt = Some(self.encrypt);

        let rsp = self.client.bridge.call(req)?;
        let result = rsp.result.unwrap_or_default();
        let message_id = result.message_id.ok_or_else(|| {
            Error::BridgeProtocol("send succeeded but carried no message id".into())
        })?;
        Ok(Receipt {
            message_id,
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
        hits.pop().expect("len checked")
    } else {
        return Err(Error::DvdvLookup(format!(
            "org key {org_key} is ambiguous: {} entries, ask for a category",
            hits.len()
        )));
    };
    crate::dvdv::validate_entry(&entry)?;
    let intermediary = Intermediary::new(entry.intermediary_url.clone(), entry.intermediary_cipher_cert.clone());
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
        sign: None,
        encrypt: None,
        tls: None,
        selection_mode: None,
        selection_rule: None,
    }
}

/// Where the release layout puts the jar, relative to the binary:
/// `../lib/osci-bridge.jar` (see `make release`). Overridable via
/// `OSCI_BRIDGE_JAR`, because environments are a fact of life.
fn default_jar_path() -> std::path::PathBuf {
    std::env::var_os("OSCI_BRIDGE_JAR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("osci-bridge.jar"))
}
