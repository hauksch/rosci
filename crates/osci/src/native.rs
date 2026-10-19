//! The native OSCI client: the Java bridge's ops, reimplemented on the
//! oscirs stack (`Dialog`, compose, security, transport) — no JVM, no
//! sidecar, no line protocol.
//!
//! One oscirs `Dialog` per operation, mirroring the Java bridge's
//! lifecycle: the send flow opens the dialog with `GetMessageId`, the
//! fetch and process-card flows with `InitDialog`, and every operation
//! drops its dialog when done — oscirs's dialog is local state, the
//! intermediary's partial timeout cleans up what a mid-flow error leaves.
//!
//! Feedback classification follows the Java bridge exactly: codes with a
//! leading `0` are receipts, `3800` ("more messages pending") is the one
//! tolerated warning, everything else is a rejection.

use std::sync::{Arc, Mutex};

use osci_core::helper::base64;
use osci_core::message::compose::{OutCertEntry, OutContent, OutContentContainer, OutMessage};
use osci_core::message::{MessageType, OsciMessage};
use osci_core::soap::{CertRole, CertUse};
use osci_transport::http::{HttpTransport, HttpTransportConfig};
use osci_transport::{Transport, TransportError};

use osci_rs as oci;

use oci::dialog::Dialog;
use oci::security::{decrypt_encrypted_data, verify_message, EncRecipient, EncryptConfig};
use oci::{Certificate, CryptoError};

use crate::config::{Identity, Intermediary};
use crate::error::Error;
use crate::p12::{P12Decrypter, P12Keypair, P12Signer};
use crate::protocol::{FetchedContent, FetchedMessage, ProcessCard, Receipt, VersionInfo};
use crate::xta::Xta;

/// The oscirs facade crate (dialogs, security, prelude types).
/// Feedback codes the Java bridge tolerated: receipts (`0xxx`) and the
/// spec's §6.6.10 "more messages pending" indicator.
fn feedback_is_acceptable(code: &str) -> bool {
    code.starts_with('0') || code == "3800"
}

/// Escape text destined for a raw-XML slot (`entry_inner`).
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Handle on the last raw transport response.
type ResponseCapture = Arc<Mutex<Vec<u8>>>;

/// Transport wrapper that keeps the last raw response around — fetch-side
/// decryption needs the response XML, which `Dialog::send`'s return value
/// (the parsed message) does not carry.
struct CapturingTransport {
    inner: HttpTransport,
    last_response: Arc<Mutex<Vec<u8>>>,
}

impl Transport for CapturingTransport {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let response = self.inner.send(message)?;
        *self
            .last_response
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = response.clone();
        Ok(response)
    }
}

/// A ready-to-use native OSCI client.
///
/// Cheap to clone — the heavyweight parts are the parsed keystores, held
/// in `Arc`s; dialogs and HTTP agents are built per operation.
#[derive(Clone)]
pub struct NativeClient {
    intermediary: Intermediary,
    signer_keypair: Arc<P12Keypair>,
    decrypter_keypair: Arc<P12Keypair>,
    /// Response timeout, also the HTTP transport's global timeout.
    timeout_ms: u64,
    /// Test mode: skip transport-level encryption toward the intermediary.
    insecure_transport: bool,
}

impl std::fmt::Debug for NativeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClient")
            .field("intermediary_url", &self.intermediary.url)
            .field("insecure_transport", &self.insecure_transport)
            .finish_non_exhaustive()
    }
}

impl NativeClient {
    /// Builds from the client config surface: intermediary (url + cipher
    /// certificate) and a PKCS#12 identity (signer, optionally a separate
    /// decrypter bundle).
    pub fn new(
        intermediary: Intermediary,
        identity: &Identity,
        response_timeout: std::time::Duration,
        insecure_transport: bool,
    ) -> Result<Self, Error> {
        let msg = identity.to_msg();
        let signer_b64 = msg
            .signer_p12
            .as_deref()
            .ok_or_else(|| Error::Config("identity carries no signer PKCS#12".into()))?;
        let signer_p12 = base64::decode(signer_b64)
            .map_err(|e| Error::Config(format!("signer PKCS#12 base64: {e}")))?;
        let signer_pin = msg.signer_pin.as_ref().map(|p| p.as_str()).unwrap_or("");
        let decrypter_p12 = match &msg.decrypter_p12 {
            Some(p12) => base64::decode(p12)
                .map_err(|e| Error::Config(format!("decrypter PKCS#12 base64: {e}")))?,
            None => signer_p12.clone(),
        };
        let decrypter_pin = match (&msg.decrypter_pin, &msg.signer_pin) {
            (Some(pin), _) => pin.as_str(),
            (None, Some(pin)) => pin.as_str(),
            (None, None) => "",
        };

        Ok(Self {
            intermediary,
            signer_keypair: Arc::new(P12Keypair::parse(&signer_p12, signer_pin)?),
            decrypter_keypair: Arc::new(P12Keypair::parse(&decrypter_p12, decrypter_pin)?),
            timeout_ms: u64::try_from(response_timeout.as_millis()).unwrap_or(u64::MAX),
            insecure_transport,
        })
    }

    /// Version handshake — local, no dialog needed. `protocol` stays the
    /// wire version the bridge protocol used, so consumers can keep
    /// asserting on it.
    pub fn versions(&self) -> VersionInfo {
        VersionInfo::from([
            (
                "protocol".to_string(),
                crate::protocol::PROTOCOL_VERSION.to_string(),
            ),
            ("bridge".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ("library".to_string(), "oscirs 3fb9258 (native)".to_string()),
            ("provider".to_string(), "RustCrypto".to_string()),
        ])
    }

    /// Sends an XTA payload (plus optional additional parts) as a
    /// StoreDelivery and returns the intermediary's receipt.
    pub fn send_xta(
        &self,
        xta: &Xta,
        attachments: &[Xta],
        recipient_cipher_cert: &str,
        subject: Option<&str>,
        _sign: bool,
        encrypt: bool,
    ) -> Result<Receipt, Error> {
        let recipient = parse_certificate(recipient_cipher_cert)?;
        let (mut dialog, capture) = self.dialog()?;

        // Round 1: reserve a message id — the intermediary hands them out
        // like queue numbers at the Amt, and nobody may skip the line.
        let mut get_id = self.base_message(MessageType::GetMessageId, None);
        let rsp = dialog
            .send(&mut get_id, &[], &boundary())
            .map_err(native_error)?;
        check_feedback(&rsp)?;
        let message_id = rsp
            .request
            .and_then(|r| r.message_id)
            .ok_or_else(|| Error::BridgeProtocol("GetMessageId response carried no id".into()))?;

        // Round 2: the store delivery itself.
        let mut store = self.base_message(MessageType::StoreDelivery, Some(&recipient));
        let escaped_subject = subject.map(xml_escape).unwrap_or_default();
        store.entry_inner = Some(format!(
            "<osci:MessageId>{message_id}</osci:MessageId><osci:Subject>{escaped_subject}</osci:Subject>"
        ));

        // Content + additional parts inline in one container. Inline base64
        // is exactly what rides inside the encrypted blob, and keeping the
        // parts in the container keeps them encrypted too.
        let mut container = OutContentContainer {
            id: "contentcontainer".to_string(),
            contents: Vec::new(),
        };
        container
            .contents
            .push(inline_content("content1", &xta.data));
        for (n, att) in attachments.iter().enumerate() {
            container
                .contents
                .push(inline_content(&format!("attachment-{}", n + 1), &att.data));
        }

        let boundary = boundary();
        let response = if encrypt {
            let recipients = vec![EncRecipient {
                cert: recipient,
                cert_element_id: "addressee_cipher".to_string(),
            }];
            dialog
                .send_encrypted(
                    &mut store,
                    oci::dialog::ContentEncryption {
                        inner: container,
                        recipients: &recipients,
                        config: EncryptConfig::default(),
                    },
                    &[],
                    &boundary,
                )
                .map_err(native_error)?
        } else {
            store.containers.push(container);
            dialog
                .send(&mut store, &[], &boundary)
                .map_err(native_error)?
        };
        check_feedback(&response)?;

        // The StoreDelivery response echoes the message id (Java reads the
        // id from the response, not from our reservation) and its
        // signature presence decides `response_signed`.
        let message_id = response
            .request
            .as_ref()
            .and_then(|r| r.message_id.clone())
            .unwrap_or(message_id);
        let signed = String::from_utf8_lossy(&capture.lock().unwrap_or_else(|p| p.into_inner()))
            .contains("osci:ClientSignature");

        Ok(Receipt {
            message_id,
            response_signed: Some(signed),
            feedback: Some(feedback_rows(&response)),
        })
    }

    /// Fetches messages from our postbox — plain containers and encrypted
    /// content both, the latter decrypted with our identity. Returns the
    /// messages plus the raw feedback rows.
    pub fn fetch(
        &self,
        selection_rule: Option<&str>,
    ) -> Result<(Vec<FetchedMessage>, Vec<Vec<String>>), Error> {
        let (mut dialog, capture) = self.dialog()?;
        let mut init = self.base_message(MessageType::InitDialog, None);
        dialog
            .send(&mut init, &[], &boundary())
            .map_err(native_error)?;

        let mut fetch = self.base_message(MessageType::FetchDelivery, None);
        if let Some(rule) = selection_rule {
            fetch.selection_rule = Some(rule.to_string());
        }
        let response = dialog
            .send(&mut fetch, &[], &boundary())
            .map_err(native_error)?;
        check_feedback(&response)?;

        let xml = capture.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let stored = oci::StoredMessage::load(&xml)
            .map_err(|e| Error::BridgeProtocol(format!("fetch response unparseable: {e}")))?;
        let body = response.body.clone().unwrap_or_default();

        let mut messages = Vec::new();
        for container in &body.containers {
            messages.push(map_plain_container(container, &stored.attachments));
        }

        let decrypter = P12Decrypter::new((*self.decrypter_keypair).clone());
        let xml_text = String::from_utf8_lossy(&stored.xml).into_owned();
        for _ in &body.encrypted_data {
            let mut message = FetchedMessage::default();
            match decrypt_encrypted_data(&xml_text, 0, &[&decrypter]) {
                Ok(content) => {
                    message.signatures_valid = Some(verify_quietly(&content.plaintext));
                    message.encrypted_contents = Some(vec![FetchedContent {
                        filename: None,
                        content_type: None,
                        data: base64::encode(&content.plaintext),
                        container: Some("encrypted".into()),
                    }]);
                }
                Err(e) => {
                    message.subject =
                        Some(format!("<not decryptable with the supplied identity: {e}>"));
                }
            }
            messages.push(message);
        }

        Ok((messages, feedback_rows(&response)))
    }

    /// Fetches the Laufzettel (process card) for a message we sent.
    pub fn process_card(&self, message_id: &str) -> Result<Vec<ProcessCard>, Error> {
        let (mut dialog, _capture) = self.dialog()?;
        let mut init = self.base_message(MessageType::InitDialog, None);
        dialog
            .send(&mut init, &[], &boundary())
            .map_err(native_error)?;

        let mut card = self.base_message(MessageType::FetchProcessCard, None);
        card.selection_rule = Some(message_id.to_string());
        let response = dialog
            .send(&mut card, &[], &boundary())
            .map_err(native_error)?;
        check_feedback(&response)?;

        let mut cards = Vec::new();
        for bundle in &response.process_card_bundles {
            for pc in &bundle.process_cards {
                cards.push(ProcessCard {
                    message_id: bundle.message_id.clone(),
                    subject: pc.subject.clone(),
                    creation: pc.creation.as_ref().map(oci::format_iso8601),
                    forwarding: pc.forwarding.as_ref().map(oci::format_iso8601),
                    reception: pc.reception.as_ref().map(oci::format_iso8601),
                    inspections: Some(
                        bundle
                            .inspections
                            .iter()
                            .map(|i| crate::protocol::Inspection {
                                subject: i.x509_subject_name.clone(),
                                issuer: i.x509_issuer_name.clone(),
                                serial_number: i.x509_serial_number.clone(),
                                online_checked: i.online_result.as_deref().map(|r| !r.is_empty()),
                                timestamp: i.timestamp.clone(),
                            })
                            .collect(),
                    ),
                });
            }
        }
        Ok(cards)
    }

    // ------------------------------------------------------------ internals

    /// A fresh dialog over a fresh transport, with the transport signature
    /// wired to our signer — and transport encryption to the intermediary
    /// unless test mode turned it off. The capture handle hands back the
    /// last raw response.
    fn dialog(&self) -> Result<(Dialog, ResponseCapture), Error> {
        let transport = HttpTransport::new(HttpTransportConfig {
            endpoint: self.intermediary.url.clone(),
            timeout_ms: self.timeout_ms,
            ..Default::default()
        })
        .map_err(|e| Error::Bridge {
            kind: crate::error::BridgeErrorKind::Transport,
            message: e.0,
            feedback: Vec::new(),
        })?;
        let capture = Arc::new(Mutex::new(Vec::new()));
        let capturing = CapturingTransport {
            inner: transport,
            last_response: capture.clone(),
        };
        let signer = P12Signer::new((*self.signer_keypair).clone(), None);
        let mut dialog = Dialog::new(Box::new(capturing))
            .with_signer(Box::new(signer), "originator_signature".to_string());
        if !self.insecure_transport {
            dialog = dialog.with_transport_encryption(
                parse_certificate(&self.intermediary.cipher_cert)?,
                EncryptConfig::default(),
            );
        }
        Ok((dialog, capture))
    }

    /// The shared outbound skeleton: languages, our certificates.
    fn base_message(&self, kind: MessageType, addressee: Option<&Certificate>) -> OutMessage {
        let mut entries = vec![
            cert_entry(
                CertRole::Originator,
                CertUse::Signature,
                "originator_signature",
                self.signer_keypair.certificate().der(),
            ),
            cert_entry(
                CertRole::Originator,
                CertUse::Cipher,
                "originator_cipher",
                self.decrypter_keypair.certificate().der(),
            ),
        ];
        if let Some(cert) = addressee {
            entries.push(cert_entry(
                CertRole::Addressee,
                CertUse::Cipher,
                "addressee_cipher",
                cert.der(),
            ));
        }
        OutMessage {
            kind: Some(kind),
            desired_languages: Some("de".into()),
            non_intermediary_certificates: entries,
            ..Default::default()
        }
    }
}

/// One inline content unit: the payload as base64 text.
fn inline_content(id: &str, data: &[u8]) -> OutContent {
    OutContent {
        id: id.to_string(),
        text: Some(base64::encode(data)),
        href: None,
    }
}

fn cert_entry(role: CertRole, use_: CertUse, id: &str, der: &[u8]) -> OutCertEntry {
    OutCertEntry {
        role,
        use_,
        id: id.to_string(),
        der: der.to_vec(),
    }
}

/// Response feedback into protocol rows (`[text, code]`, the wire order
/// the Java bridge used).
fn feedback_rows(message: &OsciMessage) -> Vec<Vec<String>> {
    message
        .feedback
        .iter()
        .map(|f| vec![f.text.clone(), f.code.clone()])
        .collect()
}

/// Java-bridge feedback classification: receipts pass, 3800 passes,
/// everything else is a rejection carrying all rows as evidence.
fn check_feedback(message: &OsciMessage) -> Result<(), Error> {
    for row in &message.feedback {
        if !feedback_is_acceptable(&row.code) {
            return Err(Error::Bridge {
                kind: crate::error::BridgeErrorKind::Osci,
                message: format!(
                    "intermediary rejected the request: {} {}",
                    row.code, row.text
                ),
                feedback: feedback_rows(message),
            });
        }
    }
    Ok(())
}

/// Best-effort signature verdict for a standalone container XML.
fn verify_quietly(xml: &[u8]) -> bool {
    verify_message(&String::from_utf8_lossy(xml), &[])
        .map(|report| report.all_valid())
        .unwrap_or(false)
}

/// Maps a plain fetched container (with its MIME attachments) into a
/// protocol message row.
fn map_plain_container(
    container: &osci_core::message::ContentContainer,
    attachments: &[osci_core::message::stored::LoadedAttachment],
) -> FetchedMessage {
    let mut message = FetchedMessage {
        signatures_valid: Some(container.signed),
        ..Default::default()
    };
    let mut contents = Vec::new();
    for content in &container.contents {
        if let Some(b64) = &content.base64_content {
            contents.push(FetchedContent {
                filename: None,
                content_type: None,
                data: b64.clone(),
                container: Some("plain".into()),
            });
        } else if let Some(href) = &content.href {
            let cid = href.trim_start_matches("cid:");
            if let Some(att) = attachments
                .iter()
                .find(|a| a.content_id == cid || format!("<{}>", a.content_id) == cid)
            {
                contents.push(FetchedContent {
                    filename: None,
                    content_type: Some(att.content_type.clone()),
                    data: base64::encode(&att.data),
                    container: Some("plain".into()),
                });
            }
        }
    }
    message.contents = Some(contents);
    message
}

fn native_error(e: oci::dialog::DialogError) -> Error {
    let (kind, message, feedback) = match &e {
        oci::dialog::DialogError::ErrorFeedback { code, text } => (
            crate::error::BridgeErrorKind::Osci,
            format!("intermediary rejected the request: {code} {text}"),
            vec![vec![text.clone(), code.clone()]],
        ),
        oci::dialog::DialogError::Transport(_) => (
            crate::error::BridgeErrorKind::Transport,
            e.to_string(),
            Vec::new(),
        ),
        _ => (
            crate::error::BridgeErrorKind::Osci,
            e.to_string(),
            Vec::new(),
        ),
    };
    Error::Bridge {
        kind,
        message,
        feedback,
    }
}

fn parse_certificate(pem_or_b64: &str) -> Result<Certificate, Error> {
    let der = certificate_der(pem_or_b64)
        .ok_or_else(|| Error::Config("certificate: neither PEM nor base64 DER".into()))?;
    Certificate::from_der(&der).map_err(|e: CryptoError| Error::Config(format!("certificate: {e}")))
}

/// Extracts the DER bytes from a PEM block or a bare base64 blob.
fn certificate_der(input: &str) -> Option<Vec<u8>> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let b64: String = if let Some(start) = input.find(begin) {
        let after = &input[start + begin.len()..];
        let stop = after.find(end)?;
        after[..stop].to_string()
    } else {
        input.to_string()
    };
    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    base64::decode(&clean).ok()
}

/// Fresh MIME boundary; composed parts are base64/inline XML so collisions
/// are nigh-impossible already, but randomness is cheaper than confidence.
fn boundary() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("rosci={}", base64::encode(&bytes))
}
