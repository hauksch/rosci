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
use osci_core::message::compose::{
    OutAttachment, OutCertEntry, OutContent, OutContentContainer, OutMessage,
};
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

/// Pulls the text of the first `<osci:MessageId>` element out of the raw
/// response — the fallback for response shapes oscirs's typed parser does
/// not surface as `request` fields.
fn extract_message_id_raw(xml: &[u8]) -> Option<String> {
    let start = find_bytes(xml, b"<osci:MessageId>")? + b"<osci:MessageId>".len();
    let rest = &xml[start..];
    let close = find_bytes(rest, b"</osci:MessageId>")?;
    Some(String::from_utf8_lossy(&rest[..close]).into_owned())
}

/// Message ids travel base64-encoded on the wire (`osci:MessageId`);
/// consumers quote the decoded form, exactly what the Java library's
/// `getMessageId()` returned. Undecodable ids pass through unchanged —
/// we print what the intermediary said, not what we hoped it said.
fn decode_message_id(raw: String) -> String {
    match base64::decode(&raw) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or(raw),
        Err(_) => raw,
    }
}

/// Escape text destined for a raw-XML slot (`entry_inner`).
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Handle on the last raw transport response.
type ResponseCapture = Arc<Mutex<Vec<u8>>>;

/// Normalizes wire base64 (the writer emits MIME-wrapped 76-char lines)
/// into the standard single-line form the DTO contract promises.
fn normalize_base64(data: &str) -> String {
    data.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Substring search that keeps needle lengths honest (two wire-shape bugs
/// here were exactly off-by-needle-length window searches).
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    find_bytes(haystack, needle).is_some()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Transport wrapper with two jobs: keep the last raw response around
/// (fetch-side decryption needs the response XML, which `Dialog::send`'s
/// return value does not carry), and peel transport-encrypted response
/// envelopes — in secure mode the intermediary encrypts its response back
/// to our cipher certificate, and the dialog machinery expects a plain
/// signed stream.
struct CapturingTransport {
    inner: HttpTransport,
    last_response: Arc<Mutex<Vec<u8>>>,
    /// Our decrypters, for unwrapping response envelopes.
    decrypters: Vec<Arc<P12Decrypter>>,
}

impl CapturingTransport {
    /// True when the stream is a transport envelope (SOAP body is one
    /// EncryptedData, no readable message entry) rather than a plain
    /// signed message.
    fn is_transport_envelope(xml: &[u8]) -> bool {
        !contains_bytes(xml, b"<soap:Header") && contains_bytes(xml, b"xenc:EncryptedData")
    }
}

impl Transport for CapturingTransport {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let response = self.inner.send(message)?;

        let plain = if Self::is_transport_envelope(&response) {
            let stored = oci::StoredMessage::load(&response)
                .map_err(|e| TransportError::new(format!("transport envelope unparseable: {e}")))?;
            let like = oci::security::StoredMessageLike {
                xml: &stored.xml,
                attachments: &stored.attachments,
            };
            let refs: Vec<&dyn oci::Decrypter> = self
                .decrypters
                .iter()
                .map(|arc| &**arc as &dyn oci::Decrypter)
                .collect();
            oci::security::decrypt_transport_message(&like, &refs)
                .map_err(|e| TransportError::new(format!("response transport decryption: {e}")))?
        } else {
            response.clone()
        };

        *self
            .last_response
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = plain.clone();
        Ok(plain)
    }
}

/// One send operation, fully addressed.
pub struct SendRequest<'a> {
    /// The main payload.
    pub xta: &'a Xta,
    /// Additional content parts riding in the same Zustellung.
    pub attachments: &'a [Xta],
    /// The recipient's cipher certificate (PEM or base64 DER).
    pub recipient_cipher_cert: &'a str,
    /// The message subject.
    pub subject: Option<&'a str>,
    /// XTA MessageMetaData author identifier (e.g. `ags:NNNNNNNNNNN`).
    pub metadata_author: Option<&'a str>,
    /// XTA MessageMetaData reader identifier.
    pub metadata_reader: Option<&'a str>,
    /// Content signing flag (transport signatures always ride).
    pub sign: bool,
    /// Content encryption flag.
    pub encrypt: bool,
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
        let (signer_p12, signer_pin) = identity.signer_material()?;
        let (decrypter_p12, decrypter_pin) = identity.decrypter_material()?;

        Ok(Self {
            intermediary,
            signer_keypair: Arc::new(P12Keypair::parse(&signer_p12, &signer_pin)?),
            decrypter_keypair: Arc::new(P12Keypair::parse(&decrypter_p12, &decrypter_pin)?),
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
            ("library".to_string(), "oscirs 9fa178f (native)".to_string()),
            ("provider".to_string(), "RustCrypto".to_string()),
        ])
    }

    /// Sends an XTA payload (plus optional additional parts) as a
    /// StoreDelivery and returns the intermediary's receipt. Binary
    /// payloads ride as MIME attachments (the Java bridge's shape); with
    /// `encrypt`, each attachment is session-key encrypted into the
    /// container (per-attachment key via MgmtData) before the container
    /// itself is encrypted.
    pub fn send_xta(&self, request: SendRequest<'_>) -> Result<Receipt, Error> {
        let recipient = parse_certificate(request.recipient_cipher_cert)?;
        let SendRequest {
            xta,
            attachments,
            recipient_cipher_cert: _,
            subject,
            metadata_author,
            metadata_reader,
            sign: _sign,
            encrypt,
        } = request;
        let (mut dialog, capture) = self.dialog()?;

        // Round 1: reserve a message id — the intermediary hands them out
        // like queue numbers at the Amt, and nobody may skip the line.
        let mut get_id = self.base_message(MessageType::GetMessageId, None);
        let rsp = dialog
            .send(&mut get_id, &[], &boundary())
            .map_err(native_error)?;
        check_feedback(&rsp)?;
        // The id rides in the response entry; oscirs only fills
        // `request` from a nested echoed request element, which real
        // ResponseToGetMessageId messages do not carry (the Java
        // reference writes the MessageId directly into the entry) — so
        // fall back to the raw response XML.
        let reserved = rsp
            .request
            .as_ref()
            .and_then(|r| r.message_id.clone())
            .or_else(|| extract_message_id_raw(&capture.lock().unwrap_or_else(|p| p.into_inner())))
            .ok_or_else(|| {
                if std::env::var_os("ROSCI_DEBUG").is_some() {
                    eprintln!(
                        "ROSCI_DEBUG: response bytes:\n{}",
                        String::from_utf8_lossy(&capture.lock().unwrap_or_else(|p| p.into_inner()))
                    );
                }
                Error::BridgeProtocol("GetMessageId response carried no id".into())
            })?;
        // the wire form stays base64 (MessageIdType is base64 binary);
        // only the receipt quotes the decoded form
        let message_id = decode_message_id(reserved.clone());

        // Round 2: the store delivery itself.
        let mut store = self.base_message(MessageType::StoreDelivery, Some(&recipient));
        let escaped_subject = subject.map(xml_escape).unwrap_or_default();
        store.entry_inner = Some(format!(
            "<osci:MessageId>{reserved}</osci:MessageId><osci:Subject>{escaped_subject}</osci:Subject>"
        ));

        // XTA MessageMetaData (Ergänzung): author/reader identification
        // plus message id and size. Only attached when at least one
        // identifier was configured — an empty custom header is ceremony
        // without content.
        if metadata_author.is_some() || metadata_reader.is_some() {
            let total_bytes =
                xta.data.len() + attachments.iter().map(|a| a.data.len()).sum::<usize>();
            store
                .custom_headers
                .push(osci_core::message::compose::OutCustomHeader {
                    id: "MessageMetaData".to_string(),
                    xml: mmd_fragment(metadata_author, metadata_reader, &message_id, total_bytes),
                });
        }

        // Content + additional parts as MIME attachments (the Java
        // bridge's shape): every part is referenced by cid:filename. With
        // encryption, each part is session-key encrypted first
        // (EncryptedData Attachment<refid> inside the container) and the
        // MIME part carries the ciphertext.
        let mut contents = Vec::new();
        contents.push(OutContent {
            id: "content1".to_string(),
            text: None,
            href: Some(format!("cid:{}", sanitize_content_id(&xta.filename))),
        });
        let mut parts: Vec<(String, String, Vec<u8>)> = vec![(
            sanitize_content_id(&xta.filename),
            "application/octet-stream".to_string(),
            xta.data.clone(),
        )];
        for att in attachments {
            let id = sanitize_content_id(&att.filename);
            contents.push(OutContent {
                id: format!("content-{}", id),
                text: None,
                href: Some(format!("cid:{id}")),
            });
            parts.push((id, "application/octet-stream".to_string(), att.data.clone()));
        }

        let cipher_uri = EncryptConfig::default().content_cipher;
        let (encrypted_attachments, part_bytes) = if encrypt {
            let plaintext_parts = parts
                .iter()
                .map(|(id, ct, data)| OutAttachment {
                    content_id: id.clone(),
                    content_type: ct.clone(),
                    base64_encoding: false,
                    data: data.clone(),
                })
                .collect::<Vec<_>>();
            let href_contents = contents.clone();
            let enc = osci_core::message::compose::encrypt_attachments(
                &href_contents,
                &plaintext_parts,
                &cipher_uri,
                None,
            )
            .map_err(|e| Error::Config(format!("attachment encryption: {e}")))?;
            let cipher_parts = parts
                .iter()
                .enumerate()
                .map(|(i, (id, ct, _))| (id.clone(), ct.clone(), enc[i].ciphertext.clone()))
                .collect::<Vec<_>>();
            (enc, cipher_parts)
        } else {
            (Vec::new(), parts.clone())
        };

        let container = OutContentContainer {
            id: "contentcontainer".to_string(),
            contents,
            encrypted_attachments,
        };

        // the bytes the transport signature's cid: references digest over
        // are the part bytes as they ride the wire
        let sign_attachments: Vec<(String, Vec<u8>)> = part_bytes
            .iter()
            .map(|(id, _, data)| (id.clone(), data.clone()))
            .collect();
        store.attachments = part_bytes
            .iter()
            .map(|(id, ct, data)| OutAttachment {
                content_id: id.clone(),
                content_type: ct.clone(),
                base64_encoding: false,
                data: data.clone(),
            })
            .collect();

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
                    &sign_attachments,
                    &boundary,
                )
                .map_err(native_error)?
        } else {
            store.containers.push(container);
            dialog
                .send(&mut store, &sign_attachments, &boundary)
                .map_err(native_error)?
        };
        check_feedback(&response)?;
        // oscirs's dialog verifies the response signature by policy
        // (VerifyIfPresent) and errors on tampering; the report's presence
        // is the "response was signed" fact for the receipt.
        let signed = dialog.last_response_report().is_some();

        // The StoreDelivery response echoes the message id (Java reads the
        // id from the response, not from our reservation).
        let message_id = response
            .request
            .as_ref()
            .and_then(|r| r.message_id.clone())
            .map(decode_message_id)
            .unwrap_or(message_id);

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
                    // The plaintext is either a ContentContainer XML (the
                    // Java dialect — extract its content rows) or the
                    // sealed payload itself (mock/test dialect — one row).
                    let rows = container_contents(&content.plaintext);
                    message.encrypted_contents = Some(if rows.is_empty() {
                        vec![FetchedContent {
                            filename: None,
                            content_type: None,
                            data: normalize_base64(&base64::encode(&content.plaintext)),
                            container: Some("encrypted".into()),
                        }]
                    } else {
                        rows
                    });
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
        let (mut dialog, capture) = self.dialog()?;
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

        // The spec nests the MessageId inside each osci:ProcessCard; the
        // oscirs bundle parser only reads a bundle-level one, so fall back
        // to the raw response (the Laufzettel identifies the message).
        let raw = capture.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let fallback_id = extract_message_id_raw(&raw);
        let mut cards = Vec::new();
        for bundle in &response.process_card_bundles {
            for pc in &bundle.process_cards {
                cards.push(ProcessCard {
                    message_id: bundle.message_id.clone().or_else(|| fallback_id.clone()),
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
            message: e.message().to_string(),
            feedback: Vec::new(),
        })?;
        let capture = Arc::new(Mutex::new(Vec::new()));
        let capturing = CapturingTransport {
            inner: transport,
            last_response: capture.clone(),
            decrypters: vec![Arc::new(P12Decrypter::new(
                (*self.decrypter_keypair).clone(),
            ))],
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
    /// The shared outbound skeleton: languages plus the certificate set
    /// the schema allows for this kind — dialog-lifecycle and fetch types
    /// carry only the originator cipher certificate, store deliveries add
    /// the originator signature and the addressee's cipher certificate.
    fn base_message(&self, kind: MessageType, addressee: Option<&Certificate>) -> OutMessage {
        let entries: Vec<OutCertEntry> = match kind {
            MessageType::StoreDelivery | MessageType::PartialStoreDelivery => {
                let mut entries = vec![
                    cert_entry(
                        CertRole::Originator,
                        CertUse::Cipher,
                        "originator_cipher",
                        self.decrypter_keypair.certificate().der(),
                    ),
                    cert_entry(
                        CertRole::Originator,
                        CertUse::Signature,
                        "originator_signature",
                        self.signer_keypair.certificate().der(),
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
                entries
            }
            // InitDialog carries the cipher certificate mandatorily
            MessageType::InitDialog => vec![
                cert_entry(
                    CertRole::Originator,
                    CertUse::Cipher,
                    "originator_cipher",
                    self.decrypter_keypair.certificate().der(),
                ),
                cert_entry(
                    CertRole::Originator,
                    CertUse::Signature,
                    "originator_signature",
                    self.signer_keypair.certificate().der(),
                ),
            ],
            // exit/fetch/process-card: signature certificate only
            MessageType::ExitDialog
            | MessageType::FetchDelivery
            | MessageType::FetchProcessCard => {
                vec![cert_entry(
                    CertRole::Originator,
                    CertUse::Signature,
                    "originator_signature",
                    self.signer_keypair.certificate().der(),
                )]
            }
            _ => vec![
                cert_entry(
                    CertRole::Originator,
                    CertUse::Cipher,
                    "originator_cipher",
                    self.decrypter_keypair.certificate().der(),
                ),
                cert_entry(
                    CertRole::Originator,
                    CertUse::Signature,
                    "originator_signature",
                    self.signer_keypair.certificate().der(),
                ),
            ],
        };
        OutMessage {
            kind: Some(kind),
            desired_languages: (!kind.is_response()).then(|| "de".to_string()),
            non_intermediary_certificates: entries,
            ..Default::default()
        }
    }
}

/// The XTA MessageMetaData custom-header fragment, in the shape of the
/// reference fixture (`testcorpus/extension/xtaMmdOsci.xml`): author /
/// reader identification plus WS-Addressing message id and size. oscirs
/// canonicalizes the fragment and sets the Id attribute.
fn mmd_fragment(
    author: Option<&str>,
    reader: Option<&str>,
    message_id: &str,
    total_bytes: usize,
) -> String {
    let mut inner = String::new();
    if let Some(author) = author {
        inner.push_str(&format!(
            "<mmd:Originators><mmd:Author><mmd:Identifier type=\"xoev\">{}</mmd:Identifier></mmd:Author></mmd:Originators>",
            xml_escape(author)
        ));
    }
    if let Some(reader) = reader {
        inner.push_str(&format!(
            "<mmd:Destinations><mmd:Reader><mmd:Identifier type=\"xoev\">{}</mmd:Identifier></mmd:Reader></mmd:Destinations>",
            xml_escape(reader)
        ));
    }
    inner.push_str(&format!(
        "<mmd:MsgIdentification><wsa:MessageID>urn:rosci:messageid:{}</wsa:MessageID></mmd:MsgIdentification>",
        xml_escape(message_id)
    ));
    inner.push_str(&format!("<mmd:MsgSize>{total_bytes}</mmd:MsgSize>"));
    format!(
        "<mmd:MessageMetaData xmlns:mmd=\"http://www.osci.eu/ws/2014/10/transport\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">{inner}</mmd:MessageMetaData>"
    )
}

/// Content ids ride in `cid:` references and MIME Content-ID headers;
/// keep them to token characters (the Java bridge used the raw filename,
/// which is fine until it isn't).
fn sanitize_content_id(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "attachment".to_string()
    } else {
        cleaned
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

/// Extracts the content rows of a decrypted ContentContainer XML: every
/// `osci:Content`'s `Base64Content` text, still base64 (the wire encoding
/// our consumers already speak).
fn container_contents(container_xml: &[u8]) -> Vec<FetchedContent> {
    let Ok(doc) = osci_core::xml::parser::parse(&String::from_utf8_lossy(container_xml)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    fn walk(element: &osci_core::xml::Element, out: &mut Vec<FetchedContent>) {
        // Base64Content sits under osci:Content in the Java writer's
        // shape, but sealed containers in the wild also carry it directly
        // under the container — match at any depth.
        if element.local == "Base64Content" {
            out.push(FetchedContent {
                filename: None,
                content_type: None,
                data: normalize_base64(&element.text()),
                container: Some("encrypted".into()),
            });
            return;
        }
        for child in element.elements() {
            walk(child, out);
        }
    }
    walk(&doc.root, &mut out);
    out
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
                data: normalize_base64(b64),
                container: Some("plain".into()),
            });
        } else if let Some(href) = &content.href {
            let cid = href.trim_start_matches("cid:");
            if let Some(att) = attachments
                .iter()
                .find(|a| a.content_id == cid || format!("<{}>", a.content_id) == cid)
            {
                contents.push(FetchedContent {
                    // the content id doubles as the filename — the same
                    // convention the Java bridge's Attachment refIds used
                    filename: Some(cid.to_string()),
                    content_type: Some(att.content_type.clone()),
                    data: normalize_base64(&base64::encode(&att.data)),
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
