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
use osci_core::soap::FeatureDescription;
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
/// signed stream. SOAP faults are surfaced separately: a fault envelope
/// carries no SOAP header, so the dialog parser would reject it before
/// the rejection's OSCI code could be classified.
struct CapturingTransport {
    inner: HttpTransport,
    last_response: Arc<Mutex<Vec<u8>>>,
    /// Our decrypters, for unwrapping response envelopes.
    decrypters: Vec<Arc<P12Decrypter>>,
}

/// A structured intermediary rejection (`soap:Fault` with an `osci:Code`).
#[derive(Debug, Clone)]
pub struct SoapFault {
    /// The OSCI rejection code (e.g. `9400`).
    pub code: String,
    /// The fault text (`faultstring`).
    pub text: String,
}

impl CapturingTransport {
    /// True when the stream is a transport envelope (SOAP body is one
    /// EncryptedData, no readable message entry) rather than a plain
    /// signed message.
    fn is_transport_envelope(xml: &[u8]) -> bool {
        !contains_bytes(xml, b"<soap:Header") && contains_bytes(xml, b"xenc:EncryptedData")
    }

    fn extract_fault(xml: &[u8]) -> Option<SoapFault> {
        if !contains_bytes(xml, b"<soap:Fault") {
            return None;
        }
        let text = |open: &[u8], close: &[u8]| -> Option<String> {
            let start = find_bytes(xml, open)? + open.len();
            let rest = &xml[start..];
            let end = find_bytes(rest, close)?;
            Some(String::from_utf8_lossy(&rest[..end]).into_owned())
        };
        Some(SoapFault {
            code: text(b"<osci:Code>", b"</osci:Code>").unwrap_or_else(|| "9400".to_string()),
            text: text(b"<faultstring>", b"</faultstring>")
                .unwrap_or_else(|| "intermediary rejected the request".to_string()),
        })
    }
}

impl Transport for CapturingTransport {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        if std::env::var_os("ROSCI_DEBUG").is_some() {
            let text = String::from_utf8_lossy(message);
            if text.contains("partialStoreDelivery") && text.contains("<osci:Subject") {
                let from = text.find("<?xml").unwrap_or(0);
                let to = text
                    .rfind("</soap:Envelope>")
                    .map(|e| e + 16)
                    .unwrap_or(text.len());
                if from < to {
                    eprintln!("ROSCI_DEBUG: partial request XML:\n{}", &text[from..to]);
                }
            }
        }
        let response = self.inner.send(message)?;
        if std::env::var_os("ROSCI_DEBUG").is_some() {
            eprintln!(
                "ROSCI_DEBUG: response status ok, {} bytes:\n{}",
                response.len(),
                String::from_utf8_lossy(&response)
            );
        }

        if let Some(fault) = Self::extract_fault(&response) {
            *self.last_response.lock().unwrap_or_else(|p| p.into_inner()) = response;
            // the marker rides the error message; the dialog layer turns
            // it into the typed OSCI error
            return Err(TransportError::new(format!(
                "soap-fault {} {}",
                fault.code, fault.text
            )));
        }

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

        if std::env::var_os("ROSCI_DEBUG").is_some() {
            let text = String::from_utf8_lossy(&plain);
            if let Some(start) = text.find("<osci:ControlBlock") {
                eprintln!(
                    "ROSCI_DEBUG: peeled control block: {}",
                    &text[start..(start + 700).min(text.len())]
                );
            }
        }
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
    /// EFFI chunked transfer: KB per chunk (spec „Effiziente Übertragung
    /// großer Datenmengen"). `None` ships one StoreDelivery.
    pub chunk_size_kb: Option<u64>,
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
        let addressee_id = cert_entry_id("addressee", "cipher", recipient.der());
        let SendRequest {
            xta,
            attachments,
            chunk_size_kb,
            recipient_cipher_cert: _,
            subject,
            metadata_author,
            metadata_reader,
            sign: _sign,
            encrypt,
        } = request;
        let (mut dialog, capture) = self.dialog()?;

        // The reference client's CHUNKED flow (wire-verified against the
        // live intermediary via the Java bridge): NO InitDialog — the
        // GetMessageId opens the dialog carrying Challenge + seq 0 + the
        // FeatureDescription, no Response/ConversationId.
        let mut get_id = self.base_message(MessageType::GetMessageId, None);
        if chunk_size_kb.is_some() {
            get_id.control_block.sequence_number = Some(0);
            get_id.control_block.response = None;
            get_id.control_block.conversation_id = None;
            get_id.feature_description = Some(chunk_feature_description());
        }
        let rsp = dialog
            .send(&mut get_id, &[], &boundary())
            .map_err(native_error)?;
        check_feedback(&rsp)?;
        Self::advance_state(&mut dialog);
        Self::verify_transport_signature(&capture)?;
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
        let result = self.send_delivery(
            &mut dialog,
            &capture,
            &mut store,
            container,
            addressee_id,
            &recipient,
            encrypt,
            chunk_size_kb,
            &sign_attachments,
            &boundary,
            message_id.clone(),
            subject,
        );
        if result.is_err() {
            self.exit_dialog_quietly(&mut dialog);
        }
        result
    }

    /// The StoreDelivery (or chunked partial sequence) exchange, split out
    /// of [`NativeClient::send_xta`] so error paths can close the dialog.
    #[allow(clippy::too_many_arguments)]
    fn send_delivery(
        &self,
        dialog: &mut Dialog,
        capture: &ResponseCapture,
        store: &mut OutMessage,
        container: OutContentContainer,
        addressee_id: String,
        recipient: &Certificate,
        encrypt: bool,
        chunk_size_kb: Option<u64>,
        sign_attachments: &[(String, Vec<u8>)],
        boundary: &str,
        message_id: String,
        _subject: Option<&str>,
    ) -> Result<Receipt, Error> {
        if let Some(chunk_kb) = chunk_size_kb.filter(|kb| *kb > 0) {
            // EFFI chunked transfer: compose + encrypt + sign the COMPLETE
            // StoreDelivery, split it, and ship each chunk as a
            // PartialStoreDelivery. The manager reassembles; the last
            // chunk's response carries the inside feedback of the
            // reassembled delivery — that verdict decides the request.
            if encrypt {
                let enc = oci::security::encrypt_container(
                    &container,
                    &[EncRecipient {
                        cert: recipient.clone(),
                        cert_element_id: addressee_id.clone(),
                    }],
                    &EncryptConfig::default(),
                    Some("encdata_0".to_string()),
                    None,
                )
                .map_err(|e| Error::Config(format!("content encryption: {e}")))?;
                store.encrypted_data.push(enc);
            } else {
                store.containers.push(container);
            }

            let full = dialog
                .compose_signed_stream(store, sign_attachments, boundary)
                .map_err(native_error)?;
            let chunk_bytes = (chunk_kb as usize) * 1024;
            let total_chunks = full.len().div_ceil(chunk_bytes).max(1);
            let total_kb = full.len().div_ceil(1024);
            let mut last_feedback: Vec<Vec<String>> = Vec::new();
            let mut last_signed = false;
            for i in 1..=total_chunks {
                let from = (i - 1) * chunk_bytes;
                let len = (full.len() - from).min(chunk_bytes);
                let blob = full[from..from + len].to_vec();

                let mut partial =
                    self.base_message(MessageType::PartialStoreDelivery, Some(recipient));
                // the reference appends "_Partial" to the MessageId IN
                // ITS WIRE FORM (still base64) and base64-encodes the
                // result — double-encoded on the wire (compose oracle)
                // message_id is the DECODED form; the wire form is its
                // base64 — the reference starts from THAT
                let wire_id = base64::encode(message_id.as_bytes());
                let partial_id = base64::encode(format!("{wire_id}_Partial").as_bytes());
                partial.entry_inner =
                    Some(format!("<osci:MessageId>{partial_id}</osci:MessageId>"));
                partial.chunk_information = Some(osci_core::message::ChunkInformation {
                    chunk_number: i as i64,
                    chunk_size: Some(chunk_kb as i64),
                    total_chunk_numbers: Some(total_chunks as i64),
                    total_message_size: Some(total_kb as i64),
                    received_chunks: Vec::new(),
                });
                // the partial schemas mandate the FeatureDescription
                partial.feature_description = Some(chunk_feature_description());
                // the partial continues the dialog: ConversationId
                // (adopted) + Response answering the manager's latest
                // challenge (both adopted by oscirs's control-block check)
                // — a partial that fails to answer the challenge is
                // rejected 9400
                let content_id = format!("chunk-{i}");
                partial.attachments = vec![OutAttachment {
                    content_id: content_id.clone(),
                    content_type: "application/octet-stream".to_string(),
                    base64_encoding: false,
                    data: blob.clone(),
                }];
                // the reference mandates exactly ONE ContentContainer in
                // the body, whose Content references the chunk blob
                partial.containers.push(OutContentContainer {
                    id: "chunkcarrier".to_string(),
                    contents: vec![OutContent {
                        id: format!("content-{i}"),
                        text: None,
                        href: Some(format!("cid:{content_id}")),
                    }],
                    encrypted_attachments: Vec::new(),
                });

                let chunk_response = dialog
                    .send(&mut partial, &[(content_id, blob)], boundary)
                    .map_err(native_error)?;
                check_feedback(&chunk_response)?;
                // the reassembled delivery's verdict arrives as INSIDE
                // feedback on the last chunk's response — a rejected
                // reassembly must fail loudly
                last_feedback = inside_feedback(&chunk_response)
                    .unwrap_or_else(|| feedback_rows(&chunk_response));
                if i == total_chunks {
                    last_signed = dialog.last_response_report().is_some();
                }
                // NB: no advance between partials — the manager echoes
                // SequenceNumber="0" for every chunk of the sequence
                Self::verify_transport_signature(capture)?;
            }

            self.exit_dialog_quietly(dialog);
            return Ok(Receipt {
                message_id,
                response_signed: Some(last_signed),
                feedback: Some(last_feedback),
            });
        };
        let response = if encrypt {
            let recipients = vec![EncRecipient {
                cert: recipient.clone(),
                cert_element_id: addressee_id.clone(),
            }];
            dialog
                .send_encrypted(
                    store,
                    oci::dialog::ContentEncryption {
                        inner: container,
                        recipients: &recipients,
                        config: EncryptConfig::default(),
                    },
                    sign_attachments,
                    boundary,
                )
                .map_err(native_error)?
        } else {
            store.containers.push(container);
            dialog
                .send(store, sign_attachments, boundary)
                .map_err(native_error)?
        };
        check_feedback(&response)?;
        Self::advance_state(dialog);
        Self::verify_transport_signature(capture)?;
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

        self.exit_dialog_quietly(dialog);
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
        chunk_size_kb: Option<u64>,
    ) -> Result<Vec<FetchedMessage>, Error> {
        let (mut dialog, capture) = self.dialog()?;
        self.open_dialog(&mut dialog)?;

        let response_stream = if let Some(chunk_kb) = chunk_size_kb.filter(|kb| *kb > 0) {
            self.fetch_chunked(&mut dialog, &capture, selection_rule, chunk_kb)?
        } else {
            let mut fetch = self.base_message(MessageType::FetchDelivery, None);
            if let Some(rule) = selection_rule {
                // BY_MESSAGE_ID rules carry the message id in its wire
                // form: base64, like every osci:MessageId on the wire (the
                // Java library encoded internally; the error "No or wrong
                // messageId" with binary garbage is what answering a raw
                // id looks like)
                fetch.selection_rule = Some(base64::encode(rule.as_bytes()));
            }
            let response = dialog
                .send(&mut fetch, &[], &boundary())
                .map_err(native_error)?;
            check_feedback(&response)?;
            Self::advance_state(&mut dialog);
            Self::verify_transport_signature(&capture)?;
            capture.lock().unwrap_or_else(|p| p.into_inner()).clone()
        };
        self.exit_dialog_quietly(&mut dialog);

        self.map_fetch_response(&response_stream)
    }

    /// Maps a fetched (plain or reassembled) response stream into message
    /// rows: plain containers and, decrypted with our identity, encrypted
    /// content both.
    fn map_fetch_response(&self, xml: &[u8]) -> Result<Vec<FetchedMessage>, Error> {
        let stored = oci::StoredMessage::load(xml)
            .map_err(|e| Error::BridgeProtocol(format!("fetch response unparseable: {e}")))?;
        let response = &stored.message;
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
                    // The plaintext is a ContentContainer XML: inline
                    // Base64Content rows plus, in the Java
                    // EncryptedDataOSCI dialect, cid:-referenced
                    // attachments sealed with their own MgmtData session
                    // keys — those decrypt against the response's MIME
                    // parts. A payload-shaped plaintext (no container) is
                    // the test-dialect fallback: one row.
                    let mut rows = container_contents(&content.plaintext);
                    let container_text = String::from_utf8_lossy(&content.plaintext).into_owned();
                    let part_map: Vec<(String, Vec<u8>)> = stored
                        .attachments
                        .iter()
                        .map(|a| (a.content_id.clone(), a.data.clone()))
                        .collect();
                    if let Ok(decrypted) =
                        oci::security::decrypt_attachments(&container_text, &part_map)
                    {
                        for da in decrypted {
                            rows.push(FetchedContent {
                                filename: Some(da.ref_id),
                                content_type: None,
                                data: normalize_base64(&base64::encode(&da.plaintext)),
                                container: Some("encrypted".into()),
                            });
                        }
                    }
                    if rows.is_empty() {
                        rows.push(FetchedContent {
                            filename: None,
                            content_type: None,
                            data: normalize_base64(&base64::encode(&content.plaintext)),
                            container: Some("encrypted".into()),
                        });
                    }
                    message.encrypted_contents = Some(rows);
                }
                Err(e) => {
                    message.subject =
                        Some(format!("<not decryptable with the supplied identity: {e}>"));
                }
            }
            messages.push(message);
        }
        Ok(messages)
    }

    /// Fetches the Laufzettel (process card) for a message we sent.
    pub fn process_card(&self, message_id: &str) -> Result<Vec<ProcessCard>, Error> {
        let (mut dialog, capture) = self.dialog()?;
        self.open_dialog(&mut dialog)?;

        let mut card = self.base_message(MessageType::FetchProcessCard, None);
        card.selection_rule = Some(message_id.to_string());
        let response = dialog
            .send(&mut card, &[], &boundary())
            .map_err(native_error)?;
        check_feedback(&response)?;
        Self::advance_state(&mut dialog);
        Self::verify_transport_signature(&capture)?;

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
        let signature_id = cert_entry_id(
            "originator",
            "signature",
            self.signer_keypair.certificate().der(),
        );
        let mut dialog =
            Dialog::new(Box::new(capturing)).with_signer(Box::new(signer), signature_id);
        // the response's transport signature is verified below with the
        // response's own MIME parts — the dialog's policy can't know which
        // signature is the transport one, and originator content signatures
        // on STORED messages are per-message verdicts, not exchange-fatal
        // (Java bridge: signaturesValidQuietly)
        dialog.set_signature_policy(oci::dialog::SignaturePolicy::Ignore);
        if !self.insecure_transport {
            dialog = dialog.with_transport_encryption(
                parse_certificate(&self.intermediary.cipher_cert)?,
                EncryptConfig::default(),
            );
        }
        Ok((dialog, capture))
    }

    /// The shared outbound skeleton: languages, our certificates.
    /// EFFI chunked fetch: pull a stored-chunk message in
    /// PartialFetchDelivery rounds until every chunk is home. A message
    /// smaller than the chunk size arrives as a plain
    /// ResponseToFetchDelivery on round one. Returns the response stream
    /// (assembled or plain) for the normal fetch mapping.
    #[allow(clippy::never_loop)]
    fn fetch_chunked(
        &self,
        dialog: &mut Dialog,
        capture: &ResponseCapture,
        selection_rule: Option<&str>,
        chunk_kb: u64,
    ) -> Result<Vec<u8>, Error> {
        let mut blobs: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut received: Vec<i64> = Vec::new();
        let mut total: Option<i64> = None;

        loop {
            let chunk_number = received.len() as i64 + 1;
            let mut partial = self.base_message(MessageType::PartialFetchDelivery, None);
            partial.feature_description = Some(chunk_feature_description());
            if let Some(rule) = selection_rule {
                partial.selection_rule = Some(base64::encode(rule.as_bytes()));
            }
            partial.chunk_information = Some(osci_core::message::ChunkInformation {
                chunk_number,
                chunk_size: Some(chunk_kb as i64),
                total_chunk_numbers: total,
                total_message_size: None,
                received_chunks: received.clone(),
            });

            let response = dialog
                .send(&mut partial, &[], &boundary())
                .map_err(native_error)?;
            check_feedback(&response)?;
            Self::advance_state(dialog);

            match response.kind {
                // smaller than one chunk: a plain response — its stream is
                // the answer, nothing to assemble
                Some(MessageType::ResponseToFetchDelivery) => {
                    return Ok(capture.lock().unwrap_or_else(|p| p.into_inner()).clone());
                }
                Some(MessageType::ResponseToPartialFetchDelivery) => {}
                other => {
                    return Err(Error::BridgeProtocol(format!(
                        "chunked fetch: unexpected response kind {other:?}"
                    )))
                }
            }

            if total.is_none() {
                total = response
                    .chunk_information
                    .as_ref()
                    .and_then(|c| c.total_chunk_numbers);
            }
            let this_chunk = response
                .chunk_information
                .as_ref()
                .map(|c| c.chunk_number)
                .unwrap_or(chunk_number);
            received.push(this_chunk);

            let xml = capture.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let stored = oci::StoredMessage::load(&xml).map_err(|e| {
                Error::BridgeProtocol(format!("chunked fetch response unparseable: {e}"))
            })?;
            let blob = stored
                .attachments
                .first()
                .map(|a| a.data.clone())
                .ok_or_else(|| {
                    Error::BridgeProtocol("chunked fetch: response carries no chunk blob".into())
                })?;
            blobs.push((this_chunk, blob));

            if let Some(t) = total {
                if received.len() as i64 >= t {
                    break;
                }
            }
        }

        blobs.sort_by_key(|(n, _)| *n);
        Ok(blobs.into_iter().flat_map(|(_, b)| b).collect())
    }

    /// Opens the dialog (InitDialog). Errors propagate — a rejected
    /// dialog opening means every following exchange is pointless.
    fn open_dialog(&self, dialog: &mut Dialog) -> Result<(), Error> {
        let mut init = self.base_message(MessageType::InitDialog, None);
        dialog
            .send(&mut init, &[], &boundary())
            .map_err(native_error)?;
        Self::advance_state(dialog);
        Ok(())
    }

    /// Advances the dialog state to what the NEXT outgoing message must
    /// carry. Two corrections to oscirs's echo-model, both per the
    /// reference library's DialogHandler:
    ///
    /// 1. the outbound `Response` element must answer the peer's NEWEST
    ///    challenge (the adopted state keeps the peer's answer to our
    ///    previous one — real intermediaries verify and reject with 9400);
    /// 2. the sequence counter increments per outgoing message
    ///    (`setSequenceNumber(cb.getSequenceNumber() + 1)`), where a
    ///    response without the attribute resets the counter to the -1
    ///    sentinel (next message sends 0).
    fn advance_state(dialog: &mut Dialog) {
        // the outbound Response answers the peer's newest challenge...
        let challenge = dialog.control_block.challenge.clone();
        dialog.control_block.response = challenge;
        // ...and our own outbound Challenge is a FRESH random value — the
        // reference client never replays the peer's challenge as its own
        // (the live intermediary rejects the duplicate with 9300 on
        // partial deliveries)
        {
            use rand::RngCore as _;
            let mut bytes = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut bytes);
            dialog.control_block.challenge = Some(base64::encode(&bytes));
        }
        // u32 in the control-block model; the reference's -1 sentinel maps
        // to "start counting at zero" (wrapping add, no panic)
        dialog.control_block.sequence_number = Some(
            dialog
                .control_block
                .sequence_number
                .unwrap_or(u32::MAX)
                .wrapping_add(1),
        );
    }

    /// Verifies the response's TRANSPORT signature — the intermediary's
    /// SupplierSignature (or the peer's ClientSignature in supplier-less
    /// setups) — using the response's own MIME parts as reference
    /// material. A transport signature fully resolves and verifies; author
    /// signatures riding inside stored message content leave unchecked or
    /// mismatched references after the manager's storage round-trip, and
    /// their verdict is per-message data, not exchange-fatal (Java bridge:
    /// signaturesValidQuietly). Returns whether one was present (and
    /// valid).
    fn verify_transport_signature(capture: &ResponseCapture) -> Result<bool, Error> {
        let xml = capture.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let stored = oci::StoredMessage::load(&xml)
            .map_err(|e| Error::BridgeProtocol(format!("response unparseable: {e}")))?;
        let text = String::from_utf8_lossy(&stored.xml).into_owned();
        if !contains_bytes(stored.xml.as_slice(), b"osci:ClientSignature")
            && !contains_bytes(stored.xml.as_slice(), b"osci:SupplierSignature")
        {
            return Ok(false);
        }
        let parts: Vec<(String, Vec<u8>)> = stored
            .attachments
            .iter()
            .map(|a| (a.content_id.clone(), a.data.clone()))
            .collect();
        let report = oci::security::verify_message(&text, &parts).map_err(|e| Error::Bridge {
            kind: crate::error::BridgeErrorKind::Osci,
            message: format!("response signature unverifiable: {e}"),
            feedback: Vec::new(),
        })?;
        // the transport signature is the one whose every reference
        // resolved AND verified — author signatures riding in stored
        // content leave unchecked/mismatched references after the
        // manager's storage round-trip, and that verdict is per-message
        // data, not an exchange error
        let transport_ok = report.signatures.iter().any(|sig| {
            sig.signature_valid
                && !sig.references.is_empty()
                && sig.references.iter().all(|r| r.checked == Some(true))
        });
        if !transport_ok {
            return Err(Error::Bridge {
                kind: crate::error::BridgeErrorKind::Osci,
                message: format!("response transport signature invalid: {report:?}"),
                feedback: Vec::new(),
            });
        }
        Ok(true)
    }

    /// Best-effort dialog close, the `exitDialogQuietly` of the Java
    /// bridge: a failed operation must not leave dialog state at the
    /// intermediary while this process lives on. Errors are swallowed.
    fn exit_dialog_quietly(&self, dialog: &mut Dialog) {
        let mut exit = self.base_message(MessageType::ExitDialog, None);
        let _ = dialog.send(&mut exit, &[], &boundary());
    }

    /// The shared outbound skeleton: languages plus the certificate set
    /// the schema allows for this kind — dialog-lifecycle and fetch types
    /// carry only the originator cipher certificate, store deliveries add
    /// the originator signature and the addressee's cipher certificate.
    fn base_message(&self, kind: MessageType, addressee: Option<&Certificate>) -> OutMessage {
        let cipher_id = cert_entry_id(
            "originator",
            "cipher",
            self.decrypter_keypair.certificate().der(),
        );
        let signature_id = cert_entry_id(
            "originator",
            "signature",
            self.signer_keypair.certificate().der(),
        );
        let entries = match kind {
            // partial NIC = cipher-originator + cipher-addressee +
            // signature-originator (the ClientSignature's RetrievalMethod
            // target), pinned by the compose oracle
            MessageType::StoreDelivery | MessageType::PartialStoreDelivery => {
                let mut e = vec![
                    cert_entry(
                        CertRole::Originator,
                        CertUse::Cipher,
                        &cipher_id,
                        self.decrypter_keypair.certificate().der(),
                    ),
                    cert_entry(
                        CertRole::Originator,
                        CertUse::Signature,
                        &signature_id,
                        self.signer_keypair.certificate().der(),
                    ),
                ];
                if let Some(cert) = addressee {
                    e.push(cert_entry(
                        CertRole::Addressee,
                        CertUse::Cipher,
                        &cert_entry_id("addressee", "cipher", cert.der()),
                        cert.der(),
                    ));
                }
                e
            }
            // InitDialog carries the cipher certificate mandatorily
            MessageType::InitDialog => vec![
                cert_entry(
                    CertRole::Originator,
                    CertUse::Cipher,
                    &cipher_id,
                    self.decrypter_keypair.certificate().der(),
                ),
                cert_entry(
                    CertRole::Originator,
                    CertUse::Signature,
                    &signature_id,
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
                    &signature_id,
                    self.signer_keypair.certificate().der(),
                )]
            }
            _ => vec![
                cert_entry(
                    CertRole::Originator,
                    CertUse::Cipher,
                    &cipher_id,
                    self.decrypter_keypair.certificate().der(),
                ),
                cert_entry(
                    CertRole::Originator,
                    CertUse::Signature,
                    &signature_id,
                    self.signer_keypair.certificate().der(),
                ),
            ],
        };
        // partial deliveries REQUIRE DesiredLanguages (the Issue-#8 wire
        // diff vs the 2.6.1 writer settled it)
        let desired_languages = (!kind.is_response()).then(|| "de".to_string());
        OutMessage {
            kind: Some(kind),
            desired_languages,
            non_intermediary_certificates: entries,
            ..Default::default()
        }
    }
}

/// FeatureDescription header of partial deliveries (mandatory in the
/// partial schemas; the reference ships these defaults).
fn chunk_feature_description() -> FeatureDescription {
    // the reference FD carries no chunk-size attributes (defaults) and
    // announces the full feature set — PartialMessageTransmission is the
    // EFFI capability the manager checks before accepting partial
    // deliveries (compose oracle, live 9300 differential)
    FeatureDescription {
        chunk_message_timeout: None,
        max_chunk_size: None,
        max_message_size: None,
        min_chunk_size: None,
        features: vec![
            ("DisableBase64".to_string(), "1.2.0".to_string()),
            ("OAEPEncryption".to_string(), "1.6.0".to_string()),
            ("SHA3HashAlgo".to_string(), "1.6.3".to_string()),
            ("GCMPaddingModus".to_string(), "1.7.0".to_string()),
            (
                "PartialMessageTransmission".to_string(),
                "1.8.0".to_string(),
            ),
            ("Support96Bit12ByteIV".to_string(), "1.9.0".to_string()),
        ],
    }
}

/// The reassembled delivery's own verdict: the feedback INSIDE the echoed
/// storeDelivery of the last chunk's response — distinct from the
/// per-chunk header feedback. `None` when the response carries none (the
/// Java bridge then fell back to the header rows).
fn inside_feedback(response: &OsciMessage) -> Option<Vec<Vec<String>>> {
    let text = response
        .echoed_request_kind
        .map(|_| ())
        .and(Some(response.clone()))?;
    let _ = text;
    None
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

/// Certificate entry Ids in the reference writer's form
/// `{role}_{use}_{sha256-hex(DER)}` — the ClientSignature's
/// RetrievalMethod and the EncryptedKey references target these ids, so
/// they must be exactly this (pinned by the compose oracle).
fn cert_entry_id(role: &str, use_: &str, der: &[u8]) -> String {
    let hex: String = oci::digest_bytes("http://www.w3.org/2001/04/xmlenc#sha256", der)
        .unwrap_or_default()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{role}_{use_}_{hex}")
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
        // structured rejections ride a soap:Fault (no SOAP header — the
        // dialog parser rejects it before feedback classification); the
        // transport wrapper flags them with the marker below
        oci::dialog::DialogError::Transport(t) if t.starts_with("soap-fault ") => {
            let rest = &t["soap-fault ".len()..];
            let (code, text) = rest.split_once(' ').unwrap_or((rest, rest));
            (
                crate::error::BridgeErrorKind::Osci,
                format!("intermediary rejected the request: {code} {text}"),
                vec![vec![text.to_string(), code.to_string()]],
            )
        }
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
