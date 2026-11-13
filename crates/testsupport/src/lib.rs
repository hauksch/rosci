//! In-process mock OSCI intermediary — the Rust replacement for the
//! retired Java `osci-mock.jar` in the e2e suites.
//!
//! A plain-TCP HTTP server (Content-Length framing) that answers every
//! dialog-bound OSCI request the binaries make: dialog chain with
//! control-block echo, a GetMessageId reservation, positive feedback for
//! deliveries, two canned fetch messages (one plain with an attachment,
//! one encrypted to the client's cipher certificate), and a canned
//! Laufzettel whose message id echoes the status query. Responses are
//! signed with the intermediary's generated signing identity;
//! [`MockIntermediary::start_tampering`] flips a SignatureValue byte so
//! client verification paths get exercised.
//!
//! Everything runs in-process; network endpoints touched: 127.0.0.1 only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use osci_core::helper::base64;
use osci_core::message::MessageType;
use osci_core::message::compose::{
    OutAttachment, OutContent, OutContentContainer, OutFeedback, OutMessage, OutProcessCard,
    OutProcessCardBundle, compose_message, signature_header_name,
};
use osci_core::message::stored::StoredMessage;
use osci_core::soap::{ControlBlock, find_header};
use osci_rs::security::{
    EncRecipient, EncryptConfig, StoredMessageLike, decrypt_transport_message, encrypt_container,
};
use osci_rs::{Certificate, RsaSigner, Signer};

/// Canned fetch attachment payload — asserted byte-honest by the suite.
pub const FETCH_ATTACHMENT_NAME: &str = "mock-antwort.xta";
pub const FETCH_ATTACHMENT_XML: &str =
    "<?xml version=\"1.0\"?><XTA><antwort>die behoerde dankt fuer die Meldung</antwort></XTA>";
/// Canned encrypted fetch content — asserted decrypted by the suite.
pub const FETCH_SECRET: &str = "streng vertrauliche antwort";
/// Canned Laufzettel subject — asserted by the status test.
pub const PROCESS_CARD_SUBJECT: &str = "mock laufzettel";

/// Per-exchange dump context: the jar mock's wire-capture contract
/// (request-N.xml raw, request-N.inner.xml decrypted, request-N.meta
/// with the transport flag, response-N.xml).
struct DumpContext {
    dir: PathBuf,
    n: usize,
}

/// A running mock intermediary on localhost.
pub struct MockIntermediary {
    pub port: u16,
    _keepalive: Arc<AtomicBool>,
}

impl MockIntermediary {
    /// Starts the mock with the generated test PKI (gen-pki.sh layout in
    /// `pki_dir`): the intermediary signs responses with
    /// `intermed-sign`, the canned encrypted fetch content is sealed to
    /// `client-cipher.pem`, and `dump_dir` (optional) receives every
    /// request body verbatim.
    pub fn start_simple(pki_dir: &Path, dump_dir: &Path) -> std::io::Result<Self> {
        Self::start(
            Some(dump_dir),
            &pki_dir.join("intermed-sign.key"),
            &pki_dir.join("intermed-sign.pem"),
            &pki_dir.join("client-cipher.pem"),
            &pki_dir.join("intermed-cipher.p12"),
            "testpin",
            false,
        )
    }

    /// Same, with the response signature corrupted after signing.
    pub fn start_tampering(pki_dir: &Path, dump_dir: &Path) -> std::io::Result<Self> {
        Self::start(
            Some(dump_dir),
            &pki_dir.join("intermed-sign.key"),
            &pki_dir.join("intermed-sign.pem"),
            &pki_dir.join("client-cipher.pem"),
            &pki_dir.join("intermed-cipher.p12"),
            "testpin",
            true,
        )
    }

    /// Full control over the wiring.
    pub fn start(
        dump_dir: Option<&Path>,
        sign_key_pem: &Path,
        sign_cert_pem: &Path,
        client_cipher_pem: &Path,
        intermed_cipher_p12: &Path,
        p12_pin: &str,
        tamper: bool,
    ) -> std::io::Result<Self> {
        Self::start_inner(
            dump_dir,
            sign_key_pem,
            sign_cert_pem,
            client_cipher_pem,
            intermed_cipher_p12,
            p12_pin,
            tamper,
            None,
        )
    }

    /// Inner wiring with an optional TLS server certificate (leaf key +
    /// cert, both PEM). When set, the accepted TCP streams are wrapped in
    /// a rustls server session — the HTTPS mock variant.
    #[allow(clippy::too_many_arguments)]
    fn start_inner(
        dump_dir: Option<&Path>,
        sign_key_pem: &Path,
        sign_cert_pem: &Path,
        client_cipher_pem: &Path,
        intermed_cipher_p12: &Path,
        p12_pin: &str,
        tamper: bool,
        tls: Option<(&Path, &Path)>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();

        // combined key+cert dump, the PEM-dump shape the oscirs signer
        // loads from
        let dump = std::env::temp_dir().join(format!(
            "testsupport-sign-{}-{}.pem",
            std::process::id(),
            port
        ));
        std::fs::write(
            &dump,
            format!(
                "{}\n{}",
                std::fs::read_to_string(sign_key_pem)?,
                std::fs::read_to_string(sign_cert_pem)?
            ),
        )?;
        let signer = RsaSigner::from_pem_dump(dump.to_str().unwrap(), None).ok();
        let sign_cert: Option<Certificate> = signer
            .as_ref()
            .map(|s| s.certificate().clone())
            .or_else(|| {
                Certificate::from_pem_bundle(&std::fs::read_to_string(sign_cert_pem).ok()?)
                    .ok()
                    .and_then(|c| c.into_iter().next())
            });
        let client_cert =
            Certificate::from_pem_bundle(&std::fs::read_to_string(client_cipher_pem).map_err(
                |e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()),
            )?)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "no cert in client pem")
            })?;
        // the intermediary's own cipher identity: decrypts transport
        // envelopes on requests that ran with full crypto
        let intermed_decrypter = osci::p12::P12Decrypter::new(
            osci::p12::P12Keypair::parse(
                std::fs::read(intermed_cipher_p12)
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                    })?
                    .as_slice(),
                p12_pin,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        );

        let dump_dir: Option<PathBuf> = dump_dir.map(|p| p.to_path_buf());
        let keepalive = Arc::new(AtomicBool::new(true));
        let keep = keepalive.clone();
        let dump_seq = Arc::new(AtomicUsize::new(0));
        let tls_config: Option<Arc<rustls::ServerConfig>> = match tls {
            Some((key_pem, cert_pem)) => {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                    Certificate::from_pem_bundle(&std::fs::read_to_string(cert_pem).map_err(
                        |e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()),
                    )?)
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                    })?
                    .into_iter()
                    .map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec()))
                    .collect();
                // PEM → DER: strip armor, base64-decode the body (the
                // gen-pki keys are PKCS#8)
                let key_pem_text = std::fs::read_to_string(key_pem).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;
                let b64: String = key_pem_text
                    .lines()
                    .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
                    .collect();
                let key_der = base64::decode(&b64).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;
                let key = rustls::pki_types::PrivateKeyDer::from(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
                );
                Some(Arc::new(
                    rustls::ServerConfig::builder_with_provider(
                        rustls::crypto::ring::default_provider().into(),
                    )
                    .with_safe_default_protocol_versions()
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                    })?
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                    })?,
                ))
            }
            None => None,
        };
        std::thread::spawn(move || -> std::io::Result<()> {
            for tcp in listener.incoming().flatten() {
                if !keep.load(Ordering::Relaxed) {
                    break;
                }
                // TLS: drive the handshake to completion with explicit
                // complete_io round-trips on the raw socket before framed
                // reads — StreamOwned's lazy read alone cannot flush the
                // ServerHello it owes.
                let mut tcp = tcp;
                let mut stream: Box<dyn StreamIo> = if let Some(config) = &tls_config {
                    let mut conn = rustls::ServerConnection::new(config.clone()).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                    })?;
                    loop {
                        conn.complete_io(&mut tcp)?;
                        if !conn.is_handshaking() && !conn.wants_write() {
                            break;
                        }
                    }
                    Box::new(rustls::StreamOwned::new(conn, tcp))
                } else {
                    Box::new(tcp)
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if let Some(len) = content_length(&request)
                        && request.len() >= len
                    {
                        break;
                    }
                }
                let body = body_of(&request).to_vec();
                if body.is_empty() {
                    // client hung up mid-request (pool probes, aborted
                    // handshakes) — nothing to answer
                    continue;
                }
                let n = dump_seq.fetch_add(1, Ordering::Relaxed) + 1;
                let dump = dump_dir.as_deref().map(|dir| DumpContext {
                    dir: dir.to_path_buf(),
                    n,
                });
                let response = handle(
                    &body,
                    signer.as_ref(),
                    sign_cert.as_ref(),
                    Some(&client_cert),
                    &intermed_decrypter,
                    tamper,
                    dump.as_ref(),
                );
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
            Ok(())
        });
        Ok(Self {
            port,
            _keepalive: keepalive,
        })
    }

    /// The e2e suite's shape: PKI layout + dump dir.
    pub fn start_with_pki(pki_dir: &Path, dump_dir: &Path) -> std::io::Result<Self> {
        Self::start_simple(pki_dir, dump_dir)
    }

    /// HTTPS variant: the same intermediary behind TLS, with
    /// `intermed-cipher` as the server certificate (self-signed — the
    /// client must trust it via `--tls-ca`/`Tls::trust_anchors`).
    /// Proves the native transport's trust-anchor path on the wire.
    pub fn start_tls(pki_dir: &Path, dump_dir: &Path) -> std::io::Result<Self> {
        Self::start_inner(
            Some(dump_dir),
            &pki_dir.join("intermed-sign.key"),
            &pki_dir.join("intermed-sign.pem"),
            &pki_dir.join("client-cipher.pem"),
            &pki_dir.join("intermed-cipher.p12"),
            "testpin",
            false,
            Some((
                &pki_dir.join("intermed-cipher.key"),
                &pki_dir.join("intermed-cipher.pem"),
            )),
        )
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/osci/externalentry", self.port)
    }
}

/// Object-safe read+write for the per-connection stream (plain TCP or
/// rustls-wrapped).
trait StreamIo: Read + Write {}
impl<T: Read + Write> StreamIo for T {}

fn content_length(raw: &[u8]) -> Option<usize> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = String::from_utf8_lossy(&raw[..header_end]);
    text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|n| header_end + 4 + n)
}

fn body_of(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => &raw[i + 4..],
        None => raw,
    }
}

fn looks_encrypted(xml: &[u8]) -> bool {
    // a TRANSPORT envelope carries the ciphertext detached at
    // cid:osci_enc; content-level EncryptedData (inside the order data)
    // must NOT trigger decryption
    String::from_utf8_lossy(xml).contains("cid:osci_enc")
}

fn control_block_of(xml: &str) -> Option<ControlBlock> {
    // element-level parsing of the four control-block fields (the
    // borrowed document must live through the extraction, so everything
    // is read before it drops)
    let doc = osci_core::xml::parser::parse(xml).ok()?;
    let header = find_header(&doc)?;
    let child = header.elements().find(|e| e.local == "ControlBlock")?;
    let conversation_id = child.attr("ConversationId").map(str::to_string);
    let sequence_number = child.attr("SequenceNumber").and_then(|v| v.parse().ok());
    let response = child
        .elements()
        .find(|e| e.local == "Response")
        .map(|e| e.text());
    let challenge = child
        .elements()
        .find(|e| e.local == "Challenge")
        .map(|e| e.text());
    drop(doc);
    Some(ControlBlock {
        conversation_id,
        sequence_number,
        response,
        challenge,
    })
}

#[allow(clippy::too_many_arguments)]
fn handle(
    body: &[u8],
    signer: Option<&RsaSigner>,
    sign_cert: Option<&Certificate>,
    client_cert: Option<&Certificate>,
    intermed_decrypter: &osci::p12::P12Decrypter,
    tamper: bool,
    dump: Option<&DumpContext>,
) -> Vec<u8> {
    let stored = StoredMessage::load(body).expect("mock parses the request");
    // full-crypto requests arrive as SOAPMessageEncrypted envelopes;
    // decrypt with the intermediary's cipher identity first
    let mut transport_encrypted = false;
    let mut inner_xml: Option<Vec<u8>> = None;
    let stored = if looks_encrypted(&stored.xml) {
        transport_encrypted = true;
        let like = StoredMessageLike {
            xml: &stored.xml,
            attachments: &stored.attachments,
        };
        let decrypted = decrypt_transport_message(&like, &[intermed_decrypter])
            .expect("mock decrypts the transport envelope");
        inner_xml = Some(decrypted.clone());
        StoredMessage::load(&decrypted).expect("inner signed stream parses")
    } else {
        stored
    };
    let kind = stored.message.kind.unwrap_or(MessageType::GetMessageId);
    let Some(request_block) = control_block_of(&String::from_utf8_lossy(&stored.xml)) else {
        eprintln!(
            "testsupport: request without ControlBlock (kind {:?}): {}",
            kind,
            String::from_utf8_lossy(&body[..body.len().min(2600)])
        );
        // a minimal, unsigned positive response keeps the suite alive
        let out = OutMessage {
            kind: Some(MessageType::ResponseToGetMessageId),
            feedback: vec![OutFeedback {
                language: Some("de".into()),
                code: "0800".into(),
                text: "Auftrag ausgeführt".into(),
            }],
            ..Default::default()
        };
        return compose_message(&out, "MIME_boundary").unwrap();
    };

    let (response_kind, code) = match kind {
        MessageType::GetMessageId => (MessageType::ResponseToGetMessageId, "0800"),
        MessageType::StoreDelivery => (MessageType::ResponseToStoreDelivery, "0801"),
        MessageType::InitDialog => (MessageType::ResponseToInitDialog, "0800"),
        MessageType::FetchDelivery => (MessageType::ResponseToFetchDelivery, "0801"),
        MessageType::FetchProcessCard => (MessageType::ResponseToFetchProcessCard, "0801"),
        MessageType::ExitDialog => (MessageType::ResponseToExitDialog, "0800"),
        other => panic!("mock intermediary cannot handle {other:?}"),
    };

    let mut out = OutMessage {
        kind: Some(response_kind),
        control_block: ControlBlock {
            conversation_id: request_block
                .conversation_id
                .or_else(|| Some("4711".to_string())),
            sequence_number: match response_kind {
                MessageType::ResponseToInitDialog => None,
                _ => request_block.sequence_number.or(Some(0)),
            },
            response: request_block.challenge,
            challenge: Some(base64::encode(b"mock-next-challenge")),
        },
        desired_languages: (!response_kind.is_response()).then(|| "de".to_string()),
        feedback: vec![OutFeedback {
            language: Some("de".into()),
            code: code.into(),
            text: "Auftrag ausgeführt".into(),
        }],
        ..Default::default()
    };
    match kind {
        MessageType::GetMessageId => {
            // the reservation: a stable canned id in wire form
            out.entry_inner = Some(
                r#"<osci:getMessageId xmlns:osci="http://www.osci.de/2002/04/osci"><osci:MessageId>bW9jay1yZXNlcnZhdGlvbi0x</osci:MessageId></osci:getMessageId>"#.to_string(),
            );
        }
        MessageType::FetchDelivery => {
            // one response, two canned messages: the plain container with
            // an attachment, and the encrypted twin sealed to the client's
            // cipher certificate (the fetch mapping turns them into
            // `contents` and `encrypted_contents` rows)
            out.containers.push(OutContentContainer {
                id: "contentcontainer".into(),
                encrypted_attachments: Vec::new(),
                contents: vec![OutContent {
                    id: "content1".into(),
                    text: None,
                    href: Some(format!("cid:{FETCH_ATTACHMENT_NAME}")),
                }],
            });
            out.attachments.push(OutAttachment {
                content_id: FETCH_ATTACHMENT_NAME.into(),
                content_type: "text/xml".into(),
                base64_encoding: false,
                data: FETCH_ATTACHMENT_XML.as_bytes().to_vec(),
            });
            let container = OutContentContainer {
                id: "encryptedcontainer".into(),
                encrypted_attachments: Vec::new(),
                contents: vec![OutContent {
                    id: "content2".into(),
                    text: Some(FETCH_SECRET.into()),
                    href: None,
                }],
            };
            let enc = encrypt_container(
                &container,
                &[EncRecipient {
                    cert: client_cert
                        .expect("client cipher cert for canned fetch")
                        .clone(),
                    cert_element_id: "originator_cipher".into(),
                }],
                &EncryptConfig::default(),
                Some("encdata_0".into()),
                None,
            )
            .expect("mock encrypts the canned fetch content");
            out.encrypted_data.push(enc);
        }
        MessageType::FetchProcessCard => {
            let selection = selection_rule_of(&String::from_utf8_lossy(&stored.xml));
            out.process_card_bundles = vec![OutProcessCardBundle {
                message_id: Some(selection),
                inspections: Vec::new(),
                process_cards: vec![OutProcessCard {
                    creation: Some(
                        chrono::DateTime::parse_from_rfc3339("2026-09-30T08:15:00Z")
                            .unwrap()
                            .with_timezone(&chrono::Utc),
                    ),
                    forwarding: None,
                    reception: None,
                    subject: Some(PROCESS_CARD_SUBJECT.into()),
                }],
            }];
        }
        _ => {}
    }

    // signed responses carry the signing certificate in an
    // IntermediaryCertificates header — the response schemas forbid the
    // NIC on several kinds (ResponseToGetMessageId et al), while the
    // intermediary-certificate header is always legal; the signature's
    // RetrievalMethod resolves against its entry id
    let sign_cert_der = if signer.is_some() {
        sign_cert.map(|c| c.der().to_vec())
    } else {
        None
    };
    if let Some(der) = &sign_cert_der {
        let cert_b64 = base64::encode(der);
        out.custom_headers.push(osci_core::message::compose::OutCustomHeader {
            id: "intermediarycertificates".into(),
            xml: format!(
                "<osci:IntermediaryCertificates xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:osci=\"http://www.osci.de/2002/04/osci\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Id=\"intermediarycertificates\" soap:actor=\"http://www.w3.org/2001/12/soap-envelope/actor/none\" soap:mustUnderstand=\"1\"><osci:SignatureCertificateIntermediary Id=\"{SIGN_CERT_ID}\"><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></osci:SignatureCertificateIntermediary></osci:IntermediaryCertificates>"
            ),
        });
    }

    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let Some(signer) = signer else {
        return stream;
    };
    // splice the signed XML part back into the known-boundary stream
    let text = String::from_utf8_lossy(&stream).to_string();
    let start = text.find("<?xml").unwrap();
    let end = text.find("</soap:Envelope>").unwrap() + "</soap:Envelope>".len();
    let xml = text[start..end].to_string();
    let mut signed = osci_rs::sign::sign_message_xml(
        &xml,
        &osci_rs::sign::SignParams {
            signer,
            method: None,
            digest: None,
            // the retrieval method must point at the element the client's
            // certificate collector keys by: the
            // SignatureCertificateIntermediary entry id
            certificate_id: SIGN_CERT_ID.to_string(),
            attachments: &[],
            header_element: Some(signature_header_name(response_kind)),
        },
    )
    .expect("mock signs the response");
    eprintln!(
        "testsupport: signed retrieval = {}",
        osci_core::xml::parser::parse(&signed)
            .map(|d| {
                let mut uri = String::new();
                if let Some(h) = osci_core::soap::find_header(&d)
                    && let Some(sig) = h
                        .elements()
                        .find(|e| e.local == "SupplierSignature" || e.local == "ClientSignature")
                    && let Some(s) = sig.elements().find(|e| e.local == "Signature")
                    && let Some(ki) = s.elements().find(|e| e.local == "KeyInfo")
                    && let Some(rm) = ki.elements().find(|e| e.local == "RetrievalMethod")
                {
                    uri = rm.attr("URI").unwrap_or_default().to_string();
                }
                uri
            })
            .unwrap_or_default()
    );
    if tamper {
        signed = corrupt_signature_value(signed);
    }
    let plain_response = text.replacen(&xml, &signed, 1).into_bytes();
    if let Some(dump) = dump {
        let _ = std::fs::write(dump.dir.join(format!("request-{}.xml", dump.n)), body);
        let inner = inner_xml.unwrap_or_else(|| body.to_vec());
        let _ = std::fs::write(
            dump.dir.join(format!("request-{}.inner.xml", dump.n)),
            &inner,
        );
        let _ = std::fs::write(
            dump.dir.join(format!("request-{}.meta", dump.n)),
            format!("transport_encrypted: {transport_encrypted}\n"),
        );
    }
    // full-crypto exchanges get enveloped responses: the manager mirrors
    // the transport crypto the client demonstrated with its request
    if transport_encrypted && let Some(cert) = client_cert {
        let enveloped = osci_rs::security::encrypt_message_for(
            &plain_response,
            cert,
            &EncryptConfig::default(),
            "MIME_boundary_response",
        )
        .expect("mock encrypts the response envelope");
        if let Some(dump) = dump {
            let _ = std::fs::write(
                dump.dir.join(format!("response-{}.xml", dump.n)),
                &enveloped,
            );
        }
        return enveloped;
    }
    if let Some(dump) = dump {
        let _ = std::fs::write(
            dump.dir.join(format!("response-{}.xml", dump.n)),
            &plain_response,
        );
    }
    plain_response
}

const SIGN_CERT_ID: &str = "intermediary_signature_cert";

fn selection_rule_of(xml: &str) -> String {
    // the SelectionRule content may wrap the id in an osci:MessageId
    // element — strip tags, keep the bare id
    const OPEN: &str = "<osci:SelectionRule>";
    const CLOSE: &str = "</osci:SelectionRule>";
    let Some(start) = xml.find(OPEN) else {
        return String::new();
    };
    let from = start + OPEN.len();
    let raw = match xml[from..].find(CLOSE) {
        Some(rel) => &xml[from..from + rel],
        None => return String::new(),
    };
    let mut out = String::new();
    let mut in_tag = false;
    for ch in raw.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

fn corrupt_signature_value(mut xml: String) -> String {
    let start = xml.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
    let bytes = unsafe { xml.as_bytes_mut() };
    bytes[start] = if bytes[start] == b'A' { b'B' } else { b'A' };
    xml
}
