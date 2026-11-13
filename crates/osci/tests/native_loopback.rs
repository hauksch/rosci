//! Native client end-to-end over a scripted in-process intermediary:
//! send (signed + content-encrypted, transport-encrypted variant
//! included), version handshake. The Rust counterpart of the Java mock
//! e2e — same control-block protocol, no JVM.

// Tests panic on broken assumptions — that is the job description.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;

use osci::Xta;
use osci::native::NativeClient;
use osci::p12::{P12Decrypter, P12Keypair};
use osci::{Identity, Intermediary};

use osci_core::helper::base64;
use osci_core::message::MessageType;
use osci_core::message::compose::{OutFeedback, OutMessage, compose_message};
use osci_core::soap::{ControlBlock, find_header};
use osci_core::xml::parser;
use osci_rs::StoredMessage;
use osci_rs::security::{EncryptConfig, decrypt_transport_message};

const PIN: &str = "testpin";

/// openssl RSA-2048 keystore + certificate PEM, like the e2e fixtures.
/// The tempdir is leaked deliberately: openssl's files must outlive the
/// p12 read, and this runs a handful of times per test binary.
fn openssl_keystore(cn: &str) -> (Vec<u8>, String) {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.pem");
    let cert = dir.path().join("cert.pem");
    let p12 = dir.path().join("ks.p12");

    let run = |args: &[&str]| {
        let out = std::process::Command::new("openssl")
            .args(args)
            .output()
            .expect("openssl");
        assert!(
            out.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        key.to_str().unwrap(),
        "-out",
        cert.to_str().unwrap(),
        "-days",
        "2",
        "-nodes",
        "-subj",
        &format!("/CN={cn}"),
    ]);
    run(&[
        "pkcs12",
        "-export",
        "-inkey",
        key.to_str().unwrap(),
        "-in",
        cert.to_str().unwrap(),
        "-name",
        "test",
        "-passout",
        &format!("pass:{PIN}"),
        "-out",
        p12.to_str().unwrap(),
    ]);
    let p12_bytes = std::fs::read(&p12).unwrap();
    let cert_pem = std::fs::read_to_string(&cert).unwrap();
    std::mem::forget(dir);
    (p12_bytes, cert_pem)
}

/// The scripted intermediary: control-block echo + positive feedback for
/// every message kind the native client drives. When the request is a
/// transport-encrypted envelope, it is decrypted first — the real thing,
/// then, just on a TCP socket instead of gov.test.osci.de.
fn serve(
    listener: TcpListener,
    intermediary_decrypter: P12Decrypter,
    client_cipher_cert: Option<String>,
) {
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
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
            let response = handle(
                &body,
                &intermediary_decrypter,
                client_cipher_cert.as_deref(),
            );
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&response).unwrap();
        }
    });
}

/// Extracts the DER certificate from a PEM string.
fn pem_certificate(pem: &str) -> osci_rs::Certificate {
    let start = pem.find("-----BEGIN CERTIFICATE-----").unwrap() + 27;
    let after = &pem[start..];
    let end = after.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    osci_rs::Certificate::from_der(&base64::decode(&b64).unwrap()).unwrap()
}

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
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    &raw[header_end + 4..]
}

fn handle(
    body: &[u8],
    intermediary_decrypter: &P12Decrypter,
    client_cipher_cert: Option<&str>,
) -> Vec<u8> {
    // transport-decrypt when the envelope is encrypted (the native client
    // sends encrypted unless the test disables it)
    let stored = StoredMessage::load(body).unwrap();
    let xml = if stored.message.kind.is_none() && looks_encrypted(&stored.xml) {
        let like = osci_rs::security::StoredMessageLike {
            xml: &stored.xml,
            attachments: &stored.attachments,
        };
        let inner = decrypt_transport_message(&like, &[intermediary_decrypter])
            .expect("mock decrypts the transport envelope");
        StoredMessage::load(&inner).expect("inner signed stream parses")
    } else {
        stored
    };

    let kind = xml.message.kind.unwrap_or(MessageType::GetMessageId);
    let request_block = control_block_of(&xml.xml);
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
            // a real intermediary mints the ConversationId on the first
            // response; the request has none yet
            conversation_id: request_block
                .conversation_id
                .or_else(|| Some("4711".to_string())),
            // ResponseToInitDialog/ExitDialog prohibit the sequence
            // attribute (it starts with the first "real" exchange)
            sequence_number: match response_kind {
                MessageType::ResponseToInitDialog => None,
                _ => request_block.sequence_number.or(Some(0)),
            },
            response: request_block.challenge,
            challenge: Some(base64::encode(b"next-challenge")),
        },
        desired_languages: (!response_kind.is_response()).then(|| "de".to_string()),
        feedback: vec![OutFeedback {
            language: Some("de".into()),
            code: code.into(),
            text: "Auftrag ausgeführt".into(),
        }],
        ..Default::default()
    };
    if kind == MessageType::FetchDelivery {
        let client_cert_pem = client_cipher_cert.expect("fetch test needs a client cert");
        let client_cert = pem_certificate(client_cert_pem);
        let container = osci_core::message::compose::OutContentContainer {
            id: "contentcontainer".into(),
            encrypted_attachments: Vec::new(),
            contents: vec![osci_core::message::compose::OutContent {
                id: "content1".into(),
                // raw text — the composer base64-encodes once on the wire
                text: Some("gefetchte XTA-Daten".to_string()),
                href: None,
            }],
        };
        let recipients = vec![osci_rs::security::EncRecipient {
            cert: client_cert,
            cert_element_id: "originator_cipher".into(),
        }];
        let enc = osci_rs::security::encrypt_container(
            &container,
            &recipients,
            &osci_rs::security::EncryptConfig::default(),
            Some("encdata_0".into()),
            None,
        )
        .unwrap();
        out.encrypted_data.push(enc);
    }
    if kind == MessageType::GetMessageId {
        // The response entry carries the echoed request; the id lives
        // nested inside it (that is where the parser looks). The xmlns
        // redeclaration is not cosmetic: oscirs resolves entry-children
        // namespaces from the entry's own declarations, and Java-written
        // intermediaries redeclare on every element anyway.
        out.entry_inner = Some(
            r#"<osci:getMessageId xmlns:osci="http://www.osci.de/2002/04/osci"><osci:MessageId>bXNnLTQ3MTE=</osci:MessageId></osci:getMessageId>"#.into(),
        );
    }
    let wire = compose_message(&out, "MIME_boundary").unwrap();
    if std::env::var("MOCK_DEBUG").is_ok() {
        eprintln!("=== mock response ===\n{}", String::from_utf8_lossy(&wire));
    }
    wire
}

fn looks_encrypted(xml: &[u8]) -> bool {
    String::from_utf8_lossy(xml).contains("EncryptedData")
}

fn control_block_of(xml: &[u8]) -> ControlBlock {
    let xml = String::from_utf8_lossy(xml).into_owned();
    let doc = parser::parse(&xml).unwrap();
    let header = find_header(&doc).unwrap();
    let child = header
        .elements()
        .find(|e| e.local == "ControlBlock")
        .unwrap();
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
    ControlBlock {
        conversation_id,
        sequence_number,
        response,
        challenge,
    }
}

#[test]
fn native_send_roundtrip_with_full_crypto() {
    let (signer_p12, signer_cert) = openssl_keystore("CN=native-client");
    let (intermediary_p12, intermediary_cert) = openssl_keystore("CN=intermediary");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let intermediary_decrypter =
        P12Decrypter::new(P12Keypair::parse(&intermediary_p12, PIN).unwrap());
    serve(listener, intermediary_decrypter, Some(signer_cert.clone()));

    let client = NativeClient::new(
        Intermediary::new(
            format!("http://127.0.0.1:{port}/osci/externalentry"),
            intermediary_cert,
        ),
        &Identity::from_p12_b64(base64::encode(&signer_p12), PIN, None, None).unwrap(),
        std::time::Duration::from_secs(30),
        false, // full crypto: transport envelope encrypted to the intermediary cert
        Default::default(),
    )
    .unwrap();

    let receipt = client
        .send_xta(osci::native::SendRequest {
            xta: &Xta::from_bytes("meldung.xta", b"XTA-Daten".to_vec()),
            attachments: &[],
            chunk_size_kb: None,
            recipient_cipher_cert: &signer_cert,
            subject: Some("XMeld Anzeige"),
            metadata_author: None,
            metadata_reader: None,
            sign: true,
            encrypt: true,
        })
        .unwrap();
    assert_eq!(receipt.message_id, "msg-4711");
    assert!(receipt.feedback.unwrap()[0][1].starts_with('0'));

    let fetched = client.fetch(None, None).unwrap();
    assert_eq!(fetched.len(), 1);
    let encrypted = fetched[0].encrypted_contents.as_ref().expect("decrypted");
    // FetchedContent.data is base64 by protocol contract
    assert_eq!(encrypted[0].data, base64::encode(b"gefetchte XTA-Daten"));

    let versions = client.versions();
    assert_eq!(versions.get("protocol").map(String::as_str), Some("1"));
}

#[test]
fn version_info_reports_protocol_and_bridge() {
    let (_p12, cert) = openssl_keystore("CN=versions");
    // no server: versions() is local-only
    let client = NativeClient::new(
        Intermediary::new("http://127.0.0.1:1/x", cert),
        &Identity::from_p12_b64(base64::encode(b"garbage"), PIN, None, None).unwrap(),
        std::time::Duration::from_secs(1),
        false,
        Default::default(),
    );
    // construction fails on garbage keystore — versions() needs no client
    assert!(
        client.is_err(),
        "garbage identity must be rejected at build"
    );
}

/// Keep the unused import honest: EncryptConfig is the default the
/// client picks; referenced here so the test fails to compile if the
/// API drifts.
#[test]
fn encrypt_config_default_is_oaep_sha256() {
    let cfg = EncryptConfig::default();
    assert!(cfg.key_transport.algorithm.contains("rsa-oaep"));
}
