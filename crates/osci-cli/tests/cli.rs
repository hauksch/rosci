//! CLI behavior tests via assert_cmd, run against a scripted in-process
//! intermediary (the Rust counterpart of the old bash fake bridge) —
//! argument plumbing, output shape and exit codes. The Java mock
//! intermediary and the live interop suite star in e2e/interop.

// Tests panic on broken assumptions — that is the job description.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;

use assert_cmd::Command;
use osci_core::helper::base64;
use osci_core::message::compose::{
    compose_message, OutContent, OutContentContainer, OutFeedback, OutMessage, OutProcessCard,
    OutProcessCardBundle,
};
use osci_core::soap::{find_header, ControlBlock};
use osci_core::xml::parser;
use osci_rs::security::{encrypt_container, EncryptConfig};
use osci_rs::Certificate;
use osci_rs::{MessageType, StoredMessage};
use predicates::prelude::*;
use predicates::str as predicate_str;

const PIN: &str = "123456";
const MESSAGE_ID_B64: &str = "ZmFrZS1tc2ctNDI="; // "fake-msg-42"

fn rosci() -> Command {
    Command::cargo_bin("rosci").unwrap()
}

/// openssl RSA-2048 keystore + certificate PEM (leaked tempdir: the files
/// must outlive the p12 read; a handful per test binary is fine).
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
            "openssl failed: {}",
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
    std::mem::forget(dir);
    (
        std::fs::read(&p12).unwrap(),
        std::fs::read_to_string(&cert).unwrap(),
    )
}

fn pem_certificate(pem: &str) -> Certificate {
    let start = pem.find("-----BEGIN CERTIFICATE-----").unwrap() + 27;
    let after = &pem[start..];
    let end = after.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    Certificate::from_der(&base64::decode(&b64).unwrap()).unwrap()
}

/// The scripted intermediary: control-block echo + positive feedback for
/// every kind the CLI drives; fetch returns an encrypted container,
/// process-card returns a Laufzettel.
fn serve(listener: TcpListener, intermediary_decrypter: (Vec<u8>, String), client_cert: String) {
    std::thread::spawn(move || {
        let decrypter = osci::p12::P12Decrypter::new(
            osci::p12::P12Keypair::parse(&intermediary_decrypter.0, &intermediary_decrypter.1)
                .unwrap(),
        );
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
                if let Some(len) = content_length(&request) {
                    if request.len() >= len {
                        break;
                    }
                }
            }
            let body = body_of(&request).to_vec();
            let response = handle(&body, &decrypter, &client_cert);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&response).unwrap();
        }
    });
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

fn handle(body: &[u8], decrypter: &osci::p12::P12Decrypter, client_cert_pem: &str) -> Vec<u8> {
    let stored = StoredMessage::load(body).unwrap();
    let xml = if looks_encrypted(&stored.xml) {
        let like = osci_rs::security::StoredMessageLike {
            xml: &stored.xml,
            attachments: &stored.attachments,
        };
        let inner = osci_rs::security::decrypt_transport_message(&like, &[decrypter])
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
        other => panic!("mock intermediary cannot handle {other:?}"),
    };

    let mut out = OutMessage {
        kind: Some(response_kind),
        control_block: ControlBlock {
            conversation_id: request_block.conversation_id,
            sequence_number: request_block.sequence_number.or(Some(0)),
            response: request_block.challenge,
            challenge: Some(base64::encode(b"next-challenge")),
        },
        desired_languages: Some("de".into()),
        feedback: vec![OutFeedback {
            language: Some("de".into()),
            code: code.into(),
            text: "Auftrag ausgeführt".into(),
        }],
        ..Default::default()
    };
    match kind {
        MessageType::GetMessageId => {
            // echoed request carries the id; xmlns redeclared because
            // oscirs resolves entry-children from the entry's own bindings
            out.entry_inner = Some(format!(
                r#"<osci:getMessageId xmlns:osci="http://www.osci.de/2002/04/osci"><osci:MessageId>{MESSAGE_ID_B64}</osci:MessageId></osci:getMessageId>"#
            ));
        }
        MessageType::FetchDelivery => {
            let client_cert = pem_certificate(client_cert_pem);
            let container = OutContentContainer {
                id: "contentcontainer".into(),
                contents: vec![OutContent {
                    id: "content1".into(),
                    // raw text — the composer base64-encodes once
                    text: Some("<XTA>gefetcht</XTA>".to_string()),
                    href: None,
                }],
            };
            let recipients = vec![osci_rs::security::EncRecipient {
                cert: client_cert,
                cert_element_id: "originator_cipher".into(),
            }];
            let enc = encrypt_container(
                &container,
                &recipients,
                &EncryptConfig::default(),
                Some("encdata_0".into()),
                None,
            )
            .unwrap();
            out.encrypted_data.push(enc);
        }
        MessageType::FetchProcessCard => {
            out.process_card_bundles = vec![OutProcessCardBundle {
                message_id: Some("fake-msg-42".into()),
                process_cards: vec![OutProcessCard {
                    creation: Some(
                        chrono::DateTime::parse_from_rfc3339("2026-09-29T10:00:00Z")
                            .unwrap()
                            .with_timezone(&chrono::Utc),
                    ),
                    forwarding: None,
                    reception: None,
                    subject: Some("XMeld".into()),
                }],
            }];
        }
        _ => {}
    }
    compose_message(&out, "MIME_boundary").unwrap()
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

/// One keystore pair + the scripted intermediary; returns (tempdir with
/// the fixture files, the server-side decrypter material).
fn native_env() -> (tempfile::TempDir, (Vec<u8>, String)) {
    let (client_p12, client_cert) = openssl_keystore("CN=cli-client");
    let (intermediary_p12, intermediary_cert) = openssl_keystore("CN=intermediary");

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("client.p12"), &client_p12).unwrap();
    std::fs::write(dir.path().join("intermediary.cer"), &intermediary_cert).unwrap();
    std::fs::write(dir.path().join("recipient.cer"), &intermediary_cert).unwrap();
    std::fs::write(dir.path().join("meldung.xta"), b"<XTA>anzeige</XTA>").unwrap();
    std::fs::write(
        dir.path().join("dvdv.json"),
        r#"[{"org_key":"0241100012345","name":"Testamt Musterstadt",
             "intermediary_url":"https://ks.test/entry",
             "intermediary_cipher_cert":"aWtz","recipient_cipher_cert":"ZW1wZmQ="}]"#,
    )
    .unwrap();

    // the intermediary's cert doubles as the recipient cert: same stack,
    // and the mock only needs its own decrypter for the transport envelope
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    serve(
        listener,
        (intermediary_p12.clone(), PIN.to_string()),
        client_cert,
    );

    std::fs::write(
        dir.path().join("endpoint.txt"),
        format!("http://127.0.0.1:{port}/osci/externalentry"),
    )
    .unwrap();
    (dir, (intermediary_p12, PIN.to_string()))
}

#[test]
fn help_works() {
    rosci()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate_str::contains("curl of OSCI"));
}

#[test]
fn root_help_lists_exit_codes() {
    let output = Command::new(env!("CARGO_BIN_EXE_rosci"))
        .arg("--help")
        .output()
        .expect("run rosci --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Exit codes"), "stdout: {stdout}");
}

#[test]
fn version_prints_local_and_native_stack() {
    rosci()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate_str::contains("rosci").and(predicate_str::contains("oscirs")));
}

#[test]
fn send_with_cert_recipient_prints_message_id() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate_str::contains("fake-msg-42").and(predicate_str::contains("accepted")));
}

#[test]
fn send_json_output_is_parseable() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    let out = rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .arg("--json")
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["message_id"], "fake-msg-42");
}

#[test]
fn send_missing_pin_is_exit_2() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env_remove("OSCI_CERT_PIN")
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn send_missing_xta_file_is_exit_2() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    rosci()
        .arg("send")
        .arg("gibt-es-nicht.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn send_stdin_dash_works() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    rosci()
        .arg("send")
        .arg("-")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .write_stdin("<XTA>von stdin</XTA>")
        .assert()
        .success()
        .stdout(predicate_str::contains("fake-msg-42"));
}

#[test]
fn bad_to_spec_is_exit_2() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "telefon:040-123456"])
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn dvdv_unknown_org_is_exit_3() {
    let (dir, _dec) = native_env();
    rosci()
        .arg("dvdv")
        .arg("find")
        .args(["--org", "0815"])
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(3);
}

#[test]
fn dvdv_find_prints_entry() {
    let (dir, _dec) = native_env();
    rosci()
        .arg("dvdv")
        .arg("find")
        .args(["--org", "0241100012345"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(
            predicate_str::contains("Testamt Musterstadt")
                .and(predicate_str::contains("https://ks.test/entry")),
        );
}

#[test]
fn fetch_writes_files() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    let out_dir = dir.path().join("post");
    let output = rosci()
        .arg("fetch")
        .arg("--all")
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .args(["--out", out_dir.to_str().unwrap()])
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .output()
        .unwrap();
    eprintln!(
        "fetch status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let written = std::fs::read_dir(&out_dir)
        .expect("out dir exists")
        .filter_map(|e| e.ok())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        written
            .iter()
            .any(|(_, bytes)| bytes == b"<XTA>gefetcht</XTA>"),
        "decoded content must be written; got {written:?}"
    );
}

#[test]
fn fetch_needs_selection_is_exit_2() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    rosci()
        .arg("fetch")
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn status_prints_laufzettel() {
    let (dir, _dec) = native_env();
    let endpoint = std::fs::read_to_string(dir.path().join("endpoint.txt")).unwrap();
    rosci()
        .arg("status")
        .arg("fake-msg-42")
        .args(["--intermediary", endpoint.trim()])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", PIN)
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate_str::contains("message_id").and(predicate_str::contains("fake-msg-42")));
}
