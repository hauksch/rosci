//! Interop: the real `rosci` binary + real bridge jar against the one
//! sanctioned remote endpoint — Governikus' public OSCI-Manager test
//! intermediary (gov.test.osci.de), the software many production Verbünde
//! run. Evidence base and ground rules: docs/TEST-INFRASTRUCTURE.md.
//!
//! Ground rules, in short:
//! * Opt-in only: tests run when `ROSCI_INTEROP=1` is set (`make interop`).
//!   Plain `cargo test` / `make test` skip at zero cost and touch no network.
//! * Functional tests only — the operator forbids load tests and guarantees
//!   no availability. An unreachable endpoint skips instead of failing.
//! * Identity: the library's public demo keystores (Governikus, PIN "123456",
//!   published in osci-bib-java at tag 2.6.1). The intermediary rejects
//!   self-signed senders (feedback code 3707), so generated identities are
//!   refused by policy. The DOI test certificate can be exercised through
//!   `ROSCI_INTEROP_CERT` + `ROSCI_INTEROP_CERT_PIN` when one is available.
//! * `status`/`fetch` against this instance are expected rejections (it
//!   keeps no client postboxes) — asserted as the loud, structured failures
//!   they are, which exercises live feedback mapping in the bargain.

use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use sha2::{Digest, Sha256};

const INTERMEDIARY: &str = "http://gov.test.osci.de/osci-manager-entry/externalentry";
const DEMO_PIN: &str = "123456";
const FIXTURE_DIR: &str = "crates/osci-cli/tests/fixtures/interop";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join(FIXTURE_DIR).join(name)
}

fn which_java() -> Option<String> {
    ["java", "/usr/bin/java"]
        .iter()
        .find(|c| Command::new(c).arg("-version").output().is_ok())
        .map(|c| c.to_string())
}

fn interop_enabled() -> bool {
    std::env::var("ROSCI_INTEROP").is_ok_and(|v| v == "1")
}

fn endpoint_reachable() -> bool {
    let mut addrs = match ("gov.test.osci.de", 80).to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return false,
    };
    addrs.any(|a| TcpStream::connect_timeout(&a, Duration::from_secs(5)).is_ok())
}

/// The fixtures are Governikus' published demo material — pinned by
/// SHA256SUMS so silent upstream rotation fails here, loudly, instead of
/// producing inexplicable intermediary rejections two years from now.
fn verify_fixtures() {
    let sums = fs::read_to_string(fixture("SHA256SUMS"))
        .expect("read interop SHA256SUMS (fixtures missing or incomplete)");
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (expected, name) = line
            .split_once(char::is_whitespace)
            .expect("SHA256SUMS line shape");
        let name = name.trim_start();
        let bytes = fs::read(fixture(name)).expect("read interop fixture");
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            digest, expected,
            "interop fixture {name} does not match SHA256SUMS — re-pin after checking docs/TEST-INFRASTRUCTURE.md"
        );
    }
}

/// Skip gate: returns `None` when the test must not run. Never fails on
/// environment problems — that is the operator's availability deal taken
/// seriously. Fixture tampering is the exception: that fails, loudly.
fn gate() -> Option<()> {
    if !interop_enabled() {
        eprintln!("interop: skipping (ROSCI_INTEROP != 1)");
        return None;
    }
    if !endpoint_reachable() {
        eprintln!("interop: skipping (gov.test.osci.de unreachable — no availability guarantee)");
        return None;
    }
    if which_java().is_none() {
        eprintln!("interop: skipping (no java on PATH)");
        return None;
    }
    let jar = repo_root().join("java/osci-bridge/target/osci-bridge.jar");
    if !jar.is_file() {
        eprintln!("interop: skipping (bridge jar missing — run make build)");
        return None;
    }
    verify_fixtures();
    Some(())
}

fn rosci() -> AssertCommand {
    let mut cmd = AssertCommand::cargo_bin("rosci").unwrap();
    cmd.env(
        "OSCI_BRIDGE_JAR",
        repo_root().join("java/osci-bridge/target/osci-bridge.jar"),
    )
    .timeout(Duration::from_secs(120));
    cmd
}

/// A send command against the test intermediary with the given identity.
/// Transport encryption and signatures stay ON unless the caller says
/// otherwise — that is the point of interop.
#[allow(clippy::too_many_arguments)]
fn send_cmd(
    subject: &str,
    payload: &Path,
    attachments: &[PathBuf],
    intermediary_cert: &Path,
    cert: &Path,
    decrypter: Option<&Path>,
    pin: &str,
) -> AssertCommand {
    let mut cmd = rosci();
    cmd.arg("send").arg(payload);
    for a in attachments {
        cmd.arg("--attachment").arg(a);
    }
    cmd.arg("--intermediary")
        .arg(INTERMEDIARY)
        .arg("--intermediary-cert")
        .arg(intermediary_cert)
        .arg("--cert")
        .arg(cert);
    if let Some(d) = decrypter {
        cmd.arg("--decrypter-cert").arg(d);
    }
    cmd.arg("--pin")
        .arg(pin)
        .arg("--to")
        .arg(format!("cert:{}", fixture("bob_cipher_4096.pem").display()))
        .arg("--subject")
        .arg(subject)
        .arg("--json");
    cmd
}

fn unique_subject(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("rosci-interop-{tag}-{}-{nanos}", std::process::id())
}

fn write_payload() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rosci-interop-{}-{}.xta",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::write(
        &path,
        format!("rosci interop probe {}\n", unique_subject("payload")),
    )
    .expect("write interop payload");
    path
}

/// A fetch command against the test intermediary, authenticated as the
/// given identity. `--message-id` is the deterministic selection; `--all`
/// is spec §6.6.9 rule 3 („oldest pending delivery") and works, but bob's
/// postbox on this public instance is shared with other testers — only
/// by-id assertions may be byte-exact.
fn fetch_cmd(
    message_id: &str,
    out_dir: &Path,
    cert: &Path,
    decrypter: &Path,
    pin: &str,
) -> AssertCommand {
    let mut cmd = rosci();
    cmd.args(["fetch", "--message-id", message_id, "--out"])
        .arg(out_dir)
        .args([
            "--intermediary",
            INTERMEDIARY,
            "--intermediary-cert",
            fixture("osci_manager_cipher_4096.pem").to_str().unwrap(),
        ])
        .arg("--cert")
        .arg(cert)
        .arg("--decrypter-cert")
        .arg(decrypter)
        .args(["--pin", pin, "--json"]);
    cmd
}

/// The happy path, twice over: a foreign, production-grade intermediary
/// accepts our store delivery and signs its response — which our automatic
/// verification (de.osci library) accepts. `response_signed: true` is the
/// whole assertion chain in one boolean: envelope crypto to the live
/// OSCI-Manager key, dialog handling, and RSA-PSS response verification.
#[test]
fn send_secure_delivery_gets_signed_response() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    let subject = unique_subject("secure");
    let output = send_cmd(
        &subject,
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    assert_eq!(json["response_signed"], true, "response must be signed");
    assert!(
        json["message_id"].as_str().is_some_and(|s| !s.is_empty()),
        "intermediary must assign a message id: {json}"
    );
    let _ = fs::remove_file(&payload);
}

/// Content encryption is an end-to-end concern; the intermediary accepts
/// store deliveries whose payload is not content-encrypted (transport
/// encryption and response signatures remain on).
#[test]
fn send_without_content_encryption_is_accepted() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    let output = send_cmd(
        &unique_subject("noenc"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .arg("--no-encrypt")
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    assert_eq!(json["response_signed"], true);
    let _ = fs::remove_file(&payload);
}

/// Unsigned store deliveries are accepted as well; the intermediary still
/// signs its response — provenance of the *response* does not depend on
/// our signature.
#[test]
fn send_without_signature_is_accepted() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    let output = send_cmd(
        &unique_subject("nosign"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .arg("--no-sign")
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    assert_eq!(json["response_signed"], true);
    let _ = fs::remove_file(&payload);
}

/// This manager retains no process cards for the ids it assigns (status)
/// and alice — who only ever sends — has an empty postbox (fetch --all,
/// feedback 9803 „keine Zustellung vorhanden"). Both must surface as the
/// structured rejections they are (exit 4, mapped feedback) — not hangs,
/// not silent nonsense. Codes deliberately not asserted (the OSCI-Manager
/// may phrase them freely).
#[test]
fn status_and_fetch_are_structured_rejections() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    let output = send_cmd(
        &unique_subject("status"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    let message_id = json["message_id"].as_str().expect("message id").to_owned();

    let intermed_pem = fixture("osci_manager_cipher_4096.pem");
    let alice_p12 = fixture("alice_signature_4096.p12");
    let conn = [
        "--intermediary",
        INTERMEDIARY,
        "--intermediary-cert",
        intermed_pem.to_str().unwrap(),
        "--cert",
        alice_p12.to_str().unwrap(),
        "--pin",
        DEMO_PIN,
    ];

    rosci()
        .args(["status", &message_id])
        .args(conn)
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("intermediary rejected"));

    rosci()
        .args(["fetch", "--all", "--out"])
        .arg(std::env::temp_dir().join(format!("rosci-interop-fetch-{}", std::process::id())))
        .args(conn)
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("intermediary rejected"));
    let _ = fs::remove_file(&payload);
}

/// Encrypting the transport envelope to the WRONG intermediary key must
/// fail loudly (exit 4) — against a live intermediary this is the closest
/// legal thing to a MITM drill.
#[test]
fn wrong_intermediary_cert_fails_loudly() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    // Exit 4 (transport/OSCI), and an actual human-readable diagnosis —
    // never silence, never a panic.
    let _ = send_cmd(
        &unique_subject("neg"),
        &payload,
        &[],
        &fixture("bob_cipher_4096.pem"), // the WRONG intermediary key on purpose
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .assert()
    .failure()
    .code(4)
    .stderr(predicate::str::is_empty().not());
    let _ = fs::remove_file(&payload);
}

/// The crown jewel: the full postbox round trip on live crypto. Alice
/// sends a content-encrypted store delivery addressed to bob; bob fetches
/// it by message id (the selection real OSCI-Managers honor) and the
/// bridge decrypts it with bob's cipher key. Byte-exactness of the
/// payload proves content encryption, postbox storage, fetch delivery
/// and decryption in one assertion chain.
#[test]
fn fetch_delivers_the_stored_message_to_its_recipient() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    let sent = fs::read(&payload).unwrap();
    let output = send_cmd(
        &unique_subject("fetch"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    let message_id = json["message_id"].as_str().expect("message id").to_owned();

    let out_dir = tempfile::tempdir().expect("fetch out dir");
    let fetch_out = fetch_cmd(
        &message_id,
        out_dir.path(),
        &fixture("bob_signature_4096.p12"),
        &fixture("bob_cipher_4096.p12"),
        DEMO_PIN,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let fetched: serde_json::Value = serde_json::from_slice(&fetch_out).expect("valid JSON result");
    let messages = fetched.as_array().expect("fetch yields a JSON array");
    assert_eq!(
        messages.len(),
        1,
        "exactly the one stored message: {fetched}"
    );
    let data = messages[0]["encrypted_contents"][0]["data"]
        .as_str()
        .expect("fetched encrypted content with data");
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data)
        .expect("fetched content is base64");
    assert_eq!(decoded, sent, "byte-exact round trip through the postbox");
    let _ = fs::remove_file(&payload);
}

/// Postbox isolation: the same message id fetched by a party that is not
/// the recipient is a clean, structured rejection — not silence, not
/// someone else's message. (Live: 9803 „No or wrong messageId given!“,
/// which this manager uses for both unknown ids and foreign postboxes.)
#[test]
fn fetch_by_a_party_without_the_message_is_rejected() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    let output = send_cmd(
        &unique_subject("isolation"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    let message_id = json["message_id"].as_str().expect("message id").to_owned();

    let out_dir = tempfile::tempdir().expect("fetch out dir");
    let _ = fetch_cmd(
        &message_id,
        out_dir.path(),
        &fixture("alice_signature_4096.p12"),
        &fixture("carol_cipher_4096.p12"),
        DEMO_PIN,
    )
    .assert()
    .failure()
    .code(4)
    .stderr(predicate::str::contains("intermediary rejected"));
    let _ = fs::remove_file(&payload);
}

/// `fetch --all` is spec §6.6.9 rule 3 („Ist weder osci:MessageId noch
/// osci:ReceptionOfDelivery vorhanden, so wird die Zustellung mit dem
/// ältesten Zeitpunkt der Einreichung … zurückgesendet") — it delivers
/// the oldest pending message, and this manager appends the §6.6.10
/// warning 3800 „weitere Zustellungen liegen vor", which must NOT fail
/// the request (spec §5: a warning means the order was executed). Bob's
/// postbox on this public instance is shared with other testers, so the
/// contents are whatever is oldest for bob — assertions stay structural.
#[test]
fn fetch_all_delivers_pending_messages_as_a_warning_not_an_error() {
    let Some(()) = gate() else { return };
    // Seed bob's postbox so the shared postbox cannot be empty.
    let payload = write_payload();
    send_cmd(
        &unique_subject("all"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .assert()
    .success();

    let out_dir = tempfile::tempdir().expect("fetch out dir");
    let mut cmd = rosci();
    cmd.args(["fetch", "--all", "--out"])
        .arg(out_dir.path())
        .args([
            "--intermediary",
            INTERMEDIARY,
            "--intermediary-cert",
            fixture("osci_manager_cipher_4096.pem").to_str().unwrap(),
        ])
        .arg("--cert")
        .arg(fixture("bob_signature_4096.p12"))
        .arg("--decrypter-cert")
        .arg(fixture("bob_cipher_4096.p12"))
        .args(["--pin", DEMO_PIN, "--json"]);
    let fetch_out = cmd.assert().success().get_output().stdout.clone();
    let fetched: serde_json::Value = serde_json::from_slice(&fetch_out).expect("valid JSON result");
    let messages = fetched.as_array().expect("fetch yields a JSON array");
    assert!(
        !messages.is_empty(),
        "at least the seeded message must arrive"
    );
    use base64::Engine as _;
    for m in messages {
        for key in ["contents", "encrypted_contents"] {
            if let Some(items) = m[key].as_array() {
                for c in items {
                    base64::engine::general_purpose::STANDARD
                        .decode(c["data"].as_str().expect("content carries data"))
                        .expect("delivered content is valid base64");
                }
            }
        }
    }
    let _ = fs::remove_file(&payload);
}

/// §7 item 3, proven live: an additional content part rides the same
/// Zustellung through content encryption and the postbox, and comes back
/// byte-exact when the recipient fetches by id.
#[test]
fn attachments_round_trip_through_the_postbox() {
    let Some(()) = gate() else { return };
    let payload = write_payload();
    let attachment = std::env::temp_dir().join(format!(
        "rosci-interop-attachment-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let attachment_name = attachment
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Deliberately not valid UTF-8: attachments are opaque bytes.
    let attachment_bytes: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
    fs::write(&attachment, &attachment_bytes).unwrap();

    let output = send_cmd(
        &unique_subject("attachment"),
        &payload,
        std::slice::from_ref(&attachment),
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    let message_id = json["message_id"].as_str().expect("message id").to_owned();

    let out_dir = tempfile::tempdir().expect("fetch out dir");
    let fetch_out = fetch_cmd(
        &message_id,
        out_dir.path(),
        &fixture("bob_signature_4096.p12"),
        &fixture("bob_cipher_4096.p12"),
        DEMO_PIN,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let fetched: serde_json::Value = serde_json::from_slice(&fetch_out).expect("valid JSON result");
    let messages = fetched.as_array().expect("fetch yields a JSON array");
    assert_eq!(messages.len(), 1, "exactly the one stored message");
    let contents = messages[0]["encrypted_contents"]
        .as_array()
        .expect("encrypted contents");
    assert!(
        contents.len() >= 2,
        "main content + attachment must both arrive: {fetched}"
    );
    let attachment_part = contents
        .iter()
        .find(|c| c["filename"].as_str() == Some(attachment_name.as_str()))
        .unwrap_or_else(|| panic!("attachment must arrive under its refId: {fetched}"));
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(attachment_part["data"].as_str().expect("attachment data"))
        .expect("attachment is base64");
    assert_eq!(
        decoded, attachment_bytes,
        "attachment round trip is byte-exact"
    );
    let _ = fs::remove_file(&payload);
    let _ = fs::remove_file(&attachment);
}

/// §7 item 1, proven live: EFFI chunked transfer. A multi-MB payload is
/// serialized into one StoreDelivery, split into PartialStoreDelivery
/// chunks (KB per chunk, opt-in) and reassembled by the manager under the
/// original message id — the recipient then picks it up with a PLAIN
/// fetch, byte-exact. (The manager's partial-fetch variant answered 9811
/// „No specified error" and is not needed against this instance; the
/// bridge keeps it for intermediaries that only serve chunks.) This
/// closes the one spec-relevant gap the compliance matrix started with.
#[test]
fn chunked_send_round_trips_through_the_postbox() {
    let Some(()) = gate() else { return };
    let payload = std::env::temp_dir().join(format!(
        "rosci-interop-chunked-{}-{}.xta",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    // ~3 MB, deliberately binary (no XML sniff to argue with).
    let payload_bytes: Vec<u8> = (0..3_000_000usize).map(|i| (i % 251) as u8).collect();
    fs::write(&payload, &payload_bytes).unwrap();

    let output = send_cmd(
        &unique_subject("chunked"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        &fixture("alice_signature_4096.p12"),
        Some(&fixture("carol_cipher_4096.p12")),
        DEMO_PIN,
    )
    .args(["--chunk-size-kb", "1024"])
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    let message_id = json["message_id"].as_str().expect("message id").to_owned();

    let out_dir = tempfile::tempdir().expect("fetch out dir");
    let mut cmd = rosci();
    cmd.args(["fetch", "--message-id", &message_id, "--out"])
        .arg(out_dir.path())
        .args([
            "--intermediary",
            INTERMEDIARY,
            "--intermediary-cert",
            fixture("osci_manager_cipher_4096.pem").to_str().unwrap(),
        ])
        .arg("--cert")
        .arg(fixture("bob_signature_4096.p12"))
        .arg("--decrypter-cert")
        .arg(fixture("bob_cipher_4096.p12"))
        .args(["--pin", DEMO_PIN, "--json"]);
    let fetch_out = cmd.assert().success().get_output().stdout.clone();
    let fetched: serde_json::Value = serde_json::from_slice(&fetch_out).expect("valid JSON result");
    let messages = fetched.as_array().expect("fetch yields a JSON array");
    assert_eq!(messages.len(), 1, "exactly the one stored message");
    let contents = messages[0]["encrypted_contents"]
        .as_array()
        .expect("encrypted contents");
    use base64::Engine as _;
    let delivered = contents
        .iter()
        .find_map(|c| {
            c["data"]
                .as_str()
                .and_then(|d| base64::engine::general_purpose::STANDARD.decode(d).ok())
        })
        .expect("chunked message must arrive with decodable content");
    assert_eq!(delivered, payload_bytes, "chunked round trip is byte-exact");
    let _ = fs::remove_file(&payload);
}

/// Rung two: a real DOI test certificate (TeleSec DOI-CA, sub-domain
/// „DOI-OSCI") instead of the demo identity — the open item from
/// docs/TEST-INFRASTRUCTURE.md. Runs only when the certificate is
/// provided via the environment; obtaining one is documented there.
#[test]
fn doi_identity_is_accepted() {
    let Some(()) = gate() else { return };
    let Ok(cert) = std::env::var("ROSCI_INTEROP_CERT") else {
        eprintln!("interop: skipping DOI rung (ROSCI_INTEROP_CERT not set)");
        return;
    };
    let pin = std::env::var("ROSCI_INTEROP_CERT_PIN")
        .expect("ROSCI_INTEROP_CERT_PIN with ROSCI_INTEROP_CERT");
    let payload = write_payload();
    let output = send_cmd(
        &unique_subject("doi"),
        &payload,
        &[],
        &fixture("osci_manager_cipher_4096.pem"),
        Path::new(&cert),
        None, // signer fallback: the DOI bundle carries the cipher key too
        &pin,
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON result");
    assert_eq!(json["response_signed"], true);
    let _ = fs::remove_file(&payload);
}
