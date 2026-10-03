//! End-to-end: the real `osci` binary + the real Java bridge jar + the
//! mock intermediary on localhost. No internet, no traces, no mercy.
//!
//! Skips gracefully when java/openssl or the jars are unavailable (host
//! development); inside the builder container `make test` provides all of
//! them. Network endpoints touched: 127.0.0.1 only.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct MockIntermediary {
    child: Child,
    port: u16,
}

impl MockIntermediary {
    fn start(dump_dir: &Path) -> Option<Self> {
        Self::start_with(dump_dir, &[])
    }

    fn start_with(dump_dir: &Path, extra_args: &[&str]) -> Option<Self> {
        let jar = repo_root().join("java/osci-mock/target/osci-mock.jar");
        if !jar.is_file() || which_java().is_none() {
            eprintln!("e2e: skipping (mock jar or java missing)");
            return None;
        }
        let port = free_port();
        let mut cmd = Command::new(which_java().unwrap());
        cmd.arg("-jar")
            .arg(&jar)
            .arg(port.to_string())
            .arg(dump_dir.to_str().unwrap());
        // With the intermediary keys on board, the mock decrypts
        // transport-encrypted requests, encrypts responses back, and signs
        // every response like a proper intermediary.
        let pki = dump_dir.parent().map(|p| p.to_path_buf());
        let key = pki.as_ref().map(|p| p.join("intermed-cipher.key"));
        if let Some(key) = key.filter(|k| k.is_file()) {
            cmd.arg("--key").arg(key);
        }
        let sign_key = pki.as_ref().map(|p| p.join("intermed-sign.key"));
        let sign_cert = pki.as_ref().map(|p| p.join("intermed-sign.pem"));
        if let Some(k) = sign_key.filter(|k| k.is_file()) {
            cmd.arg("--sign-key").arg(k).arg("--sign-cert").arg(
                sign_cert
                    .filter(|c| c.is_file())
                    .expect("sign cert next to sign key"),
            );
        }
        cmd.args(extra_args);
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn mock intermediary");

        // Wait for READY with a deadline — a JVM that never wakes up is a
        // test failure, not a coffee break.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut ready = String::new();
        {
            let stdout = child.stdout.take().expect("piped stdout");
            let mut reader = BufReader::new(stdout);
            loop {
                if std::time::Instant::now() > deadline {
                    panic!("mock intermediary did not report READY in time");
                }
                ready.clear();
                if reader.read_line(&mut ready).unwrap_or(0) == 0 {
                    panic!("mock intermediary exited before READY");
                }
                if ready.starts_with("READY") {
                    break;
                }
            }
        }
        Some(Self { child, port })
    }

    pub(crate) fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/osci-manager-entry/externalentry",
            self.port
        )
    }
}

impl Drop for MockIntermediary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn which_java() -> Option<String> {
    ["java", "/usr/bin/java"]
        .iter()
        .find(|c| Command::new(c).arg("-version").output().is_ok())
        .map(|c| c.to_string())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

struct E2e {
    workdir: PathBuf,
    _pki_cleanup: tempfile::TempDir,
}

impl E2e {
    fn setup() -> Option<(Self, MockIntermediary)> {
        let bridge_jar = repo_root().join("java/osci-bridge/target/osci-bridge.jar");
        if !bridge_jar.is_file() || which_java().is_none() {
            eprintln!("e2e: skipping (bridge jar or java missing)");
            return None;
        }
        if Command::new("openssl").arg("version").output().is_err() {
            eprintln!("e2e: skipping (openssl missing)");
            return None;
        }

        let pki_dir = tempfile::tempdir().expect("pki tempdir");
        let status = Command::new(repo_root().join("tests/gen-pki.sh"))
            .arg(pki_dir.path())
            .status()
            .expect("run gen-pki.sh");
        assert!(status.success(), "PKI generation failed");

        let dump_dir = pki_dir.path().join("dump");
        std::fs::create_dir_all(&dump_dir).unwrap();
        let mock = MockIntermediary::start(&dump_dir)?;

        // Working directory for the CLI: the PKI dir doubles as the cwd.
        let workdir = pki_dir.path().to_path_buf();
        let e2e = Self {
            workdir: workdir.clone(),
            _pki_cleanup: pki_dir,
        };

        // dvdv.json for the mock intermediary.
        let intermed_cert = std::fs::read_to_string(workdir.join("intermed-cipher.pem")).unwrap();
        let recipient_cert = std::fs::read_to_string(workdir.join("recipient-cipher.pem")).unwrap();
        let dvdv = serde_json::json!([{
            "org_key": "0241100012345",
            "name": "Mock-Empfaenger",
            "intermediary_url": mock.url(),
            "intermediary_cipher_cert": intermed_cert,
            "recipient_cipher_cert": recipient_cert,
        }]);
        std::fs::write(
            workdir.join("dvdv.json"),
            serde_json::to_vec_pretty(&dvdv).unwrap(),
        )
        .unwrap();

        std::fs::write(
            workdir.join("meldung.xta"),
            "<?xml version=\"1.0\"?><XTA><meldung>hallo behoerde</meldung></XTA>",
        )
        .unwrap();

        Some((e2e, mock))
    }

    fn rosci(&self) -> AssertCommand {
        let mut cmd = AssertCommand::cargo_bin("rosci").unwrap();
        cmd.env(
            "OSCI_BRIDGE_JAR",
            repo_root().join("java/osci-bridge/target/osci-bridge.jar"),
        )
        .env("OSCI_CERT_PIN", "testpin")
        .current_dir(&self.workdir);
        cmd
    }
}

#[test]
fn send_fetch_status_against_mock_intermediary() {
    let Some((e2e, _mock)) = E2e::setup() else {
        return;
    };

    // --- version handshake includes the jar fingerprint -----------------
    let version_out = e2e
        .rosci()
        .arg("version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let version_text = String::from_utf8_lossy(&version_out);
    assert!(
        version_text.lines().any(|l| {
            l.starts_with("jar_sha256") && l[l.find(' ').unwrap_or(0)..].trim().len() == 64
        }),
        "version must report a 64-hex jar fingerprint: {version_text}"
    );

    // --- send via DVDV resolution, full crypto path ---------------------
    let output = e2e
        .rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "dvdv:0241100012345"])
        .args(["--cert", "client-sign.p12"])
        .args(["--decrypter-cert", "client-cipher.p12"])
        .arg("--insecure-transport")
        .arg("--subject")
        .arg("e2e test sendung")
        .arg("--json")
        .timeout(Duration::from_secs(180))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: serde_json::Value = serde_json::from_slice(&output).expect("parse receipt json");
    let message_id = receipt["message_id"]
        .as_str()
        .expect("message id")
        .to_string();
    assert!(
        !message_id.is_empty(),
        "message id must not be empty: {message_id}"
    );

    // The mock dumped what actually crossed the wire: assert the store
    // delivery envelope carries the subject and the attachment reference —
    // and that the XTA itself is NOT plaintext (content encryption on).
    // Dumps are byte-exact (binary content-attachment parts included), so
    // everything is read lossily.
    let dump_dir = e2e.workdir.join("dump");
    let store_envelope = read_dump_lossy(
        &dump_dir
            .read_dir()
            .expect("dump dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| {
                std::fs::read(p)
                    .map(|c| String::from_utf8_lossy(&c).contains("storeDelivery"))
                    .unwrap_or(false)
            })
            .expect("store delivery dump"),
    );
    assert!(
        store_envelope.contains("e2e test sendung"),
        "subject must ride along"
    );
    assert!(
        store_envelope.contains("meldung.xta"),
        "attachment ref must ride along"
    );
    assert!(
        !store_envelope.contains("hallo behoerde"),
        "XTA content must be encrypted, not plaintext"
    );

    // --- status (process card / Laufzettel, now with real content) --------
    e2e.rosci()
        .arg("status")
        .arg(&message_id)
        .args(["--intermediary", &_mock_url_from_dvdv(&e2e)])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .args(["--decrypter-cert", "client-cipher.p12"])
        .arg("--insecure-transport")
        .timeout(Duration::from_secs(180))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("mock laufzettel")
                .and(predicate::str::contains("2026-09-30T08:15:00Z"))
                .and(predicate::str::contains(&message_id)),
        );

    // --- fetch: the mock serves one canned message with an attachment ----
    let fetched_dir = e2e.workdir.join("fetched");
    e2e.rosci()
        .arg("fetch")
        .arg("--all")
        .args(["--intermediary", &_mock_url_from_dvdv(&e2e)])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .args(["--decrypter-cert", "client-cipher.p12"])
        .args(["--out", fetched_dir.to_str().unwrap()])
        .arg("--insecure-transport")
        .timeout(Duration::from_secs(180))
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote"));

    // The attachment landed on disk, byte-honest.
    let fetched = std::fs::read(fetched_dir.join("mock-antwort.xta")).expect("fetched attachment");
    let fetched = String::from_utf8_lossy(&fetched);
    assert!(
        fetched.contains("die behoerde dankt"),
        "fetched XTA must carry the canned payload: {fetched}"
    );
    assert!(fetched.contains("<XTA"), "fetched XTA must be XML");

    // --- fetch --json: machine-readable shape with base64 content ---------
    let json_out = e2e
        .rosci()
        .arg("fetch")
        .arg("--all")
        .args(["--intermediary", &_mock_url_from_dvdv(&e2e)])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .args(["--decrypter-cert", "client-cipher.p12"])
        .arg("--json")
        .arg("--insecure-transport")
        .timeout(Duration::from_secs(180))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages: serde_json::Value = serde_json::from_slice(&json_out).expect("fetch json");
    let contents = messages[0]["contents"].as_array().expect("contents");
    assert!(
        !contents.is_empty(),
        "fetch json must carry content entries"
    );
    assert_eq!(
        contents[0]["filename"].as_str(),
        Some("mock-antwort.xta"),
        "attachment ref must map to the filename"
    );
    let data = contents[0]["data"].as_str().expect("base64 data");
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data)
        .expect("valid base64");
    assert!(String::from_utf8_lossy(&decoded).contains("die behoerde dankt"));

    // The encrypted twin: sealed with RSA-OAEP + AES-GCM to the client's
    // cipher certificate; the bridge must decrypt it with the fetch
    // identity's decrypter and expose it as encrypted_contents. It arrives
    // as its own message entry — find it structurally, not by index.
    let enc_msg = messages
        .as_array()
        .expect("messages array")
        .iter()
        .find(|m| {
            m["encrypted_contents"]
                .as_array()
                .is_some_and(|c| !c.is_empty())
        })
        .expect("one message with decrypted encrypted_contents");
    let encrypted = enc_msg["encrypted_contents"].as_array().unwrap();
    let enc_data = encrypted[0]["data"]
        .as_str()
        .expect("encrypted base64 data");
    let enc_decoded = base64::engine::general_purpose::STANDARD
        .decode(enc_data)
        .expect("valid base64");
    let enc_text = String::from_utf8_lossy(&enc_decoded);
    assert!(
        enc_text.contains("streng vertrauliche antwort"),
        "decrypted content must match the canned secret: {enc_text}"
    );
    // Inline content carries no filename — the container field marks it.
    assert_eq!(encrypted[0]["container"].as_str(), Some("encrypted"));
}

#[test]
fn send_with_transport_encryption_against_mock_intermediary() {
    let Some((e2e, _mock)) = E2e::setup() else {
        return;
    };
    let dump_dir = e2e.workdir.join("dump");

    // --- send WITHOUT --insecure-transport: full transport crypto --------
    // The XTA carries a recognizable marker that must never appear in the
    // raw packets, only inside the mock's decrypted inner envelopes.
    std::fs::write(
        e2e.workdir.join("geheim.xta"),
        "<?xml version=\"1.0\"?><XTA><meldung>streng geheime transportdaten</meldung></XTA>",
    )
    .unwrap();

    let output = e2e
        .rosci()
        .arg("send")
        .arg("geheim.xta")
        .args(["--to", "cert:recipient-cipher.pem"])
        .args(["--intermediary", &_mock_url_from_dvdv(&e2e)])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .args(["--decrypter-cert", "client-cipher.p12"])
        .arg("--subject")
        .arg("sichere sendung")
        .arg("--json")
        .timeout(Duration::from_secs(180))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: serde_json::Value = serde_json::from_slice(&output).expect("parse receipt json");
    let message_id = receipt["message_id"]
        .as_str()
        .expect("message id")
        .to_string();
    assert!(!message_id.is_empty(), "message id must not be empty");

    // --- every request must have crossed the wire encrypted ---------------
    let mut metas = 0;
    for entry in std::fs::read_dir(&dump_dir).unwrap().filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(n) = name
            .strip_prefix("request-")
            .and_then(|s| s.strip_suffix(".meta"))
        {
            let meta = std::fs::read_to_string(entry.path()).unwrap();
            assert!(
                meta.contains("transport_encrypted: true"),
                "request {n} was not transport-encrypted: {meta}"
            );
            metas += 1;
        }
    }
    assert!(metas >= 2, "expected at least 2 exchanges, saw {metas}");

    // --- the raw packets are ciphertext, not costume jewelry --------------
    // Find the storeDelivery exchange (getMessageId is N=1, storeDelivery N=2,
    // but assert structurally instead of trusting the sequence).
    let store_n = (1..=metas + 1).find(|n| {
        std::fs::read(dump_dir.join(format!("request-{n}.inner.xml")))
            .map(|b| {
                let s = String::from_utf8_lossy(&b);
                s.contains("storeDelivery")
            })
            .unwrap_or(false)
    });
    let Some(store_n) = store_n else {
        panic!("no decrypted storeDelivery envelope found in dumps");
    };

    let raw = String::from_utf8_lossy(
        &std::fs::read(dump_dir.join(format!("request-{store_n}.xml"))).unwrap(),
    )
    .into_owned();
    assert!(
        raw.contains("soapMessageEncrypted.xsd") && raw.contains("EncryptedKey"),
        "raw request must carry the transport-encryption markers"
    );
    for marker in [
        "sichere sendung",
        "streng geheime transportdaten",
        "storeDelivery",
        "getMessageId",
    ] {
        assert!(
            !raw.contains(marker),
            "raw transport-encrypted request leaks plaintext: {marker}"
        );
    }

    // --- ...and the mock really decrypted them ----------------------------
    let inner = String::from_utf8_lossy(
        &std::fs::read(dump_dir.join(format!("request-{store_n}.inner.xml"))).unwrap(),
    )
    .into_owned();
    assert!(
        inner.contains("storeDelivery"),
        "decrypted envelope must show storeDelivery"
    );
    assert!(
        inner.contains("sichere sendung"),
        "decrypted envelope must show the subject"
    );
    // Content-level encryption still applies inside the transport envelope:
    assert!(
        !inner.contains("streng geheime transportdaten"),
        "XTA content must be content-encrypted even inside the decrypted transport envelope"
    );

    // --- responses were encrypted too --------------------------------------
    let response = String::from_utf8_lossy(
        &std::fs::read(dump_dir.join(format!("response-{store_n}.xml"))).unwrap(),
    )
    .into_owned();
    assert!(
        response.contains("soapMessageEncrypted.xsd"),
        "response must be transport-encrypted"
    );
    assert!(
        !response.contains("die nachricht wurde entgegengenommen"),
        "encrypted response must not leak the plaintext feedback text"
    );

    // --- status over the encrypted transport (multi-exchange dialogue) ----
    // The canned Laufzettel must survive the encrypted pipe intact: the
    // client decrypted the response AND mapped the process card fields.
    e2e.rosci()
        .arg("status")
        .arg(&message_id)
        .args(["--intermediary", &_mock_url_from_dvdv(&e2e)])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .args(["--decrypter-cert", "client-cipher.p12"])
        .timeout(Duration::from_secs(180))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("mock laufzettel")
                .and(predicate::str::contains("2026-09-30T08:15:00Z")),
        );
}

fn _mock_url_from_dvdv(e2e: &E2e) -> String {
    let dvdv: serde_json::Value =
        serde_json::from_slice(&std::fs::read(e2e.workdir.join("dvdv.json")).unwrap()).unwrap();
    dvdv[0]["intermediary_url"]
        .as_str()
        .expect("url")
        .to_string()
}

/// Dumps are byte-exact — binary cipher parts make them invalid UTF-8,
/// so tests always read them lossily.
fn read_dump_lossy(path: &std::path::Path) -> String {
    String::from_utf8_lossy(&std::fs::read(path).unwrap()).into_owned()
}

#[test]
fn send_fails_cleanly_when_intermediary_is_down() {
    let Some((e2e, _mock)) = E2e::setup() else {
        return;
    };
    // Point at a closed port: the bridge must surface a transport error (4).
    e2e.rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "cert:recipient-cipher.pem"])
        .args([
            "--intermediary",
            &format!("http://127.0.0.1:{}/entry", free_port()),
        ])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .timeout(Duration::from_secs(120))
        .assert()
        .failure()
        .code(4);
}

#[test]
fn large_payload_flows_through_both_transports() {
    let Some((e2e, _mock)) = E2e::setup() else {
        return;
    };

    // ~2 MB of realistic XTA structure: enough to prove the MIME/streaming
    // path handles real payloads, small enough to keep the suite quick.
    // (A manual probe verified 5 MB through plain and fully-encrypted
    // transports alike — see docs/AUDIT.md.)
    let mut xml = String::from("<?xml version=\"1.0\"?><XTA>");
    let target = 2 * 1024 * 1024;
    let mut i = 0;
    while xml.len() < target {
        let marker = format!("<datensatz nr=\"{i:06}\">nutzdaten fuers amt</datensatz>");
        xml.push_str(&marker);
        i += 1;
    }
    xml.push_str("</XTA>");
    let big = e2e.workdir.join("gross.xta");
    std::fs::write(&big, xml).unwrap();
    assert!(
        big.metadata().unwrap().len() > 1_900_000,
        "payload must be ~2MB"
    );

    // Plain transport, no content crypto: maximum payload, minimum ceremony.
    e2e.rosci()
        .arg("send")
        .arg("gross.xta")
        .args(["--to", "cert:recipient-cipher.pem"])
        .args(["--intermediary", &_mock_url_from_dvdv(&e2e)])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .arg("--insecure-transport")
        .arg("--no-encrypt")
        .arg("--no-sign")
        .timeout(Duration::from_secs(300))
        .assert()
        .success();

    // Full stack: transport encryption + content signing + encryption.
    e2e.rosci()
        .arg("send")
        .arg("gross.xta")
        .args(["--to", "cert:recipient-cipher.pem"])
        .args(["--intermediary", &_mock_url_from_dvdv(&e2e)])
        .args(["--intermediary-cert", "intermed-cipher.pem"])
        .args(["--cert", "client-sign.p12"])
        .args(["--decrypter-cert", "client-cipher.p12"])
        .timeout(Duration::from_secs(300))
        .assert()
        .success()
        .stdout(predicate::str::contains("message_id"));
}

#[test]
fn tampered_response_signature_is_rejected_loudly() {
    // A dedicated mock that signs correctly and then flips one byte of the
    // SignatureValue. The client library verifies automatically; the CLI
    // must fail with a transport/OSCI exit code and a message naming the
    // problem — anything else would mean verification is decorative.
    let pki_dir = tempfile::tempdir().expect("pki tempdir");
    let status = Command::new(repo_root().join("tests/gen-pki.sh"))
        .arg(pki_dir.path())
        .status()
        .expect("run gen-pki.sh");
    assert!(status.success(), "PKI generation failed");

    let dump_dir = pki_dir.path().join("dump");
    std::fs::create_dir_all(&dump_dir).unwrap();
    std::fs::write(
        pki_dir.path().join("meldung.xta"),
        "<?xml version=\"1.0\"?><XTA>signatur-pruefung</XTA>",
    )
    .unwrap();
    let Some(mock) = MockIntermediary::start_with(&dump_dir, &["--tamper-signature"]) else {
        return;
    };

    let mut cmd = AssertCommand::cargo_bin("rosci").unwrap();
    cmd.env(
        "OSCI_BRIDGE_JAR",
        repo_root().join("java/osci-bridge/target/osci-bridge.jar"),
    )
    .env("OSCI_CERT_PIN", "testpin")
    .current_dir(pki_dir.path())
    .arg("send")
    .arg("meldung.xta")
    .args(["--to", "cert:recipient-cipher.pem"])
    .args(["--intermediary", &mock.url()])
    .args(["--intermediary-cert", "intermed-cipher.pem"])
    .args(["--cert", "client-sign.p12"])
    .arg("--insecure-transport")
    .timeout(Duration::from_secs(180))
    .assert()
    .failure()
    .code(4)
    .stderr(
        predicates::str::contains("Signature")
            .or(predicate::str::contains("signatur"))
            .or(predicate::str::contains("Signatur")),
    );
}
