//! REST e2e: the real `roscid` binary + real bridge jar + real mock
//! intermediary — the full server surface driven over HTTP. Ground rules:
//! 127.0.0.1 only, no interop contact (that is the gated interop suite's
//! job).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const DEMO_PIN: &str = "testpin";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn which_java() -> Option<String> {
    ["java", "/usr/bin/java"]
        .iter()
        .find(|c| Command::new(c).arg("-version").output().is_ok())
        .map(|c| c.to_string())
}

struct Mock {
    child: Child,
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Roscid {
    child: Child,
}

impl Drop for Roscid {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .map(|l| l.local_addr().map(|a| a.port()).unwrap_or(0))
        .unwrap_or(0)
}

/// Polls until the address accepts connections — spawning and listening
/// are not the same event, and a fixed `sleep` races the bind.
fn wait_for_port(addr: &str, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("{what} never came up on {addr}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

struct Smoke {
    base: String,
    dir: PathBuf,
    _pki: tempfile::TempDir,
    _mock: Mock,
    _roscid: Roscid,
}

/// Spawns the mock intermediary and roscid against it. Everything it
/// creates stays alive until the returned Smoke is dropped — the PKI
/// TempDir guard especially must not be dropped inside setup, or the
/// certs vanish before the tests read them.
fn setup() -> Option<Smoke> {
    let bridge_jar = repo_root().join("java/osci-bridge/target/osci-bridge.jar");
    let mock_jar = repo_root().join("java/osci-mock/target/osci-mock.jar");
    if !bridge_jar.is_file() || !mock_jar.is_file() || which_java().is_none() {
        eprintln!("rest-e2e: skipping (jars or java missing — make build first)");
        return None;
    }

    let pki_guard = tempfile::tempdir().expect("pki tempdir");
    let pki = pki_guard.path().to_path_buf();
    let status = Command::new(repo_root().join("tests/gen-pki.sh"))
        .arg(&pki)
        .status()
        .expect("run gen-pki.sh");
    assert!(status.success(), "PKI generation failed");

    let dump_dir = pki.join("dump");
    std::fs::create_dir_all(&dump_dir).unwrap();
    let mock_port = free_port();
    let mock_log = std::fs::File::create(pki.join("mock.log")).unwrap();
    #[allow(clippy::zombie_processes)] // Mock::drop kills + reaps
    let mock = Mock {
        child: Command::new(which_java().unwrap())
            .arg("-jar")
            .arg(&mock_jar)
            .arg(mock_port.to_string())
            .arg(&dump_dir)
            .arg("--key")
            .arg(pki.join("intermed-cipher.key"))
            .arg("--sign-key")
            .arg(pki.join("intermed-sign.key"))
            .arg("--sign-cert")
            .arg(pki.join("intermed-sign.pem"))
            .stdout(Stdio::null())
            .stderr(Stdio::from(mock_log))
            .spawn()
            .expect("spawn mock intermediary"),
    };

    wait_for_port(&format!("127.0.0.1:{mock_port}"), "mock intermediary");

    // roscid submits through the mock; recipient addressed by inline cert.
    let rosci_port = free_port();
    let roscid_child = Command::new(env!("CARGO_BIN_EXE_roscid"))
        .env("OSCI_BRIDGE_JAR", &bridge_jar)
        .env("OSCI_CERT_PIN", DEMO_PIN)
        .arg("--bind")
        .arg(format!("127.0.0.1:{rosci_port}"))
        .arg("--cert")
        .arg(pki.join("client-sign.p12"))
        .arg("--decrypter-cert")
        .arg(pki.join("client-cipher.p12"))
        .arg("--intermediary")
        .arg(format!(
            "http://127.0.0.1:{mock_port}/osci-manager-entry/externalentry"
        ))
        .arg("--intermediary-cert")
        .arg(pki.join("intermed-cipher.pem"))
        .arg("--response-timeout-secs")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn roscid");

    wait_for_port(&format!("127.0.0.1:{rosci_port}"), "roscid");

    let base_url = format!("http://127.0.0.1:{rosci_port}");
    Some(Smoke {
        base: base_url,
        dir: pki.clone(),
        _pki: pki_guard,
        _mock: mock,
        _roscid: Roscid {
            child: roscid_child,
        },
    })
}

/// Spawns a second roscid outside the Smoke setup — used for the auth and
/// dead-bridge scenarios that need their own flag set. `jar` overrides the
/// bridge jar (a nonexistent path yields a server that can never get a
/// bridge); the placeholder intermediary is never contacted by these
/// scenarios.
fn spawn_roscid(dir: &std::path::Path, bind: &str, extra: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_roscid"))
        .env(
            "OSCI_BRIDGE_JAR",
            repo_root().join("java/osci-bridge/target/osci-bridge.jar"),
        )
        .env("OSCI_CERT_PIN", DEMO_PIN)
        .arg("--bind")
        .arg(bind)
        .arg("--cert")
        .arg(dir.join("client-sign.p12"))
        .arg("--decrypter-cert")
        .arg(dir.join("client-cipher.p12"))
        .arg("--intermediary")
        .arg("http://127.0.0.1:39471/osci-manager-entry/externalentry")
        .arg("--intermediary-cert")
        .arg(dir.join("intermed-cipher.pem"))
        .args(extra)
        .arg("--response-timeout-secs")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn roscid")
}

/// Minimal HTTP/1.1 client over TcpStream: returns (status, body).
fn http(method: &str, url: &str, body: Option<&str>, key: Option<&str>) -> (u16, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (host_port, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{}", p)))
        .unwrap_or((rest, "/".into()));
    let mut stream = TcpStream::connect(host_port).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n");
    if let Some(key) = key {
        req.push_str(&format!("Authorization: Bearer {key}\r\n"));
    }
    match body {
        Some(b) => {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                b.len()
            ));
            req.push_str(b);
        }
        None => req.push_str("\r\n"),
    }
    stream.write_all(req.as_bytes()).unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status: u16 = response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn b64(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(data: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .expect("valid base64")
}

#[test]
fn rest_server_healthz_readiness_and_version() {
    let Some(smoke) = setup() else { return };

    // Liveness answers without touching the bridge.
    let (status, body) = http("GET", &format!("{}/healthz", smoke.base), None, None);
    assert_eq!(status, 200);
    assert_eq!(body.trim(), r#"{"status":"ok"}"#);

    // Readiness pings the bridge (cold-starting it on first request).
    let (status, body) = http("GET", &format!("{}/readyz", smoke.base), None, None);
    assert_eq!(status, 200, "readyz must be ready against the mock: {body}");
    assert_eq!(body.trim(), r#"{"status":"ready"}"#);

    // The version route reports the real handshake, jar fingerprint
    // included — the same contract the CLI's `version` prints.
    let (status, body) = http("GET", &format!("{}/v1/version", smoke.base), None, None);
    assert_eq!(status, 200, "version failed: {body}");
    let versions: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&body).expect("versions json");
    assert_eq!(versions["protocol"].as_str(), Some("1"));
    assert!(
        versions["bridge"].as_str().is_some_and(|v| !v.is_empty()),
        "bridge version missing: {body}"
    );
    let jar_sha = versions["jar_sha256"].as_str().expect("jar_sha256");
    assert!(
        jar_sha.len() == 64 && jar_sha.chars().all(|c| c.is_ascii_hexdigit()),
        "jar_sha256 must be a 64-hex fingerprint: {body}"
    );
}

#[test]
fn rest_send_status_fetch_round_trip() {
    let Some(smoke) = setup() else { return };
    let dir = &smoke.dir;

    // --- send: a receipt with an intermediary-assigned message id --------
    let recipient_pem =
        std::fs::read_to_string(dir.join("recipient-cipher.pem")).expect("recipient pem");
    let send = serde_json::json!({
        "to": {"cert": recipient_pem},
        "subject": "rest e2e sendung",
        "content": {"filename": "meldung.xta", "data": b64(b"rest round trip payload 2026")},
        "attachments": [{"filename": "anhang.txt", "data": b64(b"attachment bytes 123")}],
    });
    let (status, response) = http(
        "POST",
        &format!("{}/v1/send", smoke.base),
        Some(&serde_json::to_string(&send).unwrap()),
        None,
    );
    assert_eq!(status, 200, "send failed: {response}");
    let receipt: serde_json::Value = serde_json::from_str(&response).expect("receipt json");
    assert_eq!(receipt["response_signed"], true, "response must be signed");
    let message_id = receipt["message_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .expect("intermediary must assign a message id")
        .to_string();

    // --- status: the mock's canned Laufzettel for OUR message id ---------
    // A route that merely answers 200/404/422 would also pass if the
    // handler were deleted — so the card's content is asserted, not just
    // the status code.
    let (status, body) = http(
        "GET",
        &format!("{}/v1/messages/{message_id}/status", smoke.base),
        None,
        None,
    );
    assert_eq!(status, 200, "status failed: {body}");
    let cards: serde_json::Value = serde_json::from_str(&body).expect("process cards json");
    let cards = cards.as_array().expect("process cards are an array");
    assert!(!cards.is_empty(), "the mock always returns one card");
    assert_eq!(
        cards[0]["message_id"].as_str(),
        Some(message_id.as_str()),
        "card must echo the requested id: {body}"
    );
    assert!(
        cards[0]["subject"]
            .as_str()
            .is_some_and(|s| s.contains("mock laufzettel")),
        "card must carry the mock's subject: {body}"
    );
    assert_eq!(
        cards[0]["creation"].as_str(),
        Some("2026-09-30T08:15:00Z"),
        "card must carry the mock's canned creation stamp: {body}"
    );

    // --- fetch: the canned postbox back through the REST surface ---------
    let (status, body) = http(
        "POST",
        &format!("{}/v1/fetch", smoke.base),
        Some(r#"{"all":true}"#),
        None,
    );
    assert_eq!(status, 200, "fetch failed: {body}");
    let messages: serde_json::Value = serde_json::from_str(&body).expect("fetch json");
    let messages = messages.as_array().expect("fetched messages are an array");

    // Plain dialect: the attachment-referencing container.
    let plain = messages
        .iter()
        .find(|m| m["contents"].as_array().is_some_and(|c| !c.is_empty()))
        .expect("one message with plain contents");
    let content = &plain["contents"][0];
    assert_eq!(content["filename"].as_str(), Some("mock-antwort.xta"));
    let decoded = b64_decode(content["data"].as_str().expect("b64 data"));
    let text = String::from_utf8_lossy(&decoded);
    assert!(
        text.contains("die behoerde dankt"),
        "fetched XTA must carry the canned payload: {text}"
    );

    // Encrypted dialect: content sealed to the fetching client — the bridge
    // must have decrypted it for the REST response to contain plaintext.
    let sealed = messages
        .iter()
        .find(|m| {
            m["encrypted_contents"]
                .as_array()
                .is_some_and(|c| !c.is_empty())
        })
        .expect("one message with decrypted encrypted_contents");
    let enc_data = sealed["encrypted_contents"][0]["data"]
        .as_str()
        .expect("encrypted b64 data");
    let enc_decoded = b64_decode(enc_data);
    let enc_text = String::from_utf8_lossy(&enc_decoded);
    assert!(
        enc_text.contains("streng vertrauliche antwort"),
        "decrypted secret must match the canned payload: {enc_text}"
    );
}

#[test]
fn rest_readyz_reports_503_when_the_bridge_is_dead() {
    let Some(smoke) = setup() else { return };
    let dir = &smoke.dir;
    // roscid binds eagerly but builds the bridge lazily — point it at a jar
    // that does not exist and readiness must turn 503, never 200: probes
    // and load balancers read the status code, not the body.
    let port = free_port();
    #[allow(clippy::zombie_processes)] // killed + reaped below
    let mut child = Command::new(env!("CARGO_BIN_EXE_roscid"))
        .env("OSCI_BRIDGE_JAR", dir.join("no-such-bridge.jar"))
        .env("OSCI_CERT_PIN", DEMO_PIN)
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--cert")
        .arg(dir.join("client-sign.p12"))
        .arg("--decrypter-cert")
        .arg(dir.join("client-cipher.p12"))
        .arg("--intermediary")
        .arg("http://127.0.0.1:39471/osci-manager-entry/externalentry")
        .arg("--intermediary-cert")
        .arg(dir.join("intermed-cipher.pem"))
        .arg("--response-timeout-secs")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn roscid");

    let base = format!("http://127.0.0.1:{port}");
    wait_for_port(&format!("127.0.0.1:{port}"), "roscid (dead bridge)");

    let (status, _) = http("GET", &format!("{base}/healthz"), None, None);
    assert_eq!(status, 200, "liveness must not depend on the bridge");
    let (status, body) = http("GET", &format!("{base}/readyz"), None, None);
    assert_eq!(status, 503, "dead bridge must read as not-ready: {body}");
    assert!(
        body.contains("not-ready"),
        "the error kind must say not-ready: {body}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn rest_rejects_without_api_key_when_configured() {
    let Some(smoke) = setup() else { return };
    // A second roscid with an API key — the loopback bind may still carry
    // one, and the route must then enforce it.
    let port = free_port();
    #[allow(clippy::zombie_processes)] // killed + reaped below
    let mut child = spawn_roscid(
        &smoke.dir,
        &format!("127.0.0.1:{port}"),
        &["--api-key", "sekrit"],
    );
    let base = format!("http://127.0.0.1:{port}");
    wait_for_port(&format!("127.0.0.1:{port}"), "roscid (api key)");

    let (status, _) = http("GET", &format!("{base}/healthz"), None, None);
    assert_eq!(status, 200, "healthz stays open");
    let (status, _) = http(
        "POST",
        &format!("{base}/v1/send"),
        Some(r#"{"to":{"cert":"x"},"content":{"data":"eA=="}}"#),
        None,
    );
    assert_eq!(status, 401, "send without key must be rejected");
    let _ = child.kill();
    let _ = child.wait();
}
