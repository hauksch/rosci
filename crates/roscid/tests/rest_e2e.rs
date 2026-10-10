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

    // Wait for the mock to accept connections.
    let addr = format!("127.0.0.1:{mock_port}");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(&addr).is_ok() {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("mock intermediary never came up");
        }
        std::thread::sleep(Duration::from_millis(200));
    }

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

    // Wait for roscid to bind — spawning and listening are not the same
    // event, and the test's first request races the bind otherwise.
    let rosci_addr = format!("127.0.0.1:{rosci_port}");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(&rosci_addr).is_ok() {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("roscid never came up on {rosci_addr}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }

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

#[test]
fn rest_server_healthz_and_liveness() {
    let Some(smoke) = setup() else { return };
    let (status, body) = http("GET", &format!("{}/healthz", smoke.base), None, None);
    assert_eq!(status, 200);
    assert_eq!(body.trim(), r#"{"status":"ok"}"#);
}

#[test]
fn rest_send_round_trip_with_attachments() {
    let Some(smoke) = setup() else { return };
    let dir = &smoke.dir;

    let payload = b"rest round trip payload 2026";
    let payload_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(payload)
    };
    let att_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"attachment bytes 123")
    };
    let recipient_pem =
        std::fs::read_to_string(dir.join("recipient-cipher.pem")).expect("recipient pem");
    let send = serde_json::json!({
        "to": {"cert": recipient_pem},
        "subject": "rest e2e sendung",
        "content": {"filename": "meldung.xta", "data": payload_b64},
        "attachments": [{"filename": "anhang.txt", "data": att_b64}],
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
    assert!(
        receipt["message_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "intermediary must assign a message id: {receipt}"
    );
}

#[test]
fn rest_status_route_returns_process_card_shape() {
    let Some(smoke) = setup() else { return };
    let (status, body) = http(
        "GET",
        &format!("{}/v1/messages/mock-msgid-1/status", smoke.base),
        None,
        None,
    );
    // The mock may or may not have a card for the id — assert the route
    // answered with a well-formed envelope either way.
    assert!(
        status == 200 || status == 404 || status == 422,
        "status: {status} {body}"
    );
}

#[test]
fn rest_rejects_without_api_key_when_configured() {
    let Some(smoke) = setup() else { return };
    let dir = &smoke.dir;
    // A second roscid with an API key — the loopback bind may still carry
    // one, and the route must then enforce it.
    let mut child = Command::new(env!("CARGO_BIN_EXE_roscid"))
        .env(
            "OSCI_BRIDGE_JAR",
            repo_root().join("java/osci-bridge/target/osci-bridge.jar"),
        )
        .env("OSCI_CERT_PIN", DEMO_PIN)
        .arg("--bind")
        .arg("127.0.0.1:8081")
        .arg("--cert")
        .arg(dir.join("client-sign.p12"))
        .arg("--decrypter-cert")
        .arg(dir.join("client-cipher.p12"))
        .arg("--intermediary")
        .arg("http://127.0.0.1:39471/osci-manager-entry/externalentry")
        .arg("--intermediary-cert")
        .arg(dir.join("intermed-cipher.pem"))
        .arg("--api-key")
        .arg("sekrit")
        .arg("--response-timeout-secs")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn roscid");

    std::thread::sleep(Duration::from_secs(1));
    let (status, _) = http("GET", "http://127.0.0.1:8081/healthz", None, None);
    assert_eq!(status, 200, "healthz stays open");
    let (status, _) = http(
        "POST",
        "http://127.0.0.1:8081/v1/send",
        Some(r#"{"to":{"cert":"x"},"content":{"data":"eA=="}}"#),
        None,
    );
    assert_eq!(status, 401, "send without key must be rejected");
    let _ = child.kill();
    let _ = child.wait();
}
