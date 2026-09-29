//! Bridge lifecycle integration tests: spawn fake bridges (bash scripts),
//! exercise timeouts, garbage, mismatches and death. No JVM harmed —
//! the JVM comes in for the real e2e suite later.

use std::io::Write;
use std::time::Duration;

use osci::bridge::{BridgeConfig, BridgeHandle};
use osci::{Error, OsciClient};

fn write_script(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    write!(f, "{body}").unwrap();
    path
}

/// The well-behaved fake: pings, sends, fetches, shuts down.
const HAPPY: &str = r#"
while IFS= read -r line; do
  case "$line" in
    *'"ping"'*)
      echo '{"ok":true,"result":{"versions":{"bridge":"fake-1.0"}}}' ;;
    *'"send"'*)
      echo '{"ok":true,"result":{"message_id":"fake-msg-17","feedback":[["alles gut","0000"]]}}' ;;
    *'"fetch"'*)
      echo '{"ok":true,"result":{"messages":[{"subject":"s","signatures_valid":true,"contents":[{"filename":"m.xta","data":"WFRB","container":"plain"}]}]}}' ;;
    *'"process-card"'*)
      echo '{"ok":true,"result":{"process_cards":[{"message_id":"fake-msg-17","subject":"s"}]}}' ;;
    *'"shutdown"'*)
      echo '{"ok":true}'
      exit 0 ;;
    *)
      echo '{"ok":false,"error":{"kind":"protocol","message":"fake bridge kennt dieses Op nicht"}}' ;;
  esac
done
"#;

fn happy_config(dir: &tempfile::TempDir) -> BridgeConfig {
    let script = write_script(dir, "happy.sh", HAPPY);
    BridgeConfig::cmd(["bash", script.to_str().unwrap()]).response_timeout(Duration::from_secs(5))
}

fn request(op: &'static str) -> osci::protocol::Request {
    osci::protocol::Request {
        id: String::new(),
        op,
        intermediary: None,
        identity: None,
        recipient: None,
        subject: None,
        content: None,
        sign: None,
        encrypt: None,
        insecure_transport: None,
        tls: None,
        selection_mode: None,
        selection_rule: None,
    }
}

#[test]
fn ping_round_trip_with_fake_bridge() {
    let dir = tempfile::tempdir().unwrap();
    let mut bridge = BridgeHandle::spawn(&happy_config(&dir)).unwrap();
    let rsp = bridge.call(request("ping")).unwrap();
    assert!(rsp.ok);
    assert_eq!(rsp.result.unwrap().versions.unwrap()["bridge"], "fake-1.0");
    bridge.shutdown();
    let code = bridge.wait().unwrap();
    assert_eq!(code, Some(0), "fake bridge must exit cleanly");
}

#[test]
fn garbage_response_is_a_protocol_violation() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_script(&dir, "garbage.sh", "echo '42 ist keine antwort'\n");
    let mut bridge =
        BridgeHandle::spawn(&BridgeConfig::cmd(["bash", script.to_str().unwrap()])).unwrap();
    let err = bridge.call(request("ping")).unwrap_err();
    assert!(matches!(err, Error::BridgeProtocol(_)), "got: {err:?}");
}

#[test]
fn silence_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_script(&dir, "silent.sh", "sleep 30\n");
    let cfg = BridgeConfig::cmd(["bash", script.to_str().unwrap()])
        .response_timeout(Duration::from_millis(300));
    let mut bridge = BridgeHandle::spawn(&cfg).unwrap();
    let err = bridge.call(request("ping")).unwrap_err();
    assert!(matches!(err, Error::BridgeTimeout { .. }), "got: {err:?}");
}

#[test]
fn dying_bridge_is_a_spawn_level_failure() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_script(&dir, "dying.sh", "exit 3\n");
    let mut bridge =
        BridgeHandle::spawn(&BridgeConfig::cmd(["bash", script.to_str().unwrap()])).unwrap();
    // The write succeeds into the pipe buffer; the read side must notice EOF.
    let err = bridge.call(request("ping")).unwrap_err();
    assert!(
        matches!(err, Error::BridgeProtocol(_) | Error::BridgeTimeout { .. }),
        "got: {err:?}"
    );
}

#[test]
fn structured_error_maps_to_bridge_error() {
    let dir = tempfile::tempdir().unwrap();
    let script = write_script(
        &dir,
        "crypto_fail.sh",
        "read -r line; echo '{\"ok\":false,\"error\":{\"kind\":\"crypto\",\"message\":\"schluessel kaputt\"}}'\n",
    );
    let mut bridge =
        BridgeHandle::spawn(&BridgeConfig::cmd(["bash", script.to_str().unwrap()])).unwrap();
    let err = bridge.call(request("ping")).unwrap_err();
    match err {
        Error::Bridge {
            kind,
            message,
            feedback,
        } => {
            assert_eq!(kind.as_str(), "crypto");
            assert!(message.contains("schluessel"));
            assert!(feedback.is_empty());
        }
        other => panic!("expected Bridge error, got {other:?}"),
    }
}

#[test]
fn exit_codes_follow_the_documented_map() {
    assert_eq!(Error::Config("x".into()).exit_code(), 2);
    assert_eq!(Error::DvdvLookup("x".into()).exit_code(), 3);
    assert_eq!(
        Error::Bridge {
            kind: osci::BridgeErrorKind::Transport,
            message: "x".into(),
            feedback: vec![],
        }
        .exit_code(),
        4
    );
    assert_eq!(
        Error::Bridge {
            kind: osci::BridgeErrorKind::Crypto,
            message: "x".into(),
            feedback: vec![],
        }
        .exit_code(),
        5
    );
    assert_eq!(
        Error::Bridge {
            kind: osci::BridgeErrorKind::Internal,
            message: "x".into(),
            feedback: vec![],
        }
        .exit_code(),
        6
    );
}

#[test]
fn client_builder_requires_intermediary_and_identity() {
    let err = OsciClient::builder().build().unwrap_err();
    assert!(matches!(err, Error::Config(ref c) if c.contains("intermediary")));
}

#[test]
fn spawn_failure_for_missing_binary() {
    let err = BridgeHandle::spawn(&BridgeConfig::cmd(["/nonexistent/bridge-bin"])).unwrap_err();
    assert!(matches!(err, Error::BridgeSpawn(_)), "got: {err:?}");
}
