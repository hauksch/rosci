//! CLI behavior tests via assert_cmd. The bridge is a bash fake, so these
//! cover argument plumbing, output shape and exit codes — the real jar and
//! a real (mock) intermediary star in the e2e suite under tests/.

use assert_cmd::Command;
use predicates::prelude::*;

fn rosci() -> Command {
    Command::cargo_bin("rosci").unwrap()
}

const HAPPY_BRIDGE: &str = r#"
while IFS= read -r line; do
  case "$line" in
    *'"ping"'*)
      echo '{"ok":true,"result":{"versions":{"bridge":"fake-1.0","protocol":"1"}}}' ;;
    *'"send"'*)
      echo '{"ok":true,"result":{"message_id":"fake-msg-42","feedback":[["ok","0000"]]}}' ;;
    *'"fetch"'*)
      echo '{"ok":true,"result":{"messages":[{"subject":"XMeld","signatures_valid":true,"contents":[{"filename":"m.xta","data":"WFRB","container":"plain"}]}]}}' ;;
    *'"process-card"'*)
      echo '{"ok":true,"result":{"process_cards":[{"message_id":"x","subject":"XMeld","creation":"2026-09-29T10:00:00Z"}]}}' ;;
    *'"shutdown"'*)
      echo '{"ok":true}'
      exit 0 ;;
  esac
done
"#;

/// (bridge_cmd, cwd) — the fake bridge script and a working directory
/// containing the supporting files (p12, certs, dvdv.json).
fn env_with_fake_bridge() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-bridge.sh");
    std::fs::write(&script, HAPPY_BRIDGE).unwrap();

    std::fs::write(dir.path().join("client.p12"), b"fake p12").unwrap();
    std::fs::write(
        dir.path().join("intermediary.cer"),
        b"FAKE INTERMEDIARY CERT",
    )
    .unwrap();
    std::fs::write(dir.path().join("recipient.cer"), b"FAKE RECIPIENT CERT").unwrap();
    std::fs::write(
        dir.path().join("dvdv.json"),
        r#"[{"org_key":"0241100012345","name":"Testamt Musterstadt",
             "intermediary_url":"https://ks.test/entry",
             "intermediary_cipher_cert":"IKS","recipient_cipher_cert":"EMPFD"}]"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("meldung.xta"), b"<XTA>anzeige</XTA>").unwrap();

    (format!("bash {}", script.display()), dir)
}

#[test]
fn help_works() {
    rosci()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("curl of OSCI"));
}

#[test]
fn root_help_lists_exit_codes() {
    // Exit codes live in the root command's ABOUT text, not in
    // subcommand help — assert the thing the name promises.
    let output = Command::new(env!("CARGO_BIN_EXE_rosci"))
        .arg("--help")
        .output()
        .expect("run rosci --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Exit codes"), "stdout: {stdout}");
}

#[test]
fn version_prints_local_and_bridge() {
    let (bridge_cmd, _dir) = env_with_fake_bridge();
    rosci()
        .arg("version")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .assert()
        .success()
        .stdout(predicate::str::contains("rosci").and(predicate::str::contains("fake-1.0")));
}

#[test]
fn version_fails_when_required_and_missing() {
    rosci()
        .arg("version")
        .arg("--require-bridge")
        .env("OSCI_BRIDGE_JAR", "/nonexistent/osci-bridge.jar")
        .assert()
        .failure()
        .code(6);
}

#[test]
fn send_with_cert_recipient_prints_message_id() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("fake-msg-42").and(predicate::str::contains("accepted")));
}

#[test]
fn send_json_output_is_parseable() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    let out = rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .arg("--json")
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
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
fn send_via_dvdv_resolution() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "dvdv:0241100012345"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("fake-msg-42"));
}

#[test]
fn send_missing_pin_is_exit_2() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env_remove("OSCI_CERT_PIN")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn send_missing_xta_file_is_exit_2() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("send")
        .arg("gibt-es-nicht.xta")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn send_stdin_dash_works() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("send")
        .arg("-")
        .args(["--to", "cert:recipient.cer"])
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .write_stdin("<XTA>von stdin</XTA>")
        .assert()
        .success()
        .stdout(predicate::str::contains("fake-msg-42"));
}

#[test]
fn bad_to_spec_is_exit_2() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("send")
        .arg("meldung.xta")
        .args(["--to", "telefon:040-123456"])
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn dvdv_unknown_org_is_exit_3() {
    let (_bridge_cmd, dir) = env_with_fake_bridge();
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
    let (_bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("dvdv")
        .arg("find")
        .args(["--org", "0241100012345"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Testamt Musterstadt")
                .and(predicate::str::contains("https://ks.test/entry")),
        );
}

#[test]
fn fetch_writes_files() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    let out_dir = dir.path().join("post");
    rosci()
        .arg("fetch")
        .arg("--all")
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .args(["--out", out_dir.to_str().unwrap()])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .success();

    let written = std::fs::read(out_dir.join("m.xta")).unwrap();
    assert_eq!(written, b"XTA");
}

#[test]
fn fetch_needs_selection_is_exit_2() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("fetch")
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn status_prints_laufzettel() {
    let (bridge_cmd, dir) = env_with_fake_bridge();
    rosci()
        .arg("status")
        .arg("fake-msg-42")
        .args(["--intermediary", "http://fake/entry"])
        .args(["--intermediary-cert", "intermediary.cer"])
        .args(["--cert", "client.p12"])
        .env("OSCI_CERT_PIN", "123456")
        .env("OSCI_BRIDGE_CMD", &bridge_cmd)
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("message_id")
                .and(predicate::str::contains("2026-09-29T10:00:00Z")),
        );
}
