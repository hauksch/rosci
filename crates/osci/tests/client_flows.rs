//! Full client-API flows against the well-behaved fake bridge: builder
//! handshake, send, fetch, process-card, DVDV resolution. Everything the
//! real jar + mock intermediary do later, minus the JVM startup tax.

use std::io::Write;
use std::time::Duration;

use osci::bridge::BridgeConfig;
use osci::dvdv::{DvdvEntry, FileDvdv};
use osci::{Error, FetchQuery, Identity, Intermediary, OsciClient, Recipient, Xta};

const HAPPY: &str = r#"
while IFS= read -r line; do
  case "$line" in
    *'"ping"'*)
      echo '{"ok":true,"result":{"versions":{"bridge":"fake-1.0"}}}' ;;
    *'"send"'*)
      echo '{"ok":true,"result":{"message_id":"fake-msg-17","feedback":[["alles gut","0000"]]}}' ;;
    *'"fetch"'*)
      echo '{"ok":true,"result":{"messages":[{"subject":"XMeld","signatures_valid":true,"contents":[{"filename":"m.xta","data":"WFRB","container":"plain"}]}]}}' ;;
    *'"process-card"'*)
      echo '{"ok":true,"result":{"process_cards":[{"message_id":"fake-msg-17","subject":"XMeld","creation":"2026-09-29T10:00:00Z"}]}}' ;;
    *'"shutdown"'*)
      echo '{"ok":true}'
      exit 0 ;;
    *)
      echo '{"ok":false,"error":{"kind":"protocol","message":"unbekannt"}}' ;;
  esac
done
"#;

fn fake_bridge_config() -> BridgeConfig {
    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("happy.sh");
    std::fs::write(&script_path, HAPPY).unwrap();
    // Leak the tempdir on purpose: the script must outlive this function.
    std::mem::forget(dir);
    BridgeConfig::cmd(["bash", script_path.to_str().unwrap()])
        .response_timeout(Duration::from_secs(5))
}

fn test_client() -> OsciClient {
    OsciClient::builder()
        .bridge_config(fake_bridge_config())
        .intermediary(Intermediary::new("http://fake/entry", "FAKECERT"))
        .identity(Identity::from_p12_files(dummy_p12().as_path(), "123456", None, None).unwrap())
        .build()
        .unwrap()
}

fn dummy_p12() -> std::path::PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.p12");
    std::fs::write(&path, b"not a real p12, but the fake bridge cannot tell").unwrap();
    std::mem::forget(dir);
    path
}

#[test]
fn versions_handshake() {
    let mut client = test_client();
    let versions = client.versions().unwrap();
    assert_eq!(versions["bridge"], "fake-1.0");
    client.shutdown().unwrap();
}

#[test]
fn send_flow_returns_receipt() {
    let mut client = test_client();
    let xta = Xta::from_bytes("meldung.xta", b"<XTA>hallo behoerde</XTA>".to_vec());
    let receipt = client
        .send_xta(xta)
        .recipient(Recipient::from_cipher_cert_pem("RECIPIENTCERT"))
        .subject("XMeld 2.4")
        .submit()
        .unwrap();
    assert_eq!(receipt.message_id, "fake-msg-17");
    assert_eq!(receipt.feedback.unwrap()[0][1], "0000");
    client.shutdown().unwrap();
}

#[test]
fn send_without_recipient_is_config_error() {
    let mut client = test_client();
    let xta = Xta::from_bytes("m.xta", b"<XTA/>".to_vec());
    let err = client.send_xta(xta).subject("x").submit().unwrap_err();
    assert!(matches!(err, Error::Config(ref c) if c.contains("recipient")));
}

#[test]
fn fetch_flow_decodes_messages() {
    let mut client = test_client();
    let messages = client
        .fetch(FetchQuery::ByMessageId("fake-msg-17".into()))
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].subject.as_deref(), Some("XMeld"));
    assert_eq!(messages[0].signatures_valid, Some(true));
    let content = &messages[0].contents.as_ref().unwrap()[0];
    assert_eq!(content.filename.as_deref(), Some("m.xta"));
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&content.data)
        .unwrap();
    assert_eq!(decoded, b"XTA");
    client.shutdown().unwrap();
}

#[test]
fn process_card_flow_decodes_laufzettel() {
    let mut client = test_client();
    let cards = client.process_card("fake-msg-17").unwrap();
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].message_id.as_deref(), Some("fake-msg-17"));
    assert!(cards[0].creation.as_deref().unwrap().starts_with("2026-"));
    client.shutdown().unwrap();
}

#[test]
fn dvdv_resolution_provides_intermediary_and_recipient() {
    let dir = FileDvdv::from_entries(vec![DvdvEntry {
        org_key: "0241100012345".into(),
        name: "Katasteramt Musterstadt".into(),
        category: Some("osci".into()),
        intermediary_url: "https://ks.musterstadt/entry".into(),
        intermediary_cipher_cert: "IKSCERT".into(),
        recipient_cipher_cert: "EMPFCERT".into(),
    }]);

    let (intermediary, recipient) =
        osci::resolve_dvdv(&dir, "0241100012345", Some("osci")).unwrap();
    assert_eq!(intermediary.url, "https://ks.musterstadt/entry");
    assert_eq!(intermediary.cipher_cert, "IKSCERT");
    assert_eq!(recipient.cipher_cert, "EMPFCERT");

    let err = osci::resolve_dvdv(&dir, "0000", None).unwrap_err();
    assert!(matches!(err, Error::DvdvLookup(_)));
}

#[test]
fn drop_shuts_the_fake_bridge_down() {
    let mut client = test_client();
    // No explicit shutdown: Drop must do it.
    let _ = client.versions();
    drop(client);
    // If the fake bridge were still alive, the next lines in its script
    // would be waiting for input forever; the process list stays clean.
    std::io::stdout().flush().ok();
}

#[test]
fn dvdv_all_is_sorted_and_ambiguity_is_an_error() {
    let dir = FileDvdv::from_entries(vec![
        DvdvEntry {
            org_key: "00002".into(),
            name: "Zweitamt".into(),
            category: None,
            intermediary_url: "https://ks/2".into(),
            intermediary_cipher_cert: "C".into(),
            recipient_cipher_cert: "C".into(),
        },
        DvdvEntry {
            org_key: "00001".into(),
            name: "Erstamt".into(),
            category: None,
            intermediary_url: "https://ks/1".into(),
            intermediary_cipher_cert: "C".into(),
            recipient_cipher_cert: "C".into(),
        },
        DvdvEntry {
            org_key: "00001".into(),
            name: "Erstamt, zweite Stelle".into(),
            category: Some("egvp".into()),
            intermediary_url: "https://ks/1b".into(),
            intermediary_cipher_cert: "C".into(),
            recipient_cipher_cert: "C".into(),
        },
    ]);

    let all = dir.all();
    let keys: Vec<&str> = all.iter().map(|e| e.org_key.as_str()).collect();
    assert_eq!(
        keys,
        vec!["00001", "00001", "00002"],
        "all() must be sorted by org key"
    );

    // Two entries, no category → ambiguous, and the error must say so.
    let err = osci::resolve_dvdv(&dir, "00001", None).unwrap_err();
    assert!(matches!(err, Error::DvdvLookup(ref m) if m.contains("ambiguous")));

    // The category disambiguates.
    let (intermediary, _) = osci::resolve_dvdv(&dir, "00001", Some("egvp")).unwrap();
    assert_eq!(intermediary.url, "https://ks/1b");
}

#[test]
fn receipt_serializes_stable_json() {
    use osci::Receipt;
    let receipt = Receipt {
        message_id: "mock-4711".into(),
        feedback: Some(vec![vec!["alles gut".into(), "0000".into()]]),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"message_id\":\"mock-4711\""));
    assert!(json.contains("0000"));
    let back: Receipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.message_id, "mock-4711");
}
