//! Wire types for the bridge line protocol (v1).
//!
//! Field names are identical on both sides of the pipe — the Java class
//! `de.deshittifier.osci.bridge.Protocol` is the normative twin of this
//! module. If either side changes, both change, or the handshake version
//! does. No silent schema drift; we've seen where that leads.

use serde::{Deserialize, Serialize};

fn is_none<T>(opt: &Option<T>) -> bool {
    opt.is_none()
}

/// One request to the bridge. Exactly one non-`None` op per line.
#[derive(Debug, Clone, Serialize)]
pub struct Request {
    pub id: String,
    pub op: &'static str,
    #[serde(skip_serializing_if = "is_none")]
    pub intermediary: Option<Party>,
    #[serde(skip_serializing_if = "is_none")]
    pub identity: Option<IdentityMsg>,
    #[serde(skip_serializing_if = "is_none")]
    pub recipient: Option<Party>,
    #[serde(skip_serializing_if = "is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "is_none")]
    pub content: Option<Payload>,
    #[serde(skip_serializing_if = "is_none")]
    pub sign: Option<bool>,
    #[serde(skip_serializing_if = "is_none")]
    pub encrypt: Option<bool>,
    /// Test mode: plain SOAP transport (see the Java-side twin of this
    /// field). `Some(false)` disables transport encryption/signatures;
    /// content crypto is unaffected.
    #[serde(skip_serializing_if = "is_none")]
    pub insecure_transport: Option<bool>,
    #[serde(skip_serializing_if = "is_none")]
    pub tls: Option<TlsMsg>,
    #[serde(skip_serializing_if = "is_none")]
    pub selection_mode: Option<String>,
    #[serde(skip_serializing_if = "is_none")]
    pub selection_rule: Option<String>,
}

/// Intermediary or recipient, expressed the only way OSCI understands:
/// certificates. Everything else is address book fluff.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Party {
    #[serde(default, skip_serializing_if = "is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub cipher_cert: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub signature_cert: Option<String>,
}

/// Sender identity as PKCS#12 material (base64) plus PINs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityMsg {
    #[serde(default, skip_serializing_if = "is_none")]
    pub signer_p12: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub signer_pin: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub decrypter_p12: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub decrypter_pin: Option<String>,
}

/// The XTA payload. Opaque bytes, base64 — we do not parse your XTA,
/// we just carry it with dignity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    #[serde(default, skip_serializing_if = "is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub content_type: Option<String>,
    pub data: String,
}

/// TLS knobs for the bridge's HTTP(S) transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsMsg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub client_p12: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub client_pin: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub read_timeout_ms: Option<u64>,
}

/// Bridge response envelope. `ok` decides everything.
#[derive(Debug, Clone, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub op: Option<String>,
    pub ok: bool,
    #[serde(default)]
    pub result: Option<ResultMsg>,
    #[serde(default)]
    pub error: Option<ErrorMsg>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResultMsg {
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub feedback: Option<Vec<Vec<String>>>,
    #[serde(default)]
    pub messages: Option<Vec<FetchedMessage>>,
    #[serde(default)]
    pub process_cards: Option<Vec<ProcessCard>>,
    #[serde(default)]
    pub versions: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ErrorMsg {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub feedback: Option<Vec<Vec<String>>>,
}

// ---------------------------------------------------------------- public DTOs

/// A successfully submitted message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// OSCI message id handed out by the intermediary. Quote this in any
    /// follow-up correspondence; it is the Aktenzeichen of your message.
    pub message_id: String,
    /// Raw feedback rows from the intermediary, `[text, code]` per row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback: Option<Vec<Vec<String>>>,
}

/// One message fetched from the postbox.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FetchedMessage {
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub signatures_valid: Option<bool>,
    #[serde(default)]
    pub contents: Option<Vec<FetchedContent>>,
    #[serde(default)]
    pub encrypted_contents: Option<Vec<FetchedContent>>,
}

/// One content item of a fetched message.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FetchedContent {
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    /// Base64-encoded bytes.
    pub data: String,
    #[serde(default)]
    pub container: Option<String>,
}

/// A Laufzettel ("process card") entry: who touched the message, when.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ProcessCard {
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub creation: Option<String>,
    #[serde(default)]
    pub forwarding: Option<String>,
    #[serde(default)]
    pub reception: Option<String>,
    #[serde(default)]
    pub inspections: Option<Vec<Inspection>>,
}

/// A single inspection stamp on a process card.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Inspection {
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub online_checked: Option<bool>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// Version handshake data from `ping`.
pub type VersionInfo = std::collections::BTreeMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_request_serializes_with_snake_case_fields() {
        let req = Request {
            id: "r1".into(),
            op: "send",
            intermediary: Some(Party {
                url: Some("http://localhost:9/x".into()),
                cipher_cert: Some("AAECAw==".into()),
                signature_cert: None,
            }),
            identity: Some(IdentityMsg {
                signer_p12: Some("c2VjcmV0".into()),
                signer_pin: Some("123456".into()),
                decrypter_p12: None,
                decrypter_pin: None,
            }),
            recipient: Some(Party {
                url: None,
                cipher_cert: Some("AAECAw==".into()),
                signature_cert: None,
            }),
            subject: Some("Betreff".into()),
            content: Some(Payload {
                filename: Some("m.xta".into()),
                content_type: Some("application/octet-stream".into()),
                data: "WFRBCg==".into(),
            }),
            sign: Some(true),
            encrypt: Some(false),
            insecure_transport: None,
            tls: None,
            selection_mode: None,
            selection_rule: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        for needle in [
            "\"op\":\"send\"",
            "\"cipher_cert\"",
            "\"signer_p12\"",
            "\"signer_pin\"",
            "\"selection_mode\"",
            "\"tls\"",
        ] {
            if needle == "\"selection_mode\"" || needle == "\"tls\"" {
                assert!(
                    !json.contains(needle),
                    "absent fields must stay absent: {json}"
                );
            } else {
                assert!(json.contains(needle), "missing {needle} in {json}");
            }
        }
    }

    #[test]
    fn parses_bridge_error_response() {
        let rsp: Response = serde_json::from_str(
            r#"{"id":"r7","op":"send","ok":false,
                "error":{"kind":"osci","message":"abgelehnt",
                         "feedback":[["text","1050"]]}}"#,
        )
        .unwrap();
        assert!(!rsp.ok);
        let err = rsp.error.unwrap();
        assert_eq!(err.kind.as_deref(), Some("osci"));
        assert_eq!(err.feedback.unwrap()[0][1], "1050");
    }

    #[test]
    fn parses_bridge_send_result() {
        let rsp: Response = serde_json::from_str(
            r#"{"id":"r8","op":"send","ok":true,
                "result":{"message_id":"id-4711","feedback":[["ok","0000"]]}}"#,
        )
        .unwrap();
        assert!(rsp.ok);
        let result = rsp.result.unwrap();
        assert_eq!(result.message_id.as_deref(), Some("id-4711"));
    }

    #[test]
    fn parses_ping_versions() {
        let rsp: Response = serde_json::from_str(
            r#"{"ok":true,"result":{"versions":{"protocol":"1","bridge":"0.1.0"}}}"#,
        )
        .unwrap();
        let versions = rsp.result.unwrap().versions.unwrap();
        assert_eq!(versions.get("protocol").map(String::as_str), Some("1"));
    }

    #[test]
    fn response_without_id_tolerated() {
        let rsp: Response = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(rsp.id.is_none());
    }
}
