//! Public data-transfer types — the vocabulary of receipts, fetched
//! messages and process cards. Formerly the wire types of the Java
//! bridge's line protocol; with the native stack these are plain in-process
//! values, but their shape is kept stable because roscid's REST API and
//! the CLI output mirror them field-for-field.

/// Protocol version carried in the `versions()` handshake. It outlived the
/// line protocol it versioned; consumers still assert on it.
pub const PROTOCOL_VERSION: &str = "1";

// ---------------------------------------------------------------- public DTOs

/// A successfully submitted message.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    /// OSCI message id handed out by the intermediary. Quote this in any
    /// follow-up correspondence; it is the Aktenzeichen of your message.
    pub message_id: String,
    /// Whether the intermediary's response carried a signature — and one
    /// that actually verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_signed: Option<bool>,
    /// Raw feedback rows from the intermediary, `[text, code]` per row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback: Option<Vec<Vec<String>>>,
}

/// One message fetched from the postbox.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
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
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
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
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
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
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
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

/// Version handshake data from `versions()`.
pub type VersionInfo = std::collections::BTreeMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_round_trips_through_json() {
        let receipt = Receipt {
            message_id: "id-4711".into(),
            response_signed: Some(true),
            feedback: Some(vec![vec!["ok".into(), "0000".into()]]),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"message_id\":\"id-4711\""));
        let back: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, receipt);
    }

    #[test]
    fn fetched_message_parses_with_defaults() {
        let msg: FetchedMessage =
            serde_json::from_str(r#"{"contents":[{"data":"WFRBCg=="}]}"#).unwrap();
        assert_eq!(msg.contents.unwrap()[0].data, "WFRBCg==");
        assert!(msg.signatures_valid.is_none());
    }
}
