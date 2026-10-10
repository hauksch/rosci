//! REST request bodies. Deliberately mirroring the CLI's capabilities so
//! the two front ends never drift apart — `docs/REST-API.md` is the
//! contract.

/// `to`: addressed either by inline certificate (PEM / base64 DER) or by
/// DVDV org key against the server's configured extract.
#[derive(Debug, serde::Deserialize)]
pub struct ToSpec {
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    /// Reserved for to.org addressing (501 today).
    #[serde(default)]
    #[allow(dead_code)]
    pub category: Option<String>,
}

impl ToSpec {
    /// Exactly one addressing form — silently picking one over the other
    /// is how integration tests start lying.
    pub fn validate(&self) -> Result<(), String> {
        match (self.cert.as_deref(), self.org.as_deref()) {
            (Some(_), Some(_)) => Err("to: cert and org are mutually exclusive".into()),
            (None, None) => Err("to: one of cert or org is required".into()),
            _ => Ok(()),
        }
    }
}

/// A content part: the main payload and any attachments share this shape.
#[derive(Debug, serde::Deserialize)]
pub struct ContentPart {
    #[serde(default)]
    pub filename: Option<String>,
    /// Forwarded as `application/octet-stream` in v1 — the field rides
    /// along for API compatibility but the bridge doesn't differentiate
    /// yet.
    #[serde(default)]
    #[allow(dead_code)]
    pub content_type: Option<String>,
    /// Base64-encoded bytes, treated as opaque by everything involved.
    pub data: String,
}

impl ContentPart {
    /// `data` is the only mandatory part; an empty payload is a typo, not
    /// a message.
    pub fn validate(&self, label: &str) -> Result<(), String> {
        if self.data.is_empty() {
            return Err(format!("{label}: content data is empty"));
        }
        Ok(())
    }
}

/// The 200-response body of POST /v1/send — the same fields the CLI's
/// `--json` output carries.
#[derive(Debug, serde::Serialize)]
pub struct SendOk {
    pub message_id: String,
    pub response_signed: Option<bool>,
    pub feedback: Option<Vec<Vec<String>>>,
}

/// POST /v1/send
#[derive(Debug, serde::Deserialize)]
pub struct SendBody {
    pub to: ToSpec,
    pub content: ContentPart,
    #[serde(default)]
    pub attachments: Vec<ContentPart>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub chunk_size_kb: Option<u64>,
    #[serde(default = "default_true")]
    pub sign: bool,
    #[serde(default = "default_true")]
    pub encrypt: bool,
}

/// POST /v1/fetch
#[derive(Debug, serde::Deserialize)]
pub struct FetchBody {
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub all: bool,
}

impl FetchBody {
    /// Exactly one selection — the bridge would treat a missing mode as
    /// "unset" and real managers answer 9803 to that.
    pub fn validate(&self) -> Result<(), String> {
        if self.all == self.message_id.is_some() {
            return Err("fetch: exactly one of message_id or all is required".into());
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_spec_requires_exactly_one_addressing_form() {
        assert!(ToSpec {
            cert: Some("c".into()),
            org: None,
            category: None
        }
        .validate()
        .is_ok());
        assert!(ToSpec {
            cert: None,
            org: Some("0241".into()),
            category: None
        }
        .validate()
        .is_ok());
        assert!(ToSpec {
            cert: Some("c".into()),
            org: Some("0241".into()),
            category: None
        }
        .validate()
        .is_err());
        assert!(ToSpec {
            cert: None,
            org: None,
            category: None
        }
        .validate()
        .is_err());
    }

    #[test]
    fn fetch_body_requires_exactly_one_selection() {
        assert!(FetchBody {
            message_id: Some("m".into()),
            all: false
        }
        .validate()
        .is_ok());
        assert!(FetchBody {
            message_id: None,
            all: true
        }
        .validate()
        .is_ok());
        assert!(FetchBody {
            message_id: Some("m".into()),
            all: true
        }
        .validate()
        .is_err());
        assert!(FetchBody {
            message_id: None,
            all: false
        }
        .validate()
        .is_err());
    }
}
