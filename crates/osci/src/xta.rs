//! XTA payload handling. The philosophy: bytes in, bytes out, zero parsing.
//!
//! We peek at the root element purely to warn if the file doesn't look like
//! XTA — a courtesy, not a validation. If you want to send your grocery
//! list through OSCI, that is between you and your intermediary.

use std::io::Read;
use std::path::Path;

use tracing::warn;

use crate::error::Error;

/// An XTA (or, frankly, any) payload destined for an OSCI message.
#[derive(Debug, Clone)]
pub struct Xta {
    /// Filename used for the OSCI attachment reference.
    pub filename: String,
    /// The bytes. Sacred, opaque, unopened.
    pub data: Vec<u8>,
}

impl Xta {
    /// Reads the payload from a file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let data = std::fs::read(path)
            .map_err(|e| Error::Config(format!("cannot read XTA file {}: {e}", path.display())))?;
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "message.xta".to_string());
        Ok(Self::warning_checked(filename, data))
    }

    /// Builds a payload from raw bytes.
    pub fn from_bytes(filename: impl Into<String>, data: Vec<u8>) -> Self {
        Self::warning_checked(filename.into(), data)
    }

    fn warning_checked(filename: String, data: Vec<u8>) -> Self {
        if let Some(root) = sniff_root_element(&data) {
            if !root.eq_ignore_ascii_case("XTA") {
                warn!(
                    "payload root element is <{root}>, not <XTA> — sending it anyway, \
                     but double-check you picked the right file"
                );
            }
        } else {
            warn!(
                "payload does not look like XML at all — sending anyway; \
                 OSCI is not the post office, it will not return to sender"
            );
        }
        Self { filename, data }
    }

    pub(crate) fn to_payload(&self) -> crate::protocol::Payload {
        use base64::Engine as _;
        crate::protocol::Payload {
            filename: Some(self.filename.clone()),
            content_type: Some("application/octet-stream".to_string()),
            data: base64::engine::general_purpose::STANDARD.encode(&self.data),
        }
    }
}

/// Best-effort root element sniff: finds the first element tag in an XML
/// document, skipping declarations, comments, PIs and doctypes. Returns
/// `None` for anything that doesn't smell like XML.
pub fn sniff_root_element(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            match bytes.get(i + 1) {
                Some(b'?') => {
                    // XML declaration / processing instruction: skip to '?>'
                    if let Some(end) = find(bytes, i, b"?>") {
                        i = end + 2;
                        continue;
                    }
                    return None;
                }
                Some(b'!') => {
                    // comment or doctype: skip to '>'
                    let end = find(bytes, i, b">")?;
                    i = end + 1;
                    continue;
                }
                Some(c) if c.is_ascii_alphabetic() || *c == b'_' => {
                    // element: read the name
                    let start = i + 1;
                    let mut end = start;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_alphanumeric()
                            || bytes[end] == b'_'
                            || bytes[end] == b'-'
                            || bytes[end] == b':')
                    {
                        end += 1;
                    }
                    return Some(text[start..end].to_string());
                }
                _ => return None,
            }
        }
        // Non-whitespace before the first tag disqualifies the document.
        if !bytes[i].is_ascii_whitespace() {
            return None;
        }
        i += 1;
    }
    None
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Reads all of stdin — the `osci send -` code path.
pub fn read_all_stdin() -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).map_err(Error::Io)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_xta_root() {
        assert_eq!(
            sniff_root_element(b"<?xml version=\"1.0\"?>\n<XTA xmlns=\"x\">hi</XTA>"),
            Some("XTA".to_string())
        );
    }

    #[test]
    fn sniffs_namespaced_and_prefixed_roots() {
        assert_eq!(
            sniff_root_element(b"<xta:XTA xmlns:xta=\"urn:x\">x</xta:XTA>"),
            Some("xta:XTA".to_string())
        );
        assert_eq!(
            sniff_root_element(b"<!-- kommentar --><meldung>M</meldung>"),
            Some("meldung".to_string())
        );
    }

    #[test]
    fn skips_doctype_and_declaration() {
        assert_eq!(
            sniff_root_element(b"<?xml version=\"1.1\" encoding=\"UTF-8\"?>\n<!DOCTYPE XTA SYSTEM \"xta.dtd\">\n<XTA/>"),
            Some("XTA".to_string())
        );
    }

    #[test]
    fn rejects_non_xml() {
        assert_eq!(sniff_root_element(b"just some text, ehrlich"), None);
        assert_eq!(sniff_root_element(b""), None);
        assert_eq!(sniff_root_element(b"\n  \t\n"), None);
        assert_eq!(sniff_root_element(b"< not-a-tag"), None);
    }

    #[test]
    fn payload_carries_opaque_bytes() {
        let xta = Xta::from_bytes("m.xta", b"\x00\x01\xffplain not utf8".to_vec());
        let payload = xta.to_payload();
        assert_eq!(payload.filename.as_deref(), Some("m.xta"));
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload.data)
            .unwrap();
        assert_eq!(decoded, b"\x00\x01\xffplain not utf8");
    }
}
