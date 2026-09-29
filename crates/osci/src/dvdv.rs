//! DVDV recipient resolution.
//!
//! The DVDV (Deutsches Verwaltungsdiensteverzeichnis) is where recipient
//! certificates and intermediary endpoints live. The full online client
//! speaks OAuth against the FITKO REST API — which needs registered
//! client credentials, and this project leaves no online traces by
//! design. So the trait below is the seam: `FileDvdv` resolves entries
//! from a local JSON extract today; a future `BridgeDvdv` (via the
//! FITKO dvdv-bibliothek-java already wrapped in our bridge jar) can be
//! dropped in without touching the CLI.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// One resolved DVDV entry: enough to address and send.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DvdvEntry {
    /// Organisationsschlüssel, e.g. `"02411000012345"`.
    pub org_key: String,
    /// Human-readable name of the organization.
    pub name: String,
    /// OSCI category, when the entry is category-scoped.
    #[serde(default)]
    pub category: Option<String>,
    /// Intermediary entry URL.
    pub intermediary_url: String,
    /// Intermediary cipher certificate (PEM or base64 DER).
    pub intermediary_cipher_cert: String,
    /// Recipient cipher certificate (PEM or base64 DER).
    pub recipient_cipher_cert: String,
}

/// A directory of recipients. Implement this against whatever source of
/// truth you're allowed to talk to.
pub trait DvdvDirectory {
    /// Find entries for an organization key, optionally narrowed by category.
    fn find(&self, org_key: &str, category: Option<&str>) -> Result<Vec<DvdvEntry>, Error>;
}

/// File-backed directory: a JSON array of [`DvdvEntry`] objects. Fully
/// offline, fully auditable, refreshable by whatever process is allowed
/// to talk to the real DVDV.
#[derive(Debug)]
pub struct FileDvdv {
    entries: Vec<DvdvEntry>,
    #[allow(dead_code)]
    source: PathBuf,
}

impl FileDvdv {
    /// Loads the directory from a JSON file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::DvdvLookup(format!("cannot read {}: {e}", path.display())))?;
        let entries: Vec<DvdvEntry> = serde_json::from_str(&raw)
            .map_err(|e| Error::DvdvLookup(format!("invalid DVDV file {}: {e}", path.display())))?;
        Ok(Self {
            entries,
            source: path.to_path_buf(),
        })
    }

    /// Builds a directory from entries directly (tests, tooling).
    pub fn from_entries(entries: Vec<DvdvEntry>) -> Self {
        Self {
            entries,
            source: PathBuf::from("<in-memory>"),
        }
    }

    /// All entries, sorted by org key. For `osci dvdv find --all`.
    pub fn all(&self) -> Vec<DvdvEntry> {
        let mut all = self.entries.clone();
        all.sort_by(|a, b| a.org_key.cmp(&b.org_key));
        all
    }
}

impl DvdvDirectory for FileDvdv {
    fn find(&self, org_key: &str, category: Option<&str>) -> Result<Vec<DvdvEntry>, Error> {
        let mut hits: Vec<DvdvEntry> = self
            .entries
            .iter()
            .filter(|e| e.org_key == org_key)
            .filter(|e| match category {
                Some(c) => e.category.as_deref() == Some(c),
                None => true,
            })
            .cloned()
            .collect();
        if hits.is_empty() {
            return Err(Error::DvdvLookup(format!(
                "no DVDV entry for org key {org_key}{}",
                category
                    .map(|c| format!(" (category {c})"))
                    .unwrap_or_default()
            )));
        }
        hits.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(hits)
    }
}

/// Verifies the structural sanity of an entry before we let it near a message.
pub fn validate_entry(entry: &DvdvEntry) -> Result<(), Error> {
    if entry.org_key.trim().is_empty() {
        return Err(Error::DvdvLookup("entry has empty org_key".into()));
    }
    if !entry.intermediary_url.starts_with("http://")
        && !entry.intermediary_url.starts_with("https://")
    {
        return Err(Error::DvdvLookup(format!(
            "entry {} has non-http intermediary url {:?}",
            entry.org_key, entry.intermediary_url
        )));
    }
    if entry.intermediary_cipher_cert.trim().is_empty()
        || entry.recipient_cipher_cert.trim().is_empty()
    {
        return Err(Error::DvdvLookup(format!(
            "entry {} is missing certificate material",
            entry.org_key
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(org: &str, category: Option<&str>) -> DvdvEntry {
        DvdvEntry {
            org_key: org.into(),
            name: format!("Behörde {org}"),
            category: category.map(str::to_string),
            intermediary_url: "https://ks.example/entry".into(),
            intermediary_cipher_cert: "CERT".into(),
            recipient_cipher_cert: "CERT".into(),
        }
    }

    #[test]
    fn file_directory_finds_by_key_and_category() {
        let dir = FileDvdv::from_entries(vec![
            entry("0241100001", None),
            entry("0241100002", Some("osci")),
            entry("0241100002", Some("egvp")),
        ]);

        assert_eq!(dir.find("0241100001", None).unwrap().len(), 1);
        assert_eq!(dir.find("0241100002", None).unwrap().len(), 2);
        assert_eq!(dir.find("0241100002", Some("osci")).unwrap().len(), 1);
        assert!(dir.find("9999", None).is_err());
        assert!(dir.find("0241100002", Some("mail")).is_err());
    }

    #[test]
    fn file_directory_parses_json() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"[{"org_key":"01","name":"Testamt","intermediary_url":"https://x/y",
                "intermediary_cipher_cert":"a","recipient_cipher_cert":"b"}]"#,
        )
        .unwrap();
        let dir = FileDvdv::from_file(tmp.path()).unwrap();
        let hits = dir.find("01", None).unwrap();
        assert_eq!(hits[0].name, "Testamt");
        assert!(hits[0].category.is_none());
    }

    #[test]
    fn validation_rejects_broken_entries() {
        let mut e = entry("01", None);
        assert!(validate_entry(&e).is_ok());
        e.intermediary_url = "ftp://kein-http".into();
        assert!(validate_entry(&e).is_err());
        let mut e2 = entry("", None);
        e2.org_key = "  ".into();
        assert!(validate_entry(&e2).is_err());
        let mut e3 = entry("02", None);
        e3.recipient_cipher_cert = String::new();
        assert!(validate_entry(&e3).is_err());
    }

    #[test]
    fn broken_file_is_a_dvdv_error() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "definitely not json").unwrap();
        let err = FileDvdv::from_file(tmp.path()).unwrap_err();
        assert!(matches!(err, Error::DvdvLookup(_)));
    }
}
