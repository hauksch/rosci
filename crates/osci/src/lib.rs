//! `osci` — the curl of OSCI.
//!
//! A small, boring, well-lit API around the Governikus OSCI-Transport-1.2
//! Java library (`de.osci:osci-bibliothek-lib`). The Java side runs as a
//! sidecar process ("the bridge") speaking a one-line-JSON protocol over
//! stdio; this crate spawns it, drives it, and maps its errors into types
//! that don't require a correspondence course in SOAP fault codes.
//!
//! Typical use:
//!
//! ```no_run
//! # fn main() -> Result<(), osci::Error> {
//! use osci::{OsciClient, Xta, Recipient};
//!
//! let mut client = OsciClient::builder()
//!     .intermediary_url("https://intermediary.example/entry")
//!     .intermediary_cipher_cert_pem(std::fs::read_to_string("intermediary.cer")?)
//!     .signer_p12_file("client.p12", "123456")?
//!     .build()?;
//!
//! let receipt = client
//!     .send_xta(Xta::from_path("meldung.xta")?)
//!     .recipient(Recipient::from_cipher_cert_file("recipient.cer")?)
//!     .subject("XMeld 2.4 Anzeige")
//!     .submit()?;
//!
//! println!("message id: {}", receipt.message_id);
//! # Ok(())
//! # }
//! ```
//!
//! Error taxonomy and process exit codes: see [`Error`]. The wire protocol
//! with the bridge is documented in `docs/PROTOCOL.md` and versioned.

pub mod bridge;
mod client;
mod config;
pub mod dvdv;
mod error;
pub mod protocol;
mod xta;

pub use bridge::{BridgeConfig, BridgeHandle};
pub use client::{resolve_dvdv, FetchQuery, OsciClient, Recipient, SendBuilder};
pub use config::{Identity, Intermediary, Tls};
pub use dvdv::{DvdvDirectory, DvdvEntry, FileDvdv};
pub use error::{BridgeErrorKind, Error};
pub use protocol::{FetchedContent, FetchedMessage, ProcessCard, Receipt, VersionInfo};
pub use xta::{read_all_stdin, sniff_root_element, Xta};

/// Re-exported for consumers that want to serialize receipts themselves.
pub use serde_json;
