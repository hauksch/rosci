//! Error taxonomy. Five families, mapped to process exit codes so shell
//! scripts can branch on them without parsing German SOAP fault strings —
//! the traditional method, may it rest in peace.

use std::fmt;

/// Which family of thing went wrong, as reported by the bridge or detected
/// locally. Mirrors the bridge's own kinds one-to-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeErrorKind {
    /// Malformed request (missing fields, bad selection mode, ...).
    Protocol,
    /// Certificates, keys, signing, decryption.
    Crypto,
    /// Network / intermediary unreachable.
    Transport,
    /// The intermediary understood us and said "nein" (feedback codes).
    Osci,
    /// Anything we didn't anticipate. The bureaucratic equivalent of
    /// "sie müssen das Formular X-42 ausfüllen", without the form.
    Internal,
}

impl BridgeErrorKind {
    /// Parses a bridge-reported kind string; unknown strings map to Internal.
    pub fn parse(s: &str) -> Self {
        match s {
            "protocol" => Self::Protocol,
            "crypto" => Self::Crypto,
            "transport" => Self::Transport,
            "osci" => Self::Osci,
            _ => Self::Internal,
        }
    }

    /// The wire representation of this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Crypto => "crypto",
            Self::Transport => "transport",
            Self::Osci => "osci",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for BridgeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything that can go wrong in this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid usage or configuration on our side (missing flags, bad files).
    #[error("configuration error: {0}")]
    Config(String),

    /// The bridge process could not be spawned (no java? jar missing?).
    #[error("cannot start bridge process: {0}")]
    BridgeSpawn(String),

    /// The bridge died or produced output that violates the line protocol.
    #[error("bridge protocol violation: {0}")]
    BridgeProtocol(String),

    /// The bridge did not answer within the configured timeout.
    #[error(
        "bridge timed out after {timeout_ms} ms — the intermediary is probably still stamping"
    )]
    BridgeTimeout {
        /// How long we waited, in milliseconds.
        timeout_ms: u64,
    },

    /// The bridge reported a structured failure.
    #[error("{kind}: {message}")]
    Bridge {
        /// Which family of failure the bridge reported.
        kind: BridgeErrorKind,
        /// Human-readable failure detail.
        message: String,
        /// Raw OSCI feedback rows (`[text, code]`) if the intermediary
        /// rejected the request; the paper trail, as it were.
        feedback: Vec<Vec<String>>,
    },

    /// I/O problems on our side (reading the XTA file, for example).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Serde problems (should be impossible with our own types).
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A DVDV lookup failed or found nothing.
    #[error("dvdv lookup failed: {0}")]
    DvdvLookup(String),
}

impl Error {
    /// Process exit code for the CLI. Documented, stable, boring:
    ///
    /// | code | meaning                                    |
    /// |------|--------------------------------------------|
    /// | 0    | success                                    |
    /// | 2    | usage / configuration error                |
    /// | 3    | DVDV lookup failure                        |
    /// | 4    | transport / OSCI rejection                 |
    /// | 5    | crypto problem                             |
    /// | 6    | bridge protocol violation or internal bug |
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => 2,
            Error::DvdvLookup(_) => 3,
            Error::Bridge {
                kind: BridgeErrorKind::Transport,
                ..
            }
            | Error::Bridge {
                kind: BridgeErrorKind::Osci,
                ..
            } => 4,
            Error::Bridge {
                kind: BridgeErrorKind::Crypto,
                ..
            } => 5,
            Error::BridgeSpawn(_)
            | Error::BridgeProtocol(_)
            | Error::BridgeTimeout { .. }
            | Error::Bridge {
                kind: BridgeErrorKind::Internal,
                ..
            }
            | Error::Bridge {
                kind: BridgeErrorKind::Protocol,
                ..
            } => 6,
            Error::Io(_) | Error::Serde(_) => 6,
        }
    }
}

impl Error {
    /// Constructor used by the bridge handle on timeouts.
    pub(crate) fn bridge_timeout(ms: u64) -> Self {
        Error::BridgeTimeout { timeout_ms: ms }
    }
}
