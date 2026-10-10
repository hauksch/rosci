//! Configuration for the roscid server: flags + `OSCI_*` environment
//! variables, gathered into one fail-fast validated struct.

use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

/// Everything the server needs, validated at startup — a REST server that
/// starts half-configured and fails per request is a distributed way of
/// saying no.
#[derive(Debug)]
pub struct ServerConfig {
    /// Address to bind, e.g. `127.0.0.1:8080`. Non-loopback binds require
    /// an API key (enforced in [`ServerConfig::validate`]).
    pub bind: String,
    /// Shared secret for `Authorization: Bearer <key>`. Mandatory for
    /// non-loopback binds; optional (then unused) on loopback.
    pub api_key: Option<Zeroizing<String>>,
    /// Signing identity (PKCS#12).
    pub cert: PathBuf,
    /// Optional separate decrypter bundle.
    pub decrypter_cert: Option<PathBuf>,
    /// PIN for both bundles.
    pub pin: Zeroizing<String>,
    /// Intermediary entry URL — every operation goes through it.
    pub intermediary_url: String,
    /// Intermediary cipher certificate (PEM / base64 DER file).
    pub intermediary_cert: PathBuf,
    /// Optional extra TLS trust anchor for the intermediary connection.
    pub tls_ca: Option<PathBuf>,
    /// DVDV extract for `to.org` addressing. Reserved: `to.org` is 501
    /// today, but the flag ships so the extract path is stable.
    #[allow(dead_code)]
    pub dvdv_file: PathBuf,
    /// Per-operation bridge timeout. Services should bound this: a wedged
    /// JVM must surface as HTTP 504, not as a connection held open.
    pub response_timeout: Duration,
    /// Test mode: plain SOAP transport (loopback intermediaries only —
    /// the same guard the CLI applies).
    pub insecure_transport: bool,
    /// Bridge jar override; empty = library default resolution.
    pub bridge_jar: Option<PathBuf>,
}

impl ServerConfig {
    /// Fail-closed exposure check: a non-loopback bind without an API key
    /// would let anyone on the network send signed messages as this
    /// machine's identity. Refuse at startup, not at first request.
    pub fn validate(&self) -> Result<(), String> {
        // url_host_is_loopback handles scheme-less "host:port" binds and
        // bracketed IPv6; passing the raw bind keeps one parsing authority.
        if !osci::url_host_is_loopback(&self.bind) && self.api_key.is_none() {
            return Err(format!(
                "bind address {bind} is not loopback and no API key is set \
                 (OSCI_API_KEY) — a REST endpoint that signs OSCI messages \
                 must not be open to the network unauthenticated",
                bind = self.bind
            ));
        }
        Ok(())
    }

    /// Test mode (plain SOAP transport) is only defensible against
    /// loopback intermediaries — the same guard the CLI applies.
    pub fn validate_intermediary_guard(&self) -> Result<(), String> {
        if self.insecure_transport && !osci::url_host_is_loopback(host_of(&self.intermediary_url)) {
            return Err(format!(
                "insecure transport refuses non-loopback intermediary {} — \
                 point at localhost, this is a test-mode-only switch",
                self.intermediary_url
            ));
        }
        Ok(())
    }
}

/// Extracts the host from a `host:port` bind address (IPv6 comes
/// bracketed).
fn host_of(bind: &str) -> &str {
    if let Some(rest) = bind.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_binds_need_no_api_key() {
        for bind in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080"] {
            let cfg = ServerConfig {
                bind: bind.into(),
                api_key: None,
                cert: "/dev/null".into(),
                decrypter_cert: None,
                pin: Zeroizing::new("x".into()),
                intermediary_url: "http://127.0.0.1:1/".into(),
                intermediary_cert: "/dev/null".into(),
                tls_ca: None,
                dvdv_file: "dvdv.json".into(),
                response_timeout: Duration::from_secs(60),
                insecure_transport: false,
                bridge_jar: None,
            };
            assert!(cfg.validate().is_ok(), "{bind} must validate without a key");
        }
    }

    #[test]
    fn network_binds_require_an_api_key() {
        let mk = |key: Option<&str>| ServerConfig {
            bind: "0.0.0.0:8080".into(),
            api_key: key.map(|k| Zeroizing::new(k.into())),
            cert: "/dev/null".into(),
            decrypter_cert: None,
            pin: Zeroizing::new("x".into()),
            intermediary_url: "http://127.0.0.1:1/".into(),
            intermediary_cert: "/dev/null".into(),
            tls_ca: None,
            dvdv_file: "dvdv.json".into(),
            response_timeout: Duration::from_secs(60),
            insecure_transport: false,
            bridge_jar: None,
        };
        assert!(
            mk(None).validate().is_err(),
            "network bind without key must fail"
        );
        assert!(mk(Some("sekrit")).validate().is_ok());
    }

    #[test]
    fn host_of_strips_ipv6_brackets() {
        assert_eq!(super::host_of("127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(super::host_of("[::1]:8080"), "::1");
    }
}
