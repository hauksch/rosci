//! roscid — a REST server over OSCI. Same library, same bridge JVM, same
//! gates as the CLI; exposed as JSON over HTTP for other applications.

mod config;
mod dto;
mod server;
mod supervisor;

use std::time::Duration;

use clap::Parser;
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::config::ServerConfig;

#[derive(Debug, Parser)]
#[command(
    name = "roscid",
    about = "REST server over OSCI — rosci for applications.",
    version
)]
struct Args {
    /// Address to bind. Non-loopback binds require --api-key (a REST
    /// endpoint that signs OSCI messages must not be network-open).
    #[arg(long, env = "OSCI_BIND", default_value = "127.0.0.1:8080")]
    bind: String,

    /// Signing identity (PKCS#12).
    #[arg(long, env = "OSCI_CERT")]
    cert: PathBuf,

    /// Optional separate decrypter bundle for fetched content.
    #[arg(long, env = "OSCI_DECRYPTER_CERT")]
    decrypter_cert: Option<PathBuf>,

    /// PIN for the identity bundle(s).
    #[arg(long, env = "OSCI_CERT_PIN")]
    pin: Option<String>,

    /// Read the PIN from this file instead of the environment.
    #[arg(long, env = "OSCI_PINFILE")]
    pinfile: Option<PathBuf>,

    /// Intermediary entry URL — the server's submission path.
    #[arg(long, env = "OSCI_INTERMEDIARY")]
    intermediary: String,

    /// Intermediary cipher certificate (PEM / base64 DER).
    #[arg(long, env = "OSCI_INTERMEDIARY_CERT")]
    intermediary_cert: PathBuf,

    /// Extra TLS trust anchor for the intermediary connection.
    #[arg(long, env = "OSCI_TLS_CA")]
    tls_ca: Option<PathBuf>,

    /// DVDV extract (JSON); reserved for to.org addressing.
    #[arg(long, env = "OSCI_DVDV_FILE", default_value = "dvdv.json")]
    dvdv_file: PathBuf,

    /// Shared secret for `Authorization: Bearer <key>`. Required for
    /// non-loopback binds.
    #[arg(long, env = "OSCI_API_KEY")]
    api_key: Option<String>,

    /// Per-operation bridge timeout in seconds.
    #[arg(long, env = "OSCI_RESPONSE_TIMEOUT_SECS", default_value_t = 300)]
    response_timeout_secs: u64,

    /// Test mode: plain SOAP transport (loopback intermediaries only).
    #[arg(long)]
    insecure_transport: bool,

    /// Bridge jar override; default is the library's resolution chain.
    #[arg(long, env = "OSCI_BRIDGE_JAR")]
    bridge_jar: Option<PathBuf>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let pin = read_pin(&args);

    let cfg = ServerConfig {
        bind: args.bind.clone(),
        api_key: args.api_key.clone().map(Zeroizing::new),
        cert: args.cert.clone(),
        decrypter_cert: args.decrypter_cert.clone(),
        pin,
        intermediary_url: args.intermediary.clone(),
        intermediary_cert: args.intermediary_cert.clone(),
        tls_ca: args.tls_ca.clone(),
        dvdv_file: args.dvdv_file.clone(),
        response_timeout: Duration::from_secs(args.response_timeout_secs),
        insecure_transport: args.insecure_transport,
        bridge_jar: args.bridge_jar.clone(),
    };
    if let Err(e) = cfg.validate() {
        eprintln!("roscid: configuration error: {e}");
        std::process::exit(2);
    }

    let app = match server::build_app(&cfg) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("roscid: {e}");
            std::process::exit(2);
        }
    };

    tracing::info!("roscid listening on {}", cfg.bind);
    server::serve(app);
}

/// CLI flag > pinfile > `OSCI_CERT_PIN` — the same precedence the CLI
/// documents, wrapped in Zeroizing like every other PIN copy.
fn read_pin(args: &Args) -> Zeroizing<String> {
    if let Some(pin) = &args.pin {
        return Zeroizing::new(pin.clone());
    }
    if let Some(file) = &args.pinfile {
        let content = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read pin file {}: {e}", file.display()));
        return Zeroizing::new(content.trim().to_string());
    }
    if let Some(pin) = &args.pin {
        return Zeroizing::new(pin.clone());
    }
    match std::env::var("OSCI_CERT_PIN") {
        Ok(pin) => Zeroizing::new(pin),
        Err(_) => Zeroizing::new(String::new()),
    }
}
