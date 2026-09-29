//! `osci` — the curl of OSCI.
//!
//! Sends an arbitrary XTA message through OSCI-Transport 1.2 with one
//! command and zero ceremony. The heavy lifting happens in the Java
//! sidecar (see `java/osci-bridge`); this binary is the friendly face.

use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use osci::bridge::{BridgeConfig, BridgeHandle};
use osci::dvdv::{DvdvDirectory, FileDvdv};
use osci::{Error, FetchQuery, Identity, Intermediary, OsciClient, Recipient, Xta};

const ABOUT: &str = "\
The curl of OSCI: send an arbitrary XTA message to any OSCI recipient,
optionally resolved via DVDV, without filing a request in triplicate.

Exit codes: 0 ok · 2 usage/config · 3 DVDV miss · 4 transport/OSCI ·
5 crypto · 6 bridge/internal";

#[derive(Parser)]
#[command(name = "osci", version, about = ABOUT, disable_help_subcommand = true)]
struct Cli {
    /// verbosity: none = warnings, -v = info, -vv = debug, -vvv = trace
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send an XTA message (file path or `-` for stdin).
    Send(SendArgs),
    /// Fetch messages from your postbox.
    Fetch(FetchArgs),
    /// Show the Laufzettel (process card) of a sent message.
    Status(StatusArgs),
    /// Look up recipients in a DVDV extract.
    Dvdv(DvdvArgs),
    /// Print local and bridge version info.
    Version(VersionArgs),
}

/// Arguments every bridged operation shares.
#[derive(Args)]
struct ConnArgs {
    /// Intermediary entry URL (overrides DVDV resolution).
    #[arg(long, env = "OSCI_INTERMEDIARY")]
    intermediary: Option<String>,

    /// Intermediary cipher certificate (PEM/DER file).
    #[arg(long, env = "OSCI_INTERMEDIARY_CERT")]
    intermediary_cert: Option<PathBuf>,

    /// Your signature PKCS#12 bundle.
    #[arg(long, env = "OSCI_CERT")]
    cert: Option<PathBuf>,

    /// Optional separate cipher (decrypter) PKCS#12 bundle.
    #[arg(long, env = "OSCI_DECRYPTER_CERT")]
    decrypter_cert: Option<PathBuf>,

    /// Environment variable holding the PKCS#12 PIN (default OSCI_CERT_PIN).
    #[arg(long, default_value = "OSCI_CERT_PIN")]
    pinenv: String,

    /// File containing the PKCS#12 PIN (alternative to the env var).
    #[arg(long)]
    pinfile: Option<PathBuf>,

    /// PIN on the command line. Convenient, visible in `ps`; you were warned.
    #[arg(long)]
    pin: Option<String>,

    /// Extra TLS trust anchor for the intermediary connection.
    #[arg(long, env = "OSCI_TLS_CA")]
    tls_ca: Option<PathBuf>,

    /// Path to the osci-bridge.jar.
    #[arg(long, env = "OSCI_BRIDGE_JAR", default_value = "osci-bridge.jar")]
    bridge_jar: PathBuf,

    /// Full bridge command, space separated (testing hook).
    #[arg(long, env = "OSCI_BRIDGE_CMD", hide = true)]
    bridge_cmd: Option<String>,
}

#[derive(Args)]
struct SendArgs {
    /// XTA file, or `-` to read from stdin.
    file: String,

    /// Recipient: `cert:<path>` or `dvdv:<org-key>[:<category>]`.
    #[arg(long)]
    to: String,

    #[command(flatten)]
    conn: ConnArgs,

    /// Message subject.
    #[arg(long)]
    subject: Option<String>,

    /// DVDV extract (JSON) for `--to dvdv:...`.
    #[arg(long, env = "OSCI_DVDV_FILE", default_value = "dvdv.json")]
    dvdv_file: PathBuf,

    /// Send unsigned. Bold.
    #[arg(long)]
    no_sign: bool,

    /// Send unencrypted content (transport envelope stays signed).
    #[arg(long)]
    no_encrypt: bool,

    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct FetchArgs {
    /// Fetch only this message id.
    #[arg(long)]
    message_id: Option<String>,

    /// Fetch everything waiting.
    #[arg(long)]
    all: bool,

    #[command(flatten)]
    conn: ConnArgs,

    /// Write attachments to this directory instead of the cwd.
    #[arg(long)]
    out: Option<PathBuf>,

    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct StatusArgs {
    /// The message id whose Laufzettel you want.
    message_id: String,

    #[command(flatten)]
    conn: ConnArgs,

    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DvdvArgs {
    #[command(subcommand)]
    cmd: DvdvCmd,
}

#[derive(Subcommand)]
enum DvdvCmd {
    /// Find entries by organization key.
    Find {
        /// Organizationsschlüssel; omit with --all to list everything.
        #[arg(long)]
        org: Option<String>,

        /// Narrow to one OSCI category.
        #[arg(long)]
        category: Option<String>,

        /// List all entries instead of searching.
        #[arg(long)]
        all: bool,

        /// DVDV extract file.
        #[arg(long, env = "OSCI_DVDV_FILE", default_value = "dvdv.json")]
        file: PathBuf,

        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct VersionArgs {
    /// Fail if the bridge cannot be reached, instead of printing local only.
    #[arg(long)]
    require_bridge: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let result = match cli.cmd {
        Cmd::Send(args) => cmd_send(args),
        Cmd::Fetch(args) => cmd_fetch(args),
        Cmd::Status(args) => cmd_status(args),
        Cmd::Dvdv(args) => cmd_dvdv(args),
        Cmd::Version(args) => cmd_version(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("osci: {err}");
            if let Error::Bridge { feedback, .. } = &err {
                for row in feedback {
                    if row.len() >= 2 {
                        eprintln!("  intermediary feedback: [{}] {}", row[1], row[0]);
                    }
                }
            }
            ExitCode::from(err.exit_code() as u8)
        }
    }
}

fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

// ------------------------------------------------------------------ shared

fn load_pin(conn: &ConnArgs) -> Result<String, Error> {
    if let Some(pin) = &conn.pin {
        return Ok(pin.clone());
    }
    if let Some(file) = &conn.pinfile {
        let pin = std::fs::read_to_string(file)
            .map_err(|e| Error::Config(format!("cannot read pin file {}: {e}", file.display())))?;
        return Ok(pin.trim().to_string());
    }
    std::env::var(&conn.pinenv).map_err(|_| {
        Error::Config(format!(
            "no PIN: set ${}, or use --pinfile / --pin",
            conn.pinenv
        ))
    })
}

fn bridge_config(conn: &ConnArgs) -> BridgeConfig {
    if let Some(cmd) = &conn.bridge_cmd {
        return BridgeConfig::cmd(cmd.split_whitespace());
    }
    BridgeConfig::java_jar(&conn.bridge_jar)
}

fn build_client(conn: &ConnArgs, intermediary: Option<Intermediary>) -> Result<OsciClient, Error> {
    let pin = load_pin(conn)?;
    let identity = Identity::from_p12_files(
        conn.cert
            .as_deref()
            .ok_or_else(|| Error::Config("--cert (PKCS#12) is required".into()))?,
        &pin,
        conn.decrypter_cert.as_deref(),
        Some(&pin),
    )?;

    let mut builder = OsciClient::builder()
        .bridge_config(bridge_config(conn))
        .identity(identity);

    if let Some(intermediary) = intermediary {
        builder = builder.intermediary(intermediary);
    }
    if let Some(ca) = &conn.tls_ca {
        let tls = osci::Tls::default().with_trust_anchor_file(ca)?;
        builder = builder.tls(tls);
    }
    builder.build()
}

fn conn_intermediary(conn: &ConnArgs) -> Result<Option<Intermediary>, Error> {
    match (&conn.intermediary, &conn.intermediary_cert) {
        (Some(url), Some(cert)) => {
            let pem = std::fs::read_to_string(cert).map_err(|e| {
                Error::Config(format!(
                    "cannot read intermediary cert {}: {e}",
                    cert.display()
                ))
            })?;
            Ok(Some(Intermediary::new(url.clone(), pem)))
        }
        (Some(_), None) => Err(Error::Config(
            "--intermediary given without --intermediary-cert".into(),
        )),
        (None, Some(_)) => Err(Error::Config(
            "--intermediary-cert given without --intermediary".into(),
        )),
        (None, None) => Ok(None),
    }
}

fn read_payload(spec: &str) -> Result<Xta, Error> {
    if spec == "-" {
        let bytes = osci::read_all_stdin()?;
        return Ok(Xta::from_bytes("stdin.xta", bytes));
    }
    Xta::from_path(spec)
}

// ---------------------------------------------------------------- commands

fn cmd_send(args: SendArgs) -> Result<(), Error> {
    let xta = read_payload(&args.file)?;
    let pin = load_pin(&args.conn)?;

    // Recipient + possibly the whole intermediary from DVDV.
    let (recipient, dvdv_intermediary) = match parse_to(&args.to)? {
        ToSpec::Cert(path) => (Recipient::from_cipher_cert_file(&path)?, None),
        ToSpec::Dvdv { org_key, category } => {
            let dir = FileDvdv::from_file(&args.dvdv_file).map_err(|e| {
                Error::Config(format!(
                    "{} (needed for --to dvdv:...; --dvdv-file points at the extract)",
                    e
                ))
            })?;
            let (intermediary, recipient) =
                osci::resolve_dvdv(&dir, &org_key, category.as_deref())?;
            (recipient, Some(intermediary))
        }
    };

    // Flag-provided intermediary wins over DVDV (power users, testing).
    let intermediary = conn_intermediary(&args.conn)?.or(dvdv_intermediary);

    let identity = Identity::from_p12_files(
        args.conn
            .cert
            .as_deref()
            .ok_or_else(|| Error::Config("--cert (PKCS#12) is required".into()))?,
        &pin,
        args.conn.decrypter_cert.as_deref(),
        Some(&pin),
    )?;

    let mut builder = OsciClient::builder()
        .bridge_config(bridge_config(&args.conn))
        .identity(identity);
    if let Some(intermediary) = intermediary {
        builder = builder.intermediary(intermediary);
    }
    if let Some(ca) = &args.conn.tls_ca {
        builder = builder.tls(osci::Tls::default().with_trust_anchor_file(ca)?);
    }
    let mut client = builder.build()?;

    let mut send = client.send_xta(xta).recipient(recipient);
    if let Some(subject) = &args.subject {
        send = send.subject(subject.clone());
    }
    if args.no_sign {
        send = send.without_signature();
    }
    if args.no_encrypt {
        send = send.without_encryption();
    }
    let receipt = send.submit()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        println!("message_id: {}", receipt.message_id);
        println!("status:     accepted by intermediary");
    }
    client.shutdown().ok();
    Ok(())
}

fn cmd_fetch(args: FetchArgs) -> Result<(), Error> {
    if !args.all && args.message_id.is_none() {
        return Err(Error::Config("fetch needs --message-id or --all".into()));
    }
    let intermediary = conn_intermediary(&args.conn)?
        .ok_or_else(|| Error::Config("--intermediary + --intermediary-cert are required".into()))?;
    let mut client = build_client(&args.conn, Some(intermediary))?;

    let query = match &args.message_id {
        Some(id) => FetchQuery::ByMessageId(id.clone()),
        None => FetchQuery::All,
    };
    let messages = client.fetch(query)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&messages)?);
        client.shutdown().ok();
        return Ok(());
    }

    let engine = base64::engine::general_purpose::STANDARD;
    let out_dir = args.out.unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| Error::Config(format!("cannot create {}: {e}", out_dir.display())))?;

    let mut wrote = 0usize;
    for msg in &messages {
        println!(
            "message: {} (signatures valid: {})",
            msg.subject.as_deref().unwrap_or("<no subject>"),
            msg.signatures_valid
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".into())
        );
        for contents in [&msg.contents, &msg.encrypted_contents] {
            for content in contents.iter().flatten() {
                let name = content
                    .filename
                    .clone()
                    .unwrap_or_else(|| format!("content-{wrote}.bin"));
                let path = out_dir.join(sanitize_filename(&name));
                let bytes = engine
                    .decode(&content.data)
                    .map_err(|e| Error::BridgeProtocol(format!("bridge sent bad base64: {e}")))?;
                std::fs::write(&path, &bytes).map_err(Error::Io)?;
                println!("  wrote {} ({} bytes)", path.display(), bytes.len());
                wrote += 1;
            }
        }
    }
    if messages.is_empty() {
        println!("postbox empty. enjoy the silence.");
    }
    client.shutdown().ok();
    Ok(())
}

fn cmd_status(args: StatusArgs) -> Result<(), Error> {
    let intermediary = conn_intermediary(&args.conn)?
        .ok_or_else(|| Error::Config("--intermediary + --intermediary-cert are required".into()))?;
    let mut client = build_client(&args.conn, Some(intermediary))?;
    let cards = client.process_card(&args.message_id)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&cards)?);
    } else if cards.is_empty() {
        println!("no process card found for {}", args.message_id);
    } else {
        for card in &cards {
            println!("message_id: {}", card.message_id.as_deref().unwrap_or("?"));
            println!("subject:    {}", card.subject.as_deref().unwrap_or("?"));
            println!("created:    {}", card.creation.as_deref().unwrap_or("?"));
            println!("forwarded:  {}", card.forwarding.as_deref().unwrap_or("?"));
            println!("received:   {}", card.reception.as_deref().unwrap_or("?"));
            for inspection in card.inspections.iter().flatten() {
                println!(
                    "  inspection: {} (online: {})",
                    inspection.subject.as_deref().unwrap_or("?"),
                    inspection
                        .online_checked
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "?".into())
                );
            }
        }
    }
    client.shutdown().ok();
    Ok(())
}

fn cmd_dvdv(args: DvdvArgs) -> Result<(), Error> {
    let DvdvCmd::Find {
        org,
        category,
        all,
        file,
        json,
    } = args.cmd;

    let dir = FileDvdv::from_file(&file)?;
    let entries: Vec<osci::DvdvEntry> = if all || org.is_none() {
        dir.all()
    } else {
        dir.find(org.as_deref().expect("checked"), category.as_deref())?
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    if entries.is_empty() {
        println!("no entries.");
    }
    for e in &entries {
        println!(
            "{}  {}\n  intermediary: {}\n  category: {}",
            e.org_key,
            e.name,
            e.intermediary_url,
            e.category.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn cmd_version(args: VersionArgs) -> Result<(), Error> {
    println!("osci-cli   {}", env!("CARGO_PKG_VERSION"));

    // A bare bridge ping — no identity, no intermediary, no drama.
    let cfg = match std::env::var("OSCI_BRIDGE_CMD") {
        Ok(cmd) => BridgeConfig::cmd(cmd.split_whitespace()),
        Err(_) => BridgeConfig::java_jar(
            std::env::var_os("OSCI_BRIDGE_JAR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("osci-bridge.jar")),
        ),
    };
    match BridgeHandle::spawn(&cfg) {
        Ok(mut bridge) => {
            let rsp = bridge.call(osci::protocol::Request {
                id: String::new(),
                op: "ping",
                intermediary: None,
                identity: None,
                recipient: None,
                subject: None,
                content: None,
                sign: None,
                encrypt: None,
                tls: None,
                selection_mode: None,
                selection_rule: None,
            })?;
            if let Some(versions) = rsp.result.and_then(|r| r.versions) {
                for (k, v) in versions {
                    println!("{k:<11} {v}");
                }
            }
            bridge.shutdown();
            let _ = bridge.wait();
        }
        Err(err) if !args.require_bridge => {
            eprintln!("osci: bridge not reachable, local info only ({err})");
        }
        Err(err) => return Err(err),
    }
    Ok(())
}

// ---------------------------------------------------------------- helpers

enum ToSpec {
    Cert(PathBuf),
    Dvdv {
        org_key: String,
        category: Option<String>,
    },
}

fn parse_to(spec: &str) -> Result<ToSpec, Error> {
    if let Some(path) = spec.strip_prefix("cert:") {
        if path.is_empty() {
            return Err(Error::Config("--to cert: needs a path".into()));
        }
        return Ok(ToSpec::Cert(PathBuf::from(path)));
    }
    if let Some(rest) = spec.strip_prefix("dvdv:") {
        let mut parts = rest.splitn(2, ':');
        let org_key = parts.next().unwrap_or_default().to_string();
        let category = parts.next().map(str::to_string);
        if org_key.is_empty() {
            return Err(Error::Config("--to dvdv: needs an org key".into()));
        }
        return Ok(ToSpec::Dvdv { org_key, category });
    }
    Err(Error::Config(
        "--to must be cert:<path> or dvdv:<org-key>[:<category>]".into(),
    ))
}

/// Keeps fetched filenames from escaping the output directory. We trust
/// the intermediary exactly as far as we can sanitize it.
fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unnamed.bin".into()
    } else {
        cleaned
    }
}
