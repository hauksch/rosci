//! `rosci` — the curl of OSCI.
//!
//! Sends an arbitrary XTA message through OSCI-Transport 1.2 with one
//! command and zero ceremony. The heavy lifting happens in the Java
//! sidecar (see `java/osci-bridge`); this binary is the friendly face.

use std::io::Write as _;
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
#[command(
    name = "rosci",
    version,
    about = ABOUT,
    disable_help_subcommand = true,
    after_help = "Environment: OSCI_JAVA_OPTS passes extra JVM flags to the bridge\n(e.g. -Dorg.slf4j.simpleLogger.defaultLogLevel=debug). See README.md\nfor the full OSCI_* list."
)]
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
#[derive(Args, Default)]
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

    /// TLS client-authentication bundle (PKCS#12) for mutual TLS with the
    /// intermediary. Parsed JVM-side; a wrong PIN surfaces as a transport
    /// error from the bridge.
    #[arg(long, env = "OSCI_TLS_CLIENT_CERT")]
    tls_client_cert: Option<PathBuf>,

    /// PIN for --tls-client-cert (default: empty).
    #[arg(long, env = "OSCI_TLS_CLIENT_PIN")]
    tls_client_pin: Option<String>,

    /// Test mode: disable SOAP-transport encryption/signatures so local
    /// mock intermediaries can parse envelopes. Content crypto stays on.
    /// Refuses non-loopback intermediary hosts unless
    /// --insecure-transport-any-host is also given.
    #[arg(long)]
    insecure_transport: bool,

    /// Explicitly allow --insecure-transport against non-loopback hosts.
    /// If you type this flag, you are the audit finding.
    #[arg(long, requires = "insecure_transport")]
    insecure_transport_any_host: bool,

    /// Path to the osci-bridge.jar. Default: ../lib/osci-bridge.jar next
    /// to the rosci binary (the release layout), else ./osci-bridge.jar.
    #[arg(long, env = "OSCI_BRIDGE_JAR")]
    bridge_jar: Option<PathBuf>,

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

    /// Additional content parts riding in the same Zustellung. Repeatable.
    #[arg(long = "attachment", value_name = "FILE")]
    attachments: Vec<PathBuf>,

    /// Send via EFFI chunked transfer with this many KB per chunk (for
    /// intermediaries with size limits / large payloads).
    #[arg(long, value_name = "KB", value_parser = clap::value_parser!(u64).range(1..=2_097_151))]
    chunk_size_kb: Option<u64>,

    /// XTA MessageMetaData author identifier (Ergänzung; e.g.
    /// `ags:NNNNNNNNNNN`).
    #[arg(long, value_name = "ID")]
    metadata_author: Option<String>,

    /// XTA MessageMetaData reader identifier.
    #[arg(long, value_name = "ID")]
    metadata_reader: Option<String>,

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

    /// Pull the message in EFFI chunks of this many KB (for messages that
    /// were stored chunked).
    #[arg(long, value_name = "KB", value_parser = clap::value_parser!(u64).range(1..=2_097_151))]
    chunk_size_kb: Option<u64>,

    /// Fetch everything waiting. Mutually exclusive with --message-id.
    #[arg(long, conflicts_with = "message_id")]
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

        /// List all entries instead of searching. Mutually exclusive
        /// with --org.
        #[arg(long, conflicts_with = "org")]
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
            eprintln!("rosci: {err}");
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

/// --insecure-transport is a test-mode footgun; the guard makes sure it can
/// only fire at loopback endpoints unless the user takes explicit
/// responsibility with --insecure-transport-any-host.
fn check_insecure_guard(conn: &ConnArgs, url: &str) -> Result<(), Error> {
    if !conn.insecure_transport || conn.insecure_transport_any_host {
        return Ok(());
    }
    if osci::url_host_is_loopback(url) {
        return Ok(());
    }
    Err(Error::Config(format!(
        "--insecure-transport refuses non-loopback intermediaries ({url}). \
         Point at localhost, or pass --insecure-transport-any-host if this \
         is a test endpoint you control."
    )))
}

/// The PIN is wrapped in Zeroizing so every Rust-side copy is scrubbed on
/// drop. What cannot be scrubbed: the JVM-side string residency inside the
/// bridge (documented in docs/AUDIT.md) — the Rust side of the pipe can at
/// least keep its own house in order.
fn load_pin(conn: &ConnArgs) -> Result<zeroize::Zeroizing<String>, Error> {
    if let Some(pin) = &conn.pin {
        return Ok(zeroize::Zeroizing::new(pin.clone()));
    }
    if let Some(file) = &conn.pinfile {
        let pin = std::fs::read_to_string(file)
            .map_err(|e| Error::Config(format!("cannot read pin file {}: {e}", file.display())))?;
        return Ok(zeroize::Zeroizing::new(pin.trim().to_string()));
    }
    std::env::var(&conn.pinenv)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| {
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
    BridgeConfig::java_jar(resolve_bridge_jar(conn.bridge_jar.as_deref()))
}

/// An explicit `--bridge-jar`/`OSCI_BRIDGE_JAR` wins; otherwise the
/// library's default resolution runs (release layout next to the binary,
/// then cwd). Going through the CLI default used to pin a cwd-relative
/// path and defeated that lookup entirely.
fn resolve_bridge_jar(arg: Option<&std::path::Path>) -> PathBuf {
    match arg {
        Some(path) => path.to_path_buf(),
        None => osci::default_jar_path(),
    }
}

fn build_client(conn: &ConnArgs, intermediary: Option<Intermediary>) -> Result<OsciClient, Error> {
    if let Some(intermediary) = &intermediary {
        check_insecure_guard(conn, &intermediary.url)?;
    }
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

    if conn.insecure_transport {
        builder = builder.insecure_transport();
    }
    if let Some(intermediary) = intermediary {
        builder = builder.intermediary(intermediary);
    }
    if let Some(tls) = conn_tls(conn)? {
        builder = builder.tls(tls);
    }
    builder.build()
}

/// TLS knobs from ConnArgs: the trust anchor and, since the standard
/// never met a certificate it couldn't split into one more, the optional
/// mutual-TLS client bundle. `None` when nothing was configured.
fn conn_tls(conn: &ConnArgs) -> Result<Option<osci::Tls>, Error> {
    if conn.tls_ca.is_none() && conn.tls_client_cert.is_none() {
        return Ok(None);
    }
    let mut tls = osci::Tls::default();
    if let Some(ca) = &conn.tls_ca {
        tls = tls.with_trust_anchor_file(ca)?;
    }
    if let Some(cert) = &conn.tls_client_cert {
        let pin = conn.tls_client_pin.as_deref().unwrap_or("");
        tls = tls.with_client_p12_file(cert, pin)?;
    }
    Ok(Some(tls))
}

fn conn_intermediary(conn: &ConnArgs) -> Result<Option<Intermediary>, Error> {
    match (&conn.intermediary, &conn.intermediary_cert) {
        (Some(url), Some(cert)) => {
            let pem = osci::read_certificate_file(cert, "intermediary certificate")?;
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
    if let Some(intermediary) = &intermediary {
        check_insecure_guard(&args.conn, &intermediary.url)?;
    }

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
    if args.conn.insecure_transport {
        builder = builder.insecure_transport();
    }
    if let Some(intermediary) = intermediary {
        builder = builder.intermediary(intermediary);
    }
    if let Some(tls) = conn_tls(&args.conn)? {
        builder = builder.tls(tls);
    }
    let mut client = builder.build()?;

    let mut send = client.send_xta(xta).recipient(recipient);
    for path in &args.attachments {
        let xta = Xta::from_path(path)?;
        send = send.attachment(xta);
    }
    if let Some(kb) = args.chunk_size_kb {
        send = send.chunk_size_kb(kb);
    }
    if let Some(author) = &args.metadata_author {
        send = send.metadata_author(author.clone());
    }
    if let Some(reader) = &args.metadata_reader {
        send = send.metadata_reader(reader.clone());
    }
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
    client.finish();
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
    let messages = client.fetch_with(query, args.chunk_size_kb)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&messages)?);
        client.finish();
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
                let bytes = engine
                    .decode(&content.data)
                    .map_err(|e| Error::BridgeProtocol(format!("bridge sent bad base64: {e}")))?;
                let path = write_fetched_file(&out_dir, &name, &bytes)?;
                println!("  wrote {} ({} bytes)", path.display(), bytes.len());
                wrote += 1;
            }
        }
    }
    if messages.is_empty() {
        println!("postbox empty. enjoy the silence.");
    }
    client.finish();
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
    client.finish();
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
    let entries: Vec<osci::DvdvEntry> = if all {
        dir.all()
    } else if let Some(org) = &org {
        dir.find(org, category.as_deref())?
    } else {
        // Silence is not a search criterion. Ask for something.
        return Err(Error::Config("dvdv find needs --org or --all".into()));
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
    println!("rosci      {}", env!("CARGO_PKG_VERSION"));

    // A bare bridge ping — no identity, no intermediary, no drama.
    let cfg = match std::env::var("OSCI_BRIDGE_CMD") {
        Ok(cmd) => BridgeConfig::cmd(cmd.split_whitespace()),
        // default_jar_path() consults OSCI_BRIDGE_JAR itself, then the
        // release layout next to this binary, then the cwd.
        Err(_) => BridgeConfig::java_jar(osci::default_jar_path()),
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
                attachments: None,
                chunk_size_kb: None,
                metadata_author: None,
                metadata_reader: None,
                sign: None,
                encrypt: None,
                insecure_transport: None,
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
            eprintln!("rosci: bridge not reachable, local info only ({err})");
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

/// Writes fetched bytes without ever overwriting: an existing target (and
/// that includes a pre-planted symlink — `create_new` refuses those too)
/// gets a numbered sibling instead. The intermediary chooses the filename;
/// it does not get to clobber your `.bashrc` with it.
fn write_fetched_file(
    out_dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
) -> Result<PathBuf, Error> {
    let sanitized = sanitize_filename(name);
    let path = std::path::Path::new(&sanitized);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| sanitized.clone());
    let ext = path.extension().map(|e| e.to_string_lossy().into_owned());

    for attempt in 0..1000u32 {
        let candidate = match (&ext, attempt) {
            (_, 0) => out_dir.join(&sanitized),
            (None, n) => out_dir.join(format!("{stem}-{n}")),
            (Some(e), n) => out_dir.join(format!("{stem}-{n}.{e}")),
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(bytes).map_err(Error::Io)?;
                return Ok(candidate);
            }
            // Taken by a real file, a symlink, or anything else that exists:
            // fall through to the next candidate name.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("{sanitized}: no free name after 1000 attempts"),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_keeps_the_tame_and_tames_the_rest() {
        assert_eq!(sanitize_filename("meldung.xta"), "meldung.xta");
        assert_eq!(sanitize_filename("a-b_C.d"), "a-b_C.d");
        // The classic directory-escape attempt, defanged:
        assert_eq!(sanitize_filename("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(
            sanitize_filename("../../../etc/passwd"),
            ".._.._.._etc_passwd"
        );
        assert_eq!(
            sanitize_filename("nachricht mit leerzeichen.xml"),
            "nachricht_mit_leerzeichen.xml"
        );
        assert_eq!(sanitize_filename("böse ümlaute.txt"), "b_se__mlaute.txt");
        assert_eq!(sanitize_filename(""), "unnamed.bin");
        assert_eq!(sanitize_filename("///"), "___");
    }

    #[test]
    fn parse_to_accepts_cert_and_dvdv_forms() {
        assert!(
            matches!(parse_to("cert:empfaenger.cer").unwrap(), ToSpec::Cert(p) if p.as_path() == std::path::Path::new("empfaenger.cer"))
        );
        assert!(matches!(
            parse_to("dvdv:0241100012345").unwrap(),
            ToSpec::Dvdv { org_key, category: None } if org_key == "0241100012345"
        ));
        assert!(matches!(
            parse_to("dvdv:0241100012345:osci").unwrap(),
            ToSpec::Dvdv { org_key, category: Some(cat) } if org_key == "0241100012345" && cat == "osci"
        ));
    }

    #[test]
    fn parse_to_rejects_garbage() {
        for bad in ["telefon:040-123456", "cert:", "dvdv:", "dvdv::kat", "nix"] {
            assert!(parse_to(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn read_payload_missing_file_is_config_error() {
        let err = read_payload("existiert-nicht.xta").unwrap_err();
        assert!(matches!(err, Error::Config(ref c) if c.contains("cannot read XTA")));
    }
}

#[cfg(test)]
mod proptests {
    use super::sanitize_filename;
    use proptest::prelude::*;

    proptest! {
        /// The sanitizer must be idempotent: a second pass never changes
        /// anything, and the result always lives in the safe alphabet.
        #[test]
        fn sanitize_is_idempotent_and_closed(name in "\\PC{0,64}") {
            let once = sanitize_filename(&name);
            let twice = sanitize_filename(&once);
            prop_assert_eq!(&once, &twice);
            prop_assert!(!once.is_empty());
            prop_assert!(once.chars().all(|c|
                c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')));
        }
    }
}

#[cfg(test)]
mod conn_tls_tests {
    use super::*;

    #[test]
    fn conn_tls_is_none_when_nothing_is_configured() {
        assert!(conn_tls(&ConnArgs::default()).unwrap().is_none());
    }

    #[test]
    fn conn_tls_fails_on_missing_trust_anchor_file() {
        let conn = ConnArgs {
            tls_ca: Some(std::path::PathBuf::from("/gibt-es-nicht/ca.pem")),
            ..ConnArgs::default()
        };
        assert!(conn_tls(&conn).is_err());
    }

    #[test]
    fn conn_tls_carries_client_bundle_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("client.p12");
        std::fs::write(&p12, [1u8, 2, 3]).unwrap();
        let conn = ConnArgs {
            tls_client_cert: Some(p12),
            tls_client_pin: Some("pin".into()),
            ..ConnArgs::default()
        };
        let tls = conn_tls(&conn).unwrap().expect("tls configured");
        assert!(tls.client_p12_b64.is_some());
        assert!(tls.client_pin.is_some());
        assert!(tls.trust_anchors.is_empty());
    }

    #[test]
    fn conn_tls_combines_anchor_and_client_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(
            &ca,
            "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let p12 = dir.path().join("client.p12");
        std::fs::write(&p12, [9u8]).unwrap();
        let conn = ConnArgs {
            tls_ca: Some(ca),
            tls_client_cert: Some(p12),
            ..ConnArgs::default()
        };
        let tls = conn_tls(&conn).unwrap().expect("tls configured");
        assert_eq!(tls.trust_anchors.len(), 1);
        assert!(tls.client_p12_b64.is_some());
    }
}

#[cfg(test)]
mod jar_resolution_tests {
    use super::resolve_bridge_jar;
    use std::path::{Path, PathBuf};

    #[test]
    fn explicit_jar_wins_over_library_default() {
        let p = resolve_bridge_jar(Some(Path::new("/opt/dist/lib/osci-bridge.jar")));
        assert_eq!(p, PathBuf::from("/opt/dist/lib/osci-bridge.jar"));
    }

    #[test]
    fn absent_jar_defers_to_the_library_default() {
        // The library resolves OSCI_BRIDGE_JAR, then the exe-relative
        // release layout, then cwd — the exact chain the CLI used to
        // short-circuit with a cwd-relative default_value.
        let p = resolve_bridge_jar(None);
        assert_eq!(p, osci::default_jar_path());
    }
}

#[cfg(test)]
mod fetch_write_tests {
    use super::write_fetched_file;

    #[test]
    fn identical_names_get_numbered_siblings_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let first = write_fetched_file(dir.path(), "m.xta", b"eins").unwrap();
        assert_eq!(first.file_name().unwrap(), "m.xta");
        let second = write_fetched_file(dir.path(), "m.xta", b"zwei").unwrap();
        assert_eq!(second.file_name().unwrap(), "m-1.xta");
        // The first write is untouched — no silent clobbering.
        assert_eq!(std::fs::read(&first).unwrap(), b"eins");
        assert_eq!(std::fs::read(&second).unwrap(), b"zwei");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_targets_are_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"original").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("link.txt")).unwrap();

        let out = write_fetched_file(dir.path(), "link.txt", b"boese").unwrap();
        // The write landed in a sibling, not through the symlink…
        assert_eq!(out.file_name().unwrap(), "link-1.txt");
        // …and the symlink's target still carries its original bytes.
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
    }

    #[test]
    fn dotfiles_keep_their_name_and_still_do_not_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let first = write_fetched_file(dir.path(), ".bashrc", b"boser alias").unwrap();
        assert_eq!(first.file_name().unwrap(), ".bashrc");
        let second = write_fetched_file(dir.path(), ".bashrc", b"noch einer").unwrap();
        // Path::file_stem treats a leading dot as part of the stem, so the
        // sibling is ".bashrc-1" — not "-1.bashrc".
        assert_eq!(second.file_name().unwrap(), ".bashrc-1");
        assert_eq!(std::fs::read(&first).unwrap(), b"boser alias");
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("gibt-es-nicht.txt", dir.path().join("dangling.txt")).unwrap();
        let out = write_fetched_file(dir.path(), "dangling.txt", b"x").unwrap();
        assert_eq!(out.file_name().unwrap(), "dangling-1.txt");
        assert!(!dir.path().join("gibt-es-nicht.txt").exists());
    }
}
