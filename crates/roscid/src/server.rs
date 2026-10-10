//! The HTTP layer: tiny_http loop, Bearer auth, routing and the error
//! envelope. Thin on purpose — every OSCI decision lives in the `osci`
//! library; this file only decides what HTTP status a given library error
//! becomes.

use std::io::Read;
use std::sync::{Arc, Mutex};

use osci::OsciClient;
use serde_json::json;

use crate::config::ServerConfig;
use crate::dto::{FetchBody, SendBody};
use crate::supervisor::Supervisor;

/// REST bodies are capped: base64 inflates payloads by ~4/3 and a fetch
/// response carries full content — 256 MiB covers every non-chunked use
/// and anything beyond should use the chunked CLI flow anyway.
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

pub struct App {
    pub server: tiny_http::Server,
    pub supervisor: Mutex<Supervisor>,
    pub api_key: Option<String>,
}

pub fn build_app(cfg: &ServerConfig) -> Result<Arc<App>, String> {
    cfg.validate()?;
    cfg.validate_intermediary_guard()?;
    let server = tiny_http::Server::http(cfg.bind.clone())
        .map_err(|e| format!("cannot bind {}: {e}", cfg.bind))?;

    let cert = cfg.cert.clone();
    let decrypter_cert = cfg.decrypter_cert.clone();
    let pin = cfg.pin.clone();
    let url = cfg.intermediary_url.clone();
    let intermed_cert = cfg.intermediary_cert.clone();
    let tls_ca = cfg.tls_ca.clone();
    let response_timeout = cfg.response_timeout;
    let insecure_transport = cfg.insecure_transport;
    let jar = cfg.bridge_jar.clone();

    let build = move || -> Result<OsciClient, osci::Error> {
        let intermed_cert =
            osci::read_certificate_file(&intermed_cert, "intermediary certificate")?;
        let mut builder = osci::OsciClient::builder()
            .intermediary_url(url.clone())
            .intermediary_cipher_cert_pem(intermed_cert)
            .response_timeout(response_timeout);
        builder = match &decrypter_cert {
            Some(decrypter) => builder.signer_and_decrypter_p12_files(
                &cert,
                pin.as_str(),
                decrypter,
                pin.as_str(),
            )?,
            None => builder.signer_p12_file(&cert, pin.as_str())?,
        };
        if let Some(ca) = &tls_ca {
            builder = builder.tls(osci::Tls::default().with_trust_anchor_file(ca)?);
        }
        if let Some(jar) = &jar {
            builder = builder.bridge_config(osci::BridgeConfig::java_jar(jar));
        }
        if insecure_transport {
            builder = builder.insecure_transport();
        }
        builder.build()
    };

    Ok(Arc::new(App {
        server,
        supervisor: Mutex::new(Supervisor::new(build)),
        api_key: cfg.api_key.as_ref().map(|k| k.to_string()),
    }))
}

/// Blocks for the lifetime of the process: worker threads serve requests,
/// the main thread waits for SIGTERM/SIGINT and shuts the bridge down
/// politely. A daemon that orphans its JVM child is a finding waiting to
/// be filed.
pub fn serve(app: Arc<App>) -> ! {
    const WORKERS: usize = 4;
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let app = app.clone();
        handles.push(std::thread::spawn(move || worker_loop(app)));
    }

    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ])
    .expect("register signal handlers");
    let sig = signals.wait().next();
    if let Some(sig) = sig {
        tracing::info!("received signal {sig}; shutting down bridge and exiting");
    }

    if let Ok(mut supervisor) = app.supervisor.lock() {
        supervisor.shutdown();
    }
    // Workers are blocked on recv; exiting the process reclaims them.
    std::process::exit(0);
}

fn worker_loop(app: Arc<App>) {
    loop {
        let request = match app.server.recv() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("http server recv failed: {e}");
                break;
            }
        };
        handle(&app, request);
    }
}

fn handle(app: &App, mut request: tiny_http::Request) {
    let method = request.method().as_str().to_ascii_uppercase();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or(&url).to_string();

    // /healthz is the only unauthenticated route: it reveals nothing but
    // liveness, and a monitor that cannot probe liveness is useless.
    if path == "/healthz" {
        return respond(request, 200, &json!({"status": "ok"}));
    }

    if !authorized(app, &request) {
        return respond(
            request,
            401,
            &json!({"error": {"kind": "unauthorized", "message": "missing or invalid API key"}}),
        );
    }

    let mut body = Vec::new();
    if let Err(e) = request
        .as_reader()
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
    {
        return respond(
            request,
            400,
            &json!({"error": {"kind": "bad-request", "message": format!("cannot read body: {e}")}}),
        );
    }
    if body.len() as u64 > MAX_BODY_BYTES as u64 {
        return respond(
            request,
            413,
            &json!({"error": {"kind": "payload-too-large", "message": "body exceeds 256 MiB"}}),
        );
    }

    let outcome: Result<serde_json::Value, RequestError> = match (method.as_str(), path.as_str()) {
        ("GET", "/readyz") => match app.supervisor.lock() {
            Ok(mut supervisor) => {
                match supervisor.with_client(|c| {
                    c.versions()
                        .map(|_| json!({"status": "ready"}))
                        .map_err(|err| RequestError::from_library("GET /readyz", &err))
                }) {
                    Ok(value) => Ok(value),
                    // Readiness failure is an answer, not a routing error:
                    // 503 with the reason, the contract REST-API.md and
                    // openapi.yaml document. A 200 here would tell every
                    // status-code consumer (probes, load balancers) that a
                    // dead bridge is ready to serve.
                    Err(re) => Err(RequestError {
                        status: 503,
                        kind: "not-ready".into(),
                        message: re.message,
                        feedback: re.feedback,
                    }),
                }
            }
            Err(e) => Err(RequestError::internal(e.to_string())),
        },
        ("GET", "/v1/version") => run_req("GET /v1/version".to_owned(), &app.supervisor, |c| {
            c.versions()
                .map(|v| serde_json::to_value(v).expect("versions are serializable"))
                .map_err(|err| RequestError::from_library("GET /v1/version", &err))
        }),
        ("POST", "/v1/send") => run_req("POST /v1/send".to_owned(), &app.supervisor, |c| {
            let send: SendBody = serde_json::from_slice(&body)
                .map_err(|e| RequestError::bad_request(format!("invalid JSON body: {e}")))?;
            send_op(c, send)
                .map(|receipt| serde_json::to_value(receipt).expect("receipts are serializable"))
        }),
        ("POST", "/v1/fetch") => run_req("POST /v1/fetch".to_owned(), &app.supervisor, |c| {
            let fetch: FetchBody = serde_json::from_slice(&body)
                .map_err(|e| RequestError::bad_request(format!("invalid JSON body: {e}")))?;
            fetch.validate().map_err(RequestError::bad_request)?;
            let query = match fetch.message_id.as_deref() {
                Some(id) => osci::FetchQuery::ByMessageId(id.to_owned()),
                None => osci::FetchQuery::All,
            };
            c.fetch(query)
                .map(|messages| serde_json::to_value(messages).expect("messages are serializable"))
                .map_err(|err| RequestError::from_library("POST /v1/fetch", &err))
        }),
        ("GET", p) if p.starts_with("/v1/messages/") && p.ends_with("/status") => {
            let id = p
                .strip_prefix("/v1/messages/")
                .and_then(|rest| rest.strip_suffix("/status"))
                .map(percent_decode)
                .expect("prefix/suffix stripped");
            run_req(
                "GET /v1/messages/{id}/status".to_owned(),
                &app.supervisor,
                |c| {
                    c.process_card(&id)
                        .map(|cards| {
                            serde_json::to_value(cards).expect("process cards are serializable")
                        })
                        .map_err(|err| {
                            RequestError::from_library("GET /v1/messages/{id}/status", &err)
                        })
                },
            )
        }
        _ => Err(RequestError::not_found(format!(
            "no route for {method} {path}"
        ))),
    };

    match outcome {
        Ok(value) => respond(request, 200, &value),
        Err(re) => respond(request, re.status, &re.envelope()),
    }
}

/// Runs an operation against the warm client and maps library errors onto
/// the HTTP error envelope. Single flight by design: the intermediary
/// serializes operations, so concurrent HTTP requests queue here instead
/// of racing a JVM.
fn run_req<T, F>(
    what: String,
    supervisor: &Mutex<Supervisor>,
    op: F,
) -> Result<serde_json::Value, RequestError>
where
    T: serde::ser::Serialize,
    F: FnMut(&mut OsciClient) -> Result<T, RequestError>,
{
    let mut supervisor = supervisor
        .lock()
        .map_err(|e| RequestError::internal(format!("supervisor lock poisoned: {e}")))?;
    match supervisor.with_client(op) {
        Ok(value) => {
            serde_json::to_value(value).map_err(|e| RequestError::internal(format!("{what}: {e}")))
        }
        Err(err) => Err(err),
    }
}

fn send_op(client: &mut OsciClient, send: SendBody) -> Result<crate::dto::SendOk, RequestError> {
    send.to.validate().map_err(RequestError::bad_request)?;
    if send.to.org.is_some() {
        // The DVDV-resolved intermediary can differ from the server's own
        // submission path, which the warm client is bound to. The CLI
        // covers that flow today.
        return Err(RequestError::not_implemented(
            "to.org addressing is not supported by the REST interface yet — \
             pass the recipient's certificate inline instead",
        ));
    }
    let cert = send.to.cert.expect("validated: exactly one of cert/org");
    let recipient = osci::Recipient::from_cipher_cert_pem(&cert);

    let decode = |part: &crate::dto::ContentPart| -> Result<Vec<u8>, RequestError> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&part.data)
            .map_err(|e| RequestError::bad_request(format!("content is not valid base64: {e}")))
    };

    send.content
        .validate("content")
        .map_err(RequestError::bad_request)?;
    let content_bytes = decode(&send.content)?;
    let filename = send
        .content
        .filename
        .clone()
        .unwrap_or_else(|| "message.xta".into());
    let xta = osci::Xta::from_bytes(filename, content_bytes);

    let mut send_builder = client.send_xta(xta).recipient(recipient);
    if !send.sign {
        send_builder = send_builder.without_signature();
    }
    if !send.encrypt {
        send_builder = send_builder.without_encryption();
    }
    if let Some(subject) = &send.subject {
        send_builder = send_builder.subject(subject.clone());
    }
    if let Some(kb) = send.chunk_size_kb {
        send_builder = send_builder.chunk_size_kb(kb);
    }
    for part in &send.attachments {
        part.validate("attachment")
            .map_err(RequestError::bad_request)?;
        let bytes = decode(part)?;
        let name = part.filename.clone().unwrap_or_else(|| "attachment".into());
        send_builder = send_builder.attachment(osci::Xta::from_bytes(name, bytes));
    }

    send_builder
        .submit()
        .map_err(|err| RequestError::from_library("POST /v1/send", &err))
        .map(|receipt| crate::dto::SendOk {
            message_id: receipt.message_id,
            response_signed: receipt.response_signed,
            feedback: receipt.feedback,
        })
}

fn authorized(app: &App, request: &tiny_http::Request) -> bool {
    let Some(key) = &app.api_key else { return true };
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
        .map(|present| constant_time_eq(present.as_bytes(), key.as_bytes()))
        .unwrap_or(false)
}

/// Length is revealed by any comparison scheme; the *value* must not be.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn respond(request: tiny_http::Request, status: u16, value: &serde_json::Value) {
    let body = value.to_string();
    let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header");
    let response = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(header);
    let _ = request.respond(response);
}

/// A request-scoped failure carrying its HTTP status and wire envelope —
/// the REST sibling of the CLI's exit-code taxonomy.
#[derive(Debug)]
pub struct RequestError {
    pub status: u16,
    pub kind: String,
    pub message: String,
    pub feedback: Option<Vec<Vec<String>>>,
}

impl From<osci::Error> for RequestError {
    fn from(err: osci::Error) -> Self {
        let (status, kind) = if err.is_bridge_death() {
            // A typed marker the supervisor's retry logic keys on.
            (502, "bridge-death")
        } else {
            http_error(&err)
        };
        let feedback = match &err {
            osci::Error::Bridge { feedback, .. } => Some(feedback.to_vec()),
            _ => None,
        };
        Self {
            status,
            kind: kind.to_string(),
            message: err.to_string(),
            feedback,
        }
    }
}

impl From<serde_json::Error> for RequestError {
    fn from(err: serde_json::Error) -> Self {
        Self {
            status: 400,
            kind: "bad-request".into(),
            message: format!("invalid JSON body: {err}"),
            feedback: None,
        }
    }
}

impl RequestError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            kind: "bad-request".into(),
            message: message.into(),
            feedback: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: 404,
            kind: "not-found".into(),
            message: message.into(),
            feedback: None,
        }
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self {
            status: 501,
            kind: "not-implemented".into(),
            message: message.into(),
            feedback: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: 500,
            kind: "internal".into(),
            message: message.into(),
            feedback: None,
        }
    }

    pub fn from_library(what: &str, err: &osci::Error) -> Self {
        let (status, kind) = if err.is_bridge_death() {
            // A typed marker the supervisor's retry logic keys on.
            (502, "bridge-death")
        } else {
            http_error(err)
        };
        let feedback = match err {
            osci::Error::Bridge { feedback, .. } => Some(feedback.to_vec()),
            _ => None,
        };
        Self {
            status,
            kind: kind.to_string(),
            message: format!("{what}: {err}"),
            feedback,
        }
    }

    pub fn envelope(&self) -> serde_json::Value {
        let mut error = json!({"kind": self.kind, "message": self.message});
        if let Some(feedback) = &self.feedback {
            error["feedback"] = json!(feedback);
        }
        json!({"error": error})
    }
}

/// Library error → HTTP status + kind, mirroring the exit-code mapping the
/// CLI documents: intermediary rejections are semantic (422), transport
/// problems are bad gateways (502), timeouts are 504.
fn http_error(err: &osci::Error) -> (u16, &'static str) {
    use osci::BridgeErrorKind as K;
    use osci::Error as E;
    match err {
        E::Config(_) => (400, "config"),
        E::DvdvLookup(_) => (404, "dvdv"),
        E::Bridge { kind: K::Osci, .. } => (422, "osci"),
        E::Bridge {
            kind: K::Crypto, ..
        } => (422, "crypto"),
        E::Bridge {
            kind: K::Transport, ..
        } => (502, "transport"),
        E::Bridge {
            kind: K::Protocol, ..
        } => (502, "protocol"),
        E::Bridge {
            kind: K::Internal, ..
        } => (502, "internal"),
        E::BridgeProtocol(_) => (502, "protocol"),
        E::BridgeTimeout { .. } => (504, "timeout"),
        E::BridgeSpawn(_) => (500, "bridge-spawn"),
        E::Io(_) => (500, "io"),
        E::Serde(_) => (500, "internal"),
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
