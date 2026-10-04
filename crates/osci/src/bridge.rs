//! Bridge child-process management: spawn, speak, die with dignity.
//!
//! The bridge is a JVM in a trench coat; treat it accordingly — talk to it
//! through the letterbox (stdio), never let it write to stdout's drinking
//! water, and give it a polite but firm bedtime.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::error::{BridgeErrorKind, Error};
use crate::protocol::{Request, Response};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// How to launch the bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Full command line. Default: `["java", "-jar", "<jar>"]`.
    pub cmd: Vec<String>,
    /// Per-request response timeout.
    pub response_timeout: Duration,
}

impl BridgeConfig {
    /// The canonical launch: `java -jar <path>`, plus any extra JVM flags
    /// from `OSCI_JAVA_OPTS` (split on whitespace — a debugging hatch, not
    /// a place to hide your hopes).
    pub fn java_jar<P: AsRef<std::path::Path>>(jar: P) -> Self {
        let mut cmd: Vec<String> = vec!["java".to_string()];
        if let Ok(extra) = std::env::var("OSCI_JAVA_OPTS") {
            cmd.extend(extra.split_whitespace().map(str::to_string));
        }
        cmd.push("-jar".to_string());
        cmd.push(jar.as_ref().to_string_lossy().into_owned());
        Self {
            cmd,
            response_timeout: Duration::from_secs(300),
        }
    }

    /// Arbitrary command, used by tests to plug in fake bridges.
    pub fn cmd<I, S>(cmd: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            cmd: cmd.into_iter().map(Into::into).collect(),
            response_timeout: Duration::from_secs(300),
        }
    }

    /// Overrides the per-request response timeout (default 300 s).
    pub fn response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }
}

/// A live bridge process. One request in, one response out, no surprises.
///
/// Debug deliberately prints nothing about the child or the reader thread;
/// there is nothing to see and even less to debug there.
impl std::fmt::Debug for BridgeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeHandle").finish_non_exhaustive()
    }
}

/// A live bridge process handle: owns the child, its stdin and the
/// stdout reader thread. One request in, one response out, no surprises.
pub struct BridgeHandle {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    response_timeout: Duration,
}

impl BridgeHandle {
    /// Spawns the bridge. Logs (stderr) flow through to our stderr.
    pub fn spawn(cfg: &BridgeConfig) -> Result<Self, Error> {
        if cfg.cmd.is_empty() {
            return Err(Error::Config("bridge command is empty".into()));
        }
        let mut child = Command::new(&cfg.cmd[0])
            .args(&cfg.cmd[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| Error::BridgeSpawn(format!("{}: {e}", cfg.cmd[0])))?;

        // take() can only miss if the piped() above was ignored — treat it
        // as a spawn failure rather than a panic; the distinction is the
        // caller's business, not ours.
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::BridgeSpawn("child stdin was not piped".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::BridgeSpawn("child stdout was not piped".into()))?;

        // Reader thread: the only thing allowed to touch bridge stdout.
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("osci-bridge-reader".into())
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    match line {
                        Ok(l) => {
                            if tx.send(l).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|e| Error::BridgeSpawn(format!("reader thread: {e}")))?;

        Ok(Self {
            child,
            stdin,
            lines: rx,
            response_timeout: cfg.response_timeout,
        })
    }

    /// Sends one request and waits for its response.
    pub fn call(&mut self, mut req: Request) -> Result<Response, Error> {
        if req.id.is_empty() {
            req.id = format!("r{}", REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed));
        }
        let expected_id = req.id.clone();
        let json = serde_json::to_string(&req)?;

        self.stdin
            .write_all(json.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| Error::BridgeProtocol(format!("bridge closed its stdin: {e}")))?;

        let line = match self.lines.recv_timeout(self.response_timeout) {
            Ok(line) => line,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(Error::bridge_timeout(
                    self.response_timeout.as_millis() as u64
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // The reader thread hit EOF: the bridge process is gone.
                return Err(Error::BridgeProtocol(
                    "bridge exited before answering".into(),
                ));
            }
        };

        let rsp: Response = serde_json::from_str(&line).map_err(|e| {
            Error::BridgeProtocol(format!("unparseable bridge response: {e}: {line}"))
        })?;

        if let Some(id) = &rsp.id {
            if id != &expected_id {
                return Err(Error::BridgeProtocol(format!(
                    "bridge response id mismatch: sent {expected_id}, got {id}"
                )));
            }
        }
        if !rsp.ok {
            let err = rsp.error.unwrap_or_default();
            return Err(Error::Bridge {
                kind: BridgeErrorKind::parse(err.kind.as_deref().unwrap_or("internal")),
                message: err.message.unwrap_or_else(|| "unknown bridge error".into()),
                feedback: err.feedback.unwrap_or_default(),
            });
        }
        Ok(rsp)
    }

    /// Sends the shutdown request and waits briefly for the goodbye. Uses a
    /// short fixed timeout, deliberately NOT `response_timeout`: a goodbye
    /// that takes minutes is not a goodbye, and `Drop` must never block on
    /// an unresponsive JVM (see docs/REVIEW.md, finding A2).
    pub fn shutdown(&mut self) {
        let req = Request {
            id: "shutdown".into(),
            op: "shutdown",
            intermediary: None,
            identity: None,
            recipient: None,
            subject: None,
            content: None,
            sign: None,
            encrypt: None,
            insecure_transport: None,
            tls: None,
            selection_mode: None,
            selection_rule: None,
        };
        let json = match serde_json::to_string(&req) {
            Ok(json) => json,
            Err(e) => {
                debug!("cannot serialize shutdown request: {e}");
                return;
            }
        };
        if let Err(e) = self
            .stdin
            .write_all(json.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
        {
            debug!("bridge closed its stdin before shutdown: {e}");
            return;
        }
        // Two seconds of politeness, then Drop's kill-grace takes over.
        match self.lines.recv_timeout(Duration::from_secs(2)) {
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                debug!("bridge did not answer shutdown in time; Drop will handle it")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                debug!("bridge exited on shutdown")
            }
        }
    }

    /// Blocks until the process exits; returns its exit code if any.
    pub fn wait(&mut self) -> Result<Option<i32>, Error> {
        self.child.wait().map(|s| s.code()).map_err(Error::Io)
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        self.shutdown();
        // Grace period, then the hammer. A JVM that refuses to exit after
        // being asked nicely is a JVM that has stopped cooperating.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().map(|s| s.is_none()).unwrap_or(true) {
            if std::time::Instant::now() > deadline {
                warn!("bridge ignored shutdown; killing it");
                let _ = self.child.kill();
                // kill() only signals; without a reap the JVM would sit in
                // the process table until *we* exit — fine for the CLI, an
                // accumulating leak for a library consumer that drops
                // unresponsive bridges in a loop.
                let reap_deadline = std::time::Instant::now() + Duration::from_secs(2);
                while self.child.try_wait().map(|s| s.is_none()).unwrap_or(true) {
                    if std::time::Instant::now() > reap_deadline {
                        warn!("bridge survived SIGKILL; leaving it to init");
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
