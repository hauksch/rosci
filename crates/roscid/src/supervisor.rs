//! Keeps one warm `OsciClient` for the process lifetime and rebuilds it
//! when the JVM dies — the supervision the CLI never needed, because a CLI
//! spawns per command and a daemon must survive a wedged JVM.

use tracing::warn;

use osci::{Error, OsciClient};

use crate::server::RequestError;

type Build = Box<dyn Fn() -> Result<OsciClient, Error> + Send>;

pub struct Supervisor {
    build: Build,
    client: Option<OsciClient>,
}

impl Supervisor {
    pub fn new(build: impl Fn() -> Result<OsciClient, Error> + Send + 'static) -> Self {
        Self {
            build: Box::new(build),
            client: None,
        }
    }

    /// Runs `op` against the warm client. On bridge death, rebuilds the
    /// client once and retries — a request that arrives after a JVM crash
    /// should still succeed, not teach the caller about our process model.
    /// The death signal is the library's typed
    /// `Error::is_bridge_death()`, carried on the request error as the
    /// `"bridge-death"` kind.
    pub fn with_client<T>(
        &mut self,
        mut op: impl FnMut(&mut OsciClient) -> Result<T, RequestError>,
    ) -> Result<T, RequestError> {
        if self.client.is_none() {
            self.client = Some((self.build)()?);
        }
        match op(self.client.as_mut().unwrap()) {
            Err(re) if re.kind == "bridge-death" => {
                warn!("bridge died; rebuilding and retrying once");
                let _ = self.client.take();
                let mut fresh = (self.build)()?;
                let out = op(&mut fresh);
                self.client = Some(fresh);
                out
            }
            other => other,
        }
    }

    /// Politely stops the bridge (bounded, mirroring the library's Drop
    /// contract). Safe to call more than once.
    pub fn shutdown(&mut self) {
        if let Some(mut client) = self.client.take() {
            let _ = client.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn bridge_script(script: &'static str) -> OsciClient {
        OsciClient::builder()
            .bridge_config(osci::BridgeConfig {
                cmd: vec!["bash".into(), "-c".into(), script.into()],
                response_timeout: std::time::Duration::from_secs(10),
            })
            // build() pings the bridge before returning; the intermediary is
            // only contacted by real operations, which these tests never run.
            .intermediary(osci::Intermediary::new(
                "http://127.0.0.1:1/entry",
                "dGVzdA==",
            ))
            .identity(osci::Identity::default())
            .build()
            .expect("fake bridge builds")
    }

    /// Answers every request with a valid ping-shaped response.
    const HAPPY: &str = r#"
        while IFS= read -r line; do
          id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
          printf '{"id":"%s","op":"ping","ok":true,"result":{"versions":{"protocol":"1"}}}\n' "$id"
        done
    "#;

    /// Answers the first request, then dies without a response.
    const DIE_AFTER_FIRST: &str = r#"
        first=1
        while IFS= read -r line; do
          id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
          if [ "$first" = 1 ]; then
            first=0
            printf '{"id":"%s","op":"ping","ok":true,"result":{"versions":{"protocol":"1"}}}\n' "$id"
          else
            exit 3
          fi
        done
    "#;

    #[test]
    fn dead_bridge_is_rebuilt_and_the_next_operation_succeeds() {
        let spawns = Arc::new(AtomicU32::new(0));
        let counter = spawns.clone();
        let mut supervisor = Supervisor::new(move || {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(bridge_script(if n == 1 { DIE_AFTER_FIRST } else { HAPPY }))
        });

        // First operation: the dying bridge answers the warmup ping (that
        // IS an operation) — succeeds.
        supervisor
            .with_client(|c| {
                c.versions()
                    .map(|_| ())
                    .map_err(|err| RequestError::from_library("test", &err))
            })
            .unwrap();
        // Second operation: hits the dead bridge → death detected → the
        // supervisor rebuilds and the retry must succeed.
        supervisor
            .with_client(|c| {
                c.versions()
                    .map(|_| ())
                    .map_err(|err| RequestError::from_library("test", &err))
            })
            .unwrap();
        assert!(
            spawns.load(Ordering::SeqCst) >= 2,
            "a rebuild must have happened"
        );
    }

    #[test]
    fn build_failure_surfaces_instead_of_looping() {
        let mut supervisor =
            Supervisor::new(|| Err(osci::Error::BridgeSpawn("no java for you".into())));
        let err = supervisor
            .with_client(|c| {
                c.versions()
                    .map(|_| ())
                    .map_err(|err| RequestError::from_library("test", &err))
            })
            .unwrap_err();
        assert!(
            err.message.contains("no java"),
            "build failures must surface, not loop: {err:?}"
        );
    }

    // keep the unused-import lint quiet when PathBuf isn't otherwise needed
    #[allow(dead_code)]
    fn touch(_: PathBuf) {}
}
