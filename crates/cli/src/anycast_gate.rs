//! `ferrum anycast-gate`: announce a relay's anycast route only while the
//! relay is ready (PRD `phase-6-anycast-autoscaling.md` FR5).
//!
//! The gate polls the relay's `GET /readyz` and drives bird2 through `birdc`,
//! enabling the static protocol that carries the anycast route when the relay
//! is ready and disabling it when it isn't. The rules:
//! - **Announce** after `rise` ready probes in a row.
//! - **Withdraw at once** on a `503`: the relay is draining and said so.
//! - **Withdraw** after `fall` failed probes in a row (no connection, a
//!   timeout, or any other status). One lost probe doesn't flap the route.
//! - The gate starts withdrawn, so its first `birdc` call disables the route,
//!   and it withdraws again on exit. The systemd unit's `ExecStopPost` covers
//!   a gate that dies without exiting cleanly (`deploy/anycast/`).
//! - A failed `birdc` call is retried on the next poll, and the current
//!   decision is re-applied every `resync` even when nothing changed: a
//!   restarted bird comes back with the route disabled (`disabled yes`).
//!
//! BGP itself is bird's job; this only decides when the route should exist.

use std::future::Future;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// What one readiness probe saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// `200`: the relay is serving and accepting new clients.
    Ready,
    /// `503`: the relay is draining.
    Draining,
    /// No answer in time, or an answer that's neither of the above.
    Failed,
}

/// The rise/fall hysteresis that turns probes into "announce or not".
#[derive(Debug)]
pub struct Gate {
    rise: u32,
    fall: u32,
    ready_streak: u32,
    failed_streak: u32,
    announce: bool,
}

impl Gate {
    /// A withdrawn gate. `rise` and `fall` are at least 1.
    pub fn new(rise: u32, fall: u32) -> Self {
        Self {
            rise: rise.max(1),
            fall: fall.max(1),
            ready_streak: 0,
            failed_streak: 0,
            announce: false,
        }
    }

    /// Feed one probe result; returns whether the route should be announced.
    pub fn observe(&mut self, probe: Probe) -> bool {
        match probe {
            Probe::Ready => {
                self.failed_streak = 0;
                self.ready_streak = self.ready_streak.saturating_add(1);
                if self.ready_streak >= self.rise {
                    self.announce = true;
                }
            }
            Probe::Draining => {
                self.ready_streak = 0;
                self.failed_streak = 0;
                self.announce = false;
            }
            Probe::Failed => {
                self.ready_streak = 0;
                self.failed_streak = self.failed_streak.saturating_add(1);
                if self.failed_streak >= self.fall {
                    self.announce = false;
                }
            }
        }
        self.announce
    }
}

/// A parsed `http://host:port/path` readiness URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    authority: String,
    path: String,
}

impl Target {
    /// Parse a plain-HTTP URL with an explicit port, e.g.
    /// `http://127.0.0.1:9101/readyz`. The probe listener never speaks TLS.
    pub fn parse(url: &str) -> Result<Self> {
        let Some(rest) = url.strip_prefix("http://") else {
            bail!("readiness URL '{url}' must start with http://");
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/readyz"),
        };
        let port_ok = authority
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
        if !port_ok {
            bail!("readiness URL '{url}' needs a host and port, e.g. http://127.0.0.1:9101/readyz");
        }
        Ok(Self {
            authority: authority.to_string(),
            path: path.to_string(),
        })
    }
}

/// Classify an HTTP response by its status line.
fn classify(response: &[u8]) -> Probe {
    let line = response.split(|&b| b == b'\r').next().unwrap_or_default();
    let mut parts = line.split(|&b| b == b' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with(b"HTTP/1.") {
        return Probe::Failed;
    }
    match parts.next() {
        Some(b"200") => Probe::Ready,
        Some(b"503") => Probe::Draining,
        _ => Probe::Failed,
    }
}

/// Probe `target` once, giving up after `timeout`.
pub async fn probe(target: &Target, timeout: Duration) -> Probe {
    let attempt = async {
        let mut stream = TcpStream::connect(&target.authority).await?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            target.path, target.authority
        );
        stream.write_all(request.as_bytes()).await?;
        let mut head = Vec::with_capacity(128);
        let mut chunk = [0u8; 256];
        while head.len() < 1024 && !head.contains(&b'\r') {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&chunk[..n]);
        }
        Ok::<_, std::io::Error>(head)
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(head)) => classify(&head),
        _ => Probe::Failed,
    }
}

/// Where the gate's decision goes: bird in production, a recorder in tests.
pub trait Route {
    /// Announce (`true`) or withdraw (`false`) the anycast route.
    fn set(&mut self, announce: bool) -> impl Future<Output = Result<()>> + Send;
}

/// Drives bird2's static protocols through `birdc enable|disable <name>`.
pub struct Birdc {
    pub birdc: String,
    pub protocols: Vec<String>,
}

/// Whether `birdc`'s reply confirms `protocol` is now in the wanted state.
/// bird answers `<name>: enabled` (or `already enabled`), and the same for
/// `disabled`; anything else (an unknown protocol, a dead control socket) is
/// a failure, whatever the exit status says.
fn birdc_confirmed(reply: &str, protocol: &str, announce: bool) -> bool {
    let state = if announce { "enabled" } else { "disabled" };
    reply.lines().any(|line| {
        let line = line.trim();
        line == format!("{protocol}: {state}") || line == format!("{protocol}: already {state}")
    })
}

impl Route for Birdc {
    async fn set(&mut self, announce: bool) -> Result<()> {
        let verb = if announce { "enable" } else { "disable" };
        for protocol in &self.protocols {
            let out = tokio::process::Command::new(&self.birdc)
                .arg(verb)
                .arg(protocol)
                .output()
                .await
                .with_context(|| format!("running '{} {verb} {protocol}'", self.birdc))?;
            let reply = String::from_utf8_lossy(&out.stdout);
            if !out.status.success() || !birdc_confirmed(&reply, protocol, announce) {
                bail!(
                    "'{} {verb} {protocol}' failed ({}): {}",
                    self.birdc,
                    out.status,
                    reply.trim()
                );
            }
        }
        Ok(())
    }
}

/// Probe timing and hysteresis.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub interval: Duration,
    pub timeout: Duration,
    pub rise: u32,
    pub fall: u32,
    /// Re-apply the current decision this often, changed or not.
    pub resync: Duration,
}

/// Run the gate until `shutdown` resolves, then withdraw the route.
pub async fn run<R: Route>(
    target: &Target,
    route: &mut R,
    timing: Timing,
    shutdown: impl Future<Output = ()>,
) {
    let mut gate = Gate::new(timing.rise, timing.fall);
    // The last decision bird confirmed, and when. Unknown until the first
    // call succeeds, so the first decision (always "withdrawn") is applied
    // even if bird was left announcing.
    let mut applied: Option<(bool, tokio::time::Instant)> = None;
    let mut tick = tokio::time::interval(timing.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tick.tick() => {}
        }
        let seen = probe(target, timing.timeout).await;
        let want = gate.observe(seen);
        let changed = applied.map(|(state, _)| state) != Some(want);
        let due = applied.is_none_or(|(_, at)| at.elapsed() >= timing.resync);
        if !changed && !due {
            continue;
        }
        match route.set(want).await {
            Ok(()) => {
                if changed && want {
                    info!("relay ready: anycast route announced");
                } else if changed {
                    info!(probe = ?seen, "anycast route withdrawn");
                }
                applied = Some((want, tokio::time::Instant::now()));
            }
            Err(e) => warn!("anycast gate: {e:#}; retrying on the next probe"),
        }
    }
    match route.set(false).await {
        Ok(()) => info!("anycast gate stopping: route withdrawn"),
        Err(e) => warn!("anycast gate stopping: withdrawing the route failed: {e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn announces_only_after_rise_ready_probes() {
        let mut gate = Gate::new(3, 3);
        assert!(!gate.observe(Probe::Ready));
        assert!(!gate.observe(Probe::Ready));
        assert!(gate.observe(Probe::Ready));
    }

    #[test]
    fn a_failure_resets_the_rise_count() {
        let mut gate = Gate::new(2, 3);
        assert!(!gate.observe(Probe::Ready));
        assert!(!gate.observe(Probe::Failed));
        assert!(!gate.observe(Probe::Ready));
        assert!(gate.observe(Probe::Ready));
    }

    #[test]
    fn draining_withdraws_at_once() {
        let mut gate = Gate::new(1, 3);
        assert!(gate.observe(Probe::Ready));
        assert!(!gate.observe(Probe::Draining));
    }

    #[test]
    fn isolated_failures_dont_flap_the_route() {
        let mut gate = Gate::new(1, 3);
        assert!(gate.observe(Probe::Ready));
        for _ in 0..5 {
            assert!(gate.observe(Probe::Failed));
            assert!(gate.observe(Probe::Failed));
            assert!(gate.observe(Probe::Ready));
        }
        assert!(gate.observe(Probe::Failed));
        assert!(gate.observe(Probe::Failed));
        assert!(!gate.observe(Probe::Failed), "three in a row withdraw");
    }

    #[test]
    fn coming_back_from_a_drain_needs_the_full_rise() {
        let mut gate = Gate::new(2, 1);
        gate.observe(Probe::Ready);
        assert!(gate.observe(Probe::Ready));
        assert!(!gate.observe(Probe::Draining));
        assert!(!gate.observe(Probe::Ready));
        assert!(gate.observe(Probe::Ready));
    }

    #[test]
    fn classifies_status_lines() {
        assert_eq!(classify(b"HTTP/1.1 200 OK\r\n\r\nready"), Probe::Ready);
        assert_eq!(
            classify(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Probe::Draining
        );
        assert_eq!(classify(b"HTTP/1.1 404 Not Found\r\n"), Probe::Failed);
        assert_eq!(classify(b"HTTP/1.1 2000 OK\r\n"), Probe::Failed);
        assert_eq!(classify(b"SSH-2.0-OpenSSH\r\n"), Probe::Failed);
        assert_eq!(classify(b""), Probe::Failed);
    }

    #[test]
    fn parses_readiness_urls() {
        let t = Target::parse("http://127.0.0.1:9101/readyz").unwrap();
        assert_eq!(
            (t.authority.as_str(), t.path.as_str()),
            ("127.0.0.1:9101", "/readyz")
        );
        let t = Target::parse("http://[::1]:9101").unwrap();
        assert_eq!(
            (t.authority.as_str(), t.path.as_str()),
            ("[::1]:9101", "/readyz")
        );
        assert!(Target::parse("https://127.0.0.1:9101/readyz").is_err());
        assert!(Target::parse("http://127.0.0.1/readyz").is_err());
        assert!(Target::parse("http://:9101/readyz").is_err());
    }

    #[test]
    fn birdc_replies_must_confirm_the_state() {
        assert!(birdc_confirmed(
            "ferrum_anycast4: enabled\n",
            "ferrum_anycast4",
            true
        ));
        assert!(birdc_confirmed(
            "BIRD 2.15 ready.\nferrum_anycast4: already disabled\n",
            "ferrum_anycast4",
            false
        ));
        assert!(!birdc_confirmed(
            "ferrum_anycast4: enabled\n",
            "ferrum_anycast4",
            false
        ));
        assert!(!birdc_confirmed(
            "syntax error, unexpected CF_SYM_UNDEFINED\n",
            "ferrum_anycast4",
            true
        ));
        assert!(!birdc_confirmed(
            "Unable to connect to server control socket\n",
            "ferrum_anycast4",
            false
        ));
        assert!(!birdc_confirmed(
            "ferrum_anycast6: enabled\n",
            "ferrum_anycast4",
            true
        ));
    }

    /// Records every decision; fails the first `fail_next` calls.
    #[derive(Clone, Default)]
    struct Recorder {
        calls: Arc<Mutex<Vec<bool>>>,
        fail_next: Arc<Mutex<u32>>,
    }

    impl Route for Recorder {
        async fn set(&mut self, announce: bool) -> Result<()> {
            let mut fail = self.fail_next.lock().unwrap();
            if *fail > 0 {
                *fail -= 1;
                bail!("birdc unavailable");
            }
            self.calls.lock().unwrap().push(announce);
            Ok(())
        }
    }

    impl Recorder {
        fn calls(&self) -> Vec<bool> {
            self.calls.lock().unwrap().clone()
        }

        /// Wait up to `ms` for the recorded calls to equal `want`.
        async fn wait_for(&self, want: &[bool], ms: u64) {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
            while self.calls() != want {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "calls {:?}, wanted {want:?}",
                    self.calls()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    const TIMING: Timing = Timing {
        interval: Duration::from_millis(50),
        timeout: Duration::from_millis(500),
        rise: 2,
        fall: 2,
        resync: Duration::from_secs(60),
    };

    /// A real relay with its real probe endpoint (`ferrum relay
    /// --metrics-listen`), and the URL of its `/readyz`.
    async fn relay_with_probes() -> (
        Arc<ferrum_transport::RelayServer>,
        tokio::task::JoinHandle<()>,
        Target,
    ) {
        let server = Arc::new(
            ferrum_transport::RelayServer::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let probes = tokio::spawn(crate::serve_relay_metrics(
            addr,
            server.metrics(),
            server.clone(),
        ));
        let target = Target::parse(&format!("http://{addr}/readyz")).unwrap();
        // Wait for the listener before the gate starts counting.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while probe(&target, Duration::from_millis(200)).await != Probe::Ready {
            assert!(
                tokio::time::Instant::now() < deadline,
                "probe endpoint never came up"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (server, probes, target)
    }

    /// FR5: against a real relay the gate withdraws on startup, announces
    /// once the relay has been ready for `rise` probes, withdraws as soon as
    /// the relay starts draining, and withdraws again on exit. `fall` is high
    /// so a 503 treated as an ordinary failure would miss the deadline.
    #[tokio::test]
    async fn follows_a_real_relay_through_its_drain() {
        let (server, _probes, target) = relay_with_probes().await;
        let route = Recorder::default();
        let stop = Arc::new(tokio::sync::Notify::new());
        let timing = Timing { fall: 20, ..TIMING };
        let gate = tokio::spawn({
            let (mut route, stop) = (route.clone(), stop.clone());
            async move { run(&target, &mut route, timing, stop.notified()).await }
        });

        route.wait_for(&[false, true], 2000).await;
        let drained_at = tokio::time::Instant::now();
        server.begin_drain();
        route.wait_for(&[false, true, false], 2000).await;
        assert!(
            drained_at.elapsed() < TIMING.interval * 4,
            "withdrawal took {:?}",
            drained_at.elapsed()
        );
        // Still draining: nothing more happens.
        tokio::time::sleep(TIMING.interval * 4).await;
        assert_eq!(route.calls(), [false, true, false]);

        stop.notify_one();
        gate.await.unwrap();
        assert_eq!(
            route.calls(),
            [false, true, false, false],
            "withdraw on exit"
        );
    }

    /// A relay that stops answering is withdrawn after `fall` failed probes.
    #[tokio::test]
    async fn withdraws_when_the_relay_stops_answering() {
        let (_server, probes, target) = relay_with_probes().await;
        let route = Recorder::default();
        let gate = tokio::spawn({
            let mut route = route.clone();
            async move { run(&target, &mut route, TIMING, std::future::pending()).await }
        });
        route.wait_for(&[false, true], 2000).await;
        probes.abort(); // the probe listener goes away: connections are refused
        route.wait_for(&[false, true, false], 2000).await;
        gate.abort();
    }

    /// A failed birdc call is retried on the next probe, with the decision
    /// as it stands then: here the relay is ready by the time birdc works, so
    /// the retry announces rather than replaying a stale withdrawal.
    #[tokio::test]
    async fn retries_a_failed_route_update() {
        let (_server, _probes, target) = relay_with_probes().await;
        let route = Recorder::default();
        *route.fail_next.lock().unwrap() = 3;
        let gate = tokio::spawn({
            let mut route = route.clone();
            async move { run(&target, &mut route, TIMING, std::future::pending()).await }
        });
        route.wait_for(&[true], 2000).await;
        tokio::time::sleep(TIMING.interval * 4).await;
        assert_eq!(route.calls(), [true], "no repeat once applied");
        gate.abort();
    }

    /// The decision is re-applied every `resync`, so a bird restart (which
    /// disables the route) is corrected without a change in readiness.
    #[tokio::test]
    async fn reapplies_the_decision_every_resync() {
        let (_server, _probes, target) = relay_with_probes().await;
        let route = Recorder::default();
        let timing = Timing {
            resync: Duration::from_millis(200),
            ..TIMING
        };
        let gate = tokio::spawn({
            let mut route = route.clone();
            async move { run(&target, &mut route, timing, std::future::pending()).await }
        });
        route.wait_for(&[false, true], 2000).await;
        route.wait_for(&[false, true, true, true], 2000).await;
        gate.abort();
    }

    /// Nothing listening: the gate stays withdrawn.
    #[tokio::test]
    async fn never_announces_without_a_ready_relay() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let target = Target::parse(&format!("http://127.0.0.1:{port}/readyz")).unwrap();
        let route = Recorder::default();
        let gate = tokio::spawn({
            let mut route = route.clone();
            async move { run(&target, &mut route, TIMING, std::future::pending()).await }
        });
        // A refused connection can take a couple of seconds to report on
        // Windows; the probe timeout bounds it either way.
        route.wait_for(&[false], 3000).await;
        tokio::time::sleep(TIMING.timeout * 3).await;
        assert_eq!(route.calls(), [false]);
        gate.abort();
    }
}
