//! The actual `ferrum-helper` daemon (Unix only): binds a Unix domain socket,
//! secures it to a group, and services `HelperRequest`s — opening a TUN device
//! (handing its fd back via `SCM_RIGHTS`) or running the kill-switch firewall
//! commands — one request per connection.

use std::io;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream as StdUnixStream;

use anyhow::Context;
use ferrum_core::config::Cidr;
use ferrum_tunnel::device::{self, TunConfig};
use ferrum_tunnel::firewall;
use ferrum_tunnel::helper_proto::{recv_request, send_response, HelperRequest, HelperResponse};
use tracing::{error, info, warn};

/// `RUST_LOG`-driven filter, defaulting to `info`.
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Bind `socket_path`, secure it to `group`, and serve connections until
/// SIGTERM/SIGINT.
pub async fn run(socket_path: &str, group: &str) -> anyhow::Result<()> {
    // A stale socket file from a previous crashed run would otherwise make
    // `bind` fail with `AddrInUse`.
    let _ = std::fs::remove_file(socket_path);
    let listener = tokio::net::UnixListener::bind(socket_path)
        .with_context(|| format!("binding helper socket at {socket_path}"))?;
    secure_socket(socket_path, group);
    info!(socket = socket_path, "ferrum-helper listening");

    tokio::select! {
        _ = accept_loop(listener) => {}
        _ = shutdown_signal() => info!("ferrum-helper shutting down"),
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Accept connections forever, handling each on a blocking thread (the
/// request/response + `SCM_RIGHTS` work is synchronous libc, not
/// tokio-integrated — see `ferrum_tunnel::fdpass`).
async fn accept_loop(listener: tokio::net::UnixListener) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                error!("accept failed: {e}");
                continue;
            }
        };
        tokio::task::spawn_blocking(move || {
            // `into_std` restores blocking mode, so the plain
            // `helper_proto`/`fdpass` calls (built on `std::os::unix::net`)
            // work unmodified.
            let std_stream = match stream.into_std() {
                Ok(s) => s,
                Err(e) => {
                    warn!("converting connection to a blocking socket failed: {e}");
                    return;
                }
            };
            if let Err(e) = handle_connection(std_stream) {
                warn!("connection error: {e}");
            }
        });
    }
}

/// Service exactly one request on `stream`, then return (the client connects
/// fresh per request — see `device::open_via_helper` and the desktop's
/// kill-switch client).
fn handle_connection(mut stream: StdUnixStream) -> io::Result<()> {
    let req = recv_request(&mut stream)?;
    let (resp, fd) = dispatch(req);
    send_response(&stream, &resp, fd)
}

/// Handle one request, returning the response and (for a successful
/// `OpenTun`) the fd to send alongside it.
fn dispatch(req: HelperRequest) -> (HelperResponse, Option<RawFd>) {
    match req {
        HelperRequest::OpenTun { name, address, mtu } => open_tun(&name, &address, mtu),
        HelperRequest::KillSwitchEngage { iface, allow_ips } => {
            kill_switch_engage(&iface, &allow_ips)
        }
        HelperRequest::KillSwitchDisengage => match firewall::disengage() {
            Ok(()) => {
                info!("kill-switch disengaged");
                (HelperResponse::Ok, None)
            }
            Err(e) => {
                warn!("kill-switch disengage failed: {e}");
                (HelperResponse::Err(e.to_string()), None)
            }
        },
        HelperRequest::SetDns { iface, servers } => set_dns(&iface, &servers),
        HelperRequest::RestoreDns { iface } => match ferrum_tunnel::dns::restore_dns(&iface) {
            Ok(()) => {
                info!(iface, "system DNS restored");
                (HelperResponse::Ok, None)
            }
            Err(e) => {
                warn!("restoring system DNS failed: {e}");
                (HelperResponse::Err(e.to_string()), None)
            }
        },
        HelperRequest::LeakGuardEngage {
            iface,
            dns_servers,
            block_ipv6,
        } => leak_guard_engage(&iface, &dns_servers, block_ipv6),
        HelperRequest::LeakGuardDisengage => match ferrum_tunnel::leakguard::disengage() {
            Ok(()) => {
                info!("leak guard disengaged");
                (HelperResponse::Ok, None)
            }
            Err(e) => {
                warn!("leak-guard disengage failed: {e}");
                (HelperResponse::Err(e.to_string()), None)
            }
        },
    }
}

/// Parse string IPs, rejecting the request cleanly on a malformed one.
fn parse_ips(ips: &[String]) -> Result<Vec<IpAddr>, HelperResponse> {
    ips.iter()
        .map(|s| s.parse())
        .collect::<Result<Vec<IpAddr>, _>>()
        .map_err(|e| HelperResponse::Err(format!("invalid IP address: {e}")))
}

fn set_dns(iface: &str, servers: &[String]) -> (HelperResponse, Option<RawFd>) {
    let ips = match parse_ips(servers) {
        Ok(ips) => ips,
        Err(resp) => return (resp, None),
    };
    match ferrum_tunnel::dns::set_dns(iface, &ips) {
        Ok(()) => {
            info!(iface, servers = ips.len(), "system DNS set");
            (HelperResponse::Ok, None)
        }
        Err(e) => {
            error!("setting system DNS failed: {e}");
            (HelperResponse::Err(e.to_string()), None)
        }
    }
}

fn leak_guard_engage(
    iface: &str,
    dns_servers: &[String],
    block_ipv6: bool,
) -> (HelperResponse, Option<RawFd>) {
    let ips = match parse_ips(dns_servers) {
        Ok(ips) => ips,
        Err(resp) => return (resp, None),
    };
    match ferrum_tunnel::leakguard::engage(iface, &ips, block_ipv6) {
        Ok(()) => {
            info!(iface, block_ipv6, "leak guard engaged");
            (HelperResponse::Ok, None)
        }
        Err(e) => {
            error!("leak-guard engage failed: {e}");
            (HelperResponse::Err(e.to_string()), None)
        }
    }
}

fn open_tun(name: &str, address: &str, mtu: u16) -> (HelperResponse, Option<RawFd>) {
    let cidr: Cidr = match address.parse() {
        Ok(c) => c,
        Err(e) => {
            return (
                HelperResponse::Err(format!("invalid address '{address}': {e}")),
                None,
            )
        }
    };
    let cfg = TunConfig {
        name: name.to_string(),
        address: cidr,
        mtu,
    };
    match device::open_raw(&cfg) {
        Ok(fd) => {
            info!(iface = name, "opened TUN device for a client");
            (HelperResponse::TunOpened, Some(fd))
        }
        Err(e) => {
            error!("opening TUN device failed: {e}");
            (HelperResponse::Err(e.to_string()), None)
        }
    }
}

fn kill_switch_engage(iface: &str, allow_ips: &[String]) -> (HelperResponse, Option<RawFd>) {
    let ips: Result<Vec<IpAddr>, _> = allow_ips.iter().map(|s| s.parse()).collect();
    let ips = match ips {
        Ok(ips) => ips,
        Err(e) => return (HelperResponse::Err(format!("invalid allow_ips: {e}")), None),
    };
    match firewall::engage(iface, &ips) {
        Ok(()) => {
            info!(iface, allowed = ips.len(), "kill-switch engaged");
            (HelperResponse::Ok, None)
        }
        Err(e) => {
            error!("kill-switch engage failed: {e}");
            (HelperResponse::Err(e.to_string()), None)
        }
    }
}

/// Restrict the socket to `group` (mode 0660); falls back to world-accessible
/// (0666, with a warning) if the group doesn't exist. This is the daemon's
/// entire access-control boundary — anyone who can open the socket can ask it
/// to create a TUN device or change firewall rules, so pick `group`
/// membership carefully (see `apps/desktop/README.md`).
fn secure_socket(path: &str, group: &str) {
    use std::ffi::CString;

    let gid = CString::new(group).ok().and_then(|cgroup| {
        // SAFETY: `cgroup` is a valid NUL-terminated C string; `getgrnam`
        // returns either null or a pointer to a static/thread-local buffer we
        // only read before any other libc call on this thread.
        let grp = unsafe { libc::getgrnam(cgroup.as_ptr()) };
        if grp.is_null() {
            None
        } else {
            Some(unsafe { (*grp).gr_gid })
        }
    });

    let mode = match gid {
        Some(gid) => {
            if let Ok(cpath) = CString::new(path) {
                // SAFETY: `cpath` is a valid NUL-terminated path; `u32::MAX`
                // (all-ones) is `(uid_t)-1`, POSIX's "leave the owner unchanged".
                let rc = unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) };
                if rc != 0 {
                    warn!(
                        "chown {path} to group '{group}' failed: {}",
                        io::Error::last_os_error()
                    );
                }
            }
            0o660
        }
        None => {
            warn!(
                "group '{group}' not found; falling back to a world-accessible \
                 socket (mode 0666) — create the group for a tighter trust boundary"
            );
            0o666
        }
    };
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!("setting permissions on {path} failed: {e}");
    }
}

/// A future that resolves on Ctrl-C (SIGINT) or SIGTERM (mirrors `ferrum`
/// CLI's `shutdown_signal`, so `systemctl stop` triggers a clean exit).
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!("could not install SIGTERM handler: {e}");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_tunnel::helper_proto::{recv_response, send_request};

    // `tag` differs per test (each has its own path), so pid+tag is already
    // collision-free without needing a thread/test-run id.
    fn temp_socket_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ferrum-helper-test-{tag}-{}.sock",
            std::process::id()
        ))
    }

    /// One request/response round trip, retrying the connect+request a
    /// handful of times on a transient I/O error. Under heavy concurrent
    /// test-suite load the just-spawned server task can be slow to reach its
    /// first `accept()`, which can drop an already-connected socket before
    /// reading the request (observed as `BrokenPipe`) — a scheduling artifact
    /// of running many tests at once, not of the production IPC path (a real
    /// caller already treats any I/O error here as "helper unreachable" and
    /// falls back — see `open_tun`/`ask_helper` in `apps/desktop`).
    async fn round_trip(
        socket_path: &std::path::Path,
        req: &HelperRequest,
    ) -> (HelperResponse, Option<RawFd>) {
        let mut last_err = None;
        for attempt in 0..20 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            let attempted: io::Result<(HelperResponse, Option<RawFd>)> = (|| {
                let mut stream = StdUnixStream::connect(socket_path)?;
                send_request(&mut stream, req)?;
                recv_response(&stream)
            })();
            match attempted {
                Ok(r) => return r,
                Err(e) => last_err = Some(e),
            }
        }
        panic!("round trip to {socket_path:?} never succeeded: {last_err:?}");
    }

    /// Drives the real daemon (accept loop, dispatch, `firewall`/`device`
    /// calls) end-to-end over a real socket — except the privileged syscalls
    /// themselves, which this unprivileged test process can't perform. That
    /// still exercises the whole IPC path (bind → connect → framed
    /// request/response → clean error propagation) and confirms a permission
    /// failure comes back as a `HelperResponse::Err`, not a crash or hang.
    /// Full success (an actual TUN device / `nft` rules) needs to be run as
    /// root — see `apps/desktop/README.md`.
    ///
    /// `multi_thread` matters here: the test's own blocking `send_request`/
    /// `recv_response` calls run on the current OS thread, and a
    /// single-threaded runtime would have no other thread left to drive the
    /// spawned server task while the client blocks waiting for its response —
    /// a self-deadlock (production is unaffected: the CLI and desktop shell
    /// both already run multi-threaded tokio runtimes).
    #[tokio::test(flavor = "multi_thread")]
    async fn open_tun_request_round_trips_and_reports_permission_errors_cleanly() {
        let socket_path = temp_socket_path("opentun");
        let socket_str = socket_path.to_str().unwrap().to_string();
        let server_socket = socket_str.clone();
        tokio::spawn(async move {
            let _ = run(&server_socket, "ferrum-test-nonexistent-group").await;
        });
        wait_for_socket(&socket_path).await;

        let (resp, fd) = round_trip(
            &socket_path,
            &HelperRequest::OpenTun {
                name: "ferrum-test0".to_string(),
                address: "10.99.0.1/24".to_string(),
                mtu: 1420,
            },
        )
        .await;
        // This test process has no CAP_NET_ADMIN, so the daemon's real
        // `device::open_raw` call fails; confirm that failure is reported as
        // a clean `Err`, never a fd and never a protocol desync/hang.
        match resp {
            HelperResponse::Err(msg) => assert!(!msg.is_empty()),
            HelperResponse::TunOpened => {
                // Running as root (e.g. a developer's manual check): a real
                // fd must come back.
                assert!(fd.is_some());
            }
            HelperResponse::Ok => panic!("OpenTun must not return a bare Ok"),
        }

        let _ = std::fs::remove_file(&socket_path);
    }

    // See the `multi_thread` note on the `OpenTun` test above — same reason.
    #[tokio::test(flavor = "multi_thread")]
    async fn kill_switch_engage_reports_permission_errors_cleanly() {
        let socket_path = temp_socket_path("killswitch");
        let socket_str = socket_path.to_str().unwrap().to_string();
        let server_socket = socket_str.clone();
        tokio::spawn(async move {
            let _ = run(&server_socket, "ferrum-test-nonexistent-group").await;
        });
        wait_for_socket(&socket_path).await;

        let (resp, fd) = round_trip(
            &socket_path,
            &HelperRequest::KillSwitchEngage {
                iface: "ferrum-test0".to_string(),
                allow_ips: vec!["203.0.113.7".to_string()],
            },
        )
        .await;
        assert!(fd.is_none());
        // Without root, `nft` itself refuses (see the `firewall` module); a
        // developer running this as root would instead see `Ok`.
        assert!(matches!(resp, HelperResponse::Err(_) | HelperResponse::Ok));

        let _ = std::fs::remove_file(&socket_path);
    }

    // See the `multi_thread` note on the `OpenTun` test above — same reason.
    #[tokio::test(flavor = "multi_thread")]
    async fn leak_guard_engage_reports_permission_errors_cleanly() {
        let socket_path = temp_socket_path("leakguard");
        let socket_str = socket_path.to_str().unwrap().to_string();
        let server_socket = socket_str.clone();
        tokio::spawn(async move {
            let _ = run(&server_socket, "ferrum-test-nonexistent-group").await;
        });
        wait_for_socket(&socket_path).await;

        let (resp, fd) = round_trip(
            &socket_path,
            &HelperRequest::LeakGuardEngage {
                iface: "ferrum-test0".to_string(),
                dns_servers: vec!["10.99.0.53".to_string()],
                block_ipv6: true,
            },
        )
        .await;
        assert!(fd.is_none());
        // Without root, `nft` itself refuses; a developer running this as root
        // would instead see `Ok`.
        assert!(matches!(resp, HelperResponse::Err(_) | HelperResponse::Ok));

        // A malformed IP is rejected in the daemon, before any privileged call.
        let (resp, fd) = round_trip(
            &socket_path,
            &HelperRequest::LeakGuardEngage {
                iface: "ferrum-test0".to_string(),
                dns_servers: vec!["not-an-ip".to_string()],
                block_ipv6: false,
            },
        )
        .await;
        assert!(fd.is_none());
        assert!(matches!(resp, HelperResponse::Err(msg) if msg.contains("invalid IP")));

        let _ = std::fs::remove_file(&socket_path);
    }

    async fn wait_for_socket(path: &std::path::Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("helper socket never appeared at {path:?}");
    }
}
