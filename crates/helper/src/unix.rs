//! The actual `ferrum-helper` daemon (Unix only): binds a Unix domain socket,
//! secures it to a group, and services `HelperRequest`s — opening a TUN device
//! (handing its fd back via `SCM_RIGHTS`) or running the kill-switch firewall
//! commands — one request per connection.
//!
//! Access control (SEC-005) is layered: the socket is `root:<group>` mode
//! 0660 (the kernel's connect-time check), **and** every connection's peer
//! credentials (`SO_PEERCRED` / `getpeereid`, via tokio's `peer_cred`) are
//! checked against an [`AccessPolicy`] before a request is dispatched. A
//! missing group is fatal — there is no world-accessible fallback. Allowed
//! callers are further bounded by one request per connection, a per-uid
//! [`RateLimiter`], a cap on in-flight connections, and I/O timeouts.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
#[cfg(test)]
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use ferrum_core::config::Cidr;
use ferrum_tunnel::device::{self, TunConfig};
use ferrum_tunnel::firewall;
use ferrum_tunnel::helper_proto::{recv_request, send_response, HelperRequest, HelperResponse};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

/// Connections being serviced at once; beyond this, new ones are dropped
/// (each holds a blocking-pool thread, so this bounds a flood from an allowed
/// caller). Real clients make one short request at a time.
const MAX_IN_FLIGHT: usize = 16;

/// Read/write timeout per connection, so a caller that connects and then
/// stalls can't pin a thread indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-uid token bucket: a burst of this many requests...
const RATE_BURST: f64 = 32.0;
/// ...refilled at this many requests per second. Generous for a desktop
/// session (a (re)connect issues a handful of requests, and reconnects back
/// off exponentially) while bounding a compromised caller hammering root.
const RATE_REFILL_PER_SEC: f64 = 2.0;

/// `RUST_LOG`-driven filter, defaulting to `info`.
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Who may ask the daemon to do anything: root, members of the configured
/// group (by the peer's effective gid, its passwd primary group, or the group
/// database's member list), and any explicitly allow-listed uid.
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    /// gid of `--group`.
    pub gid: libc::gid_t,
    /// Extra uids allowed regardless of group membership (`--allow-uid`).
    pub allow_uids: Vec<libc::uid_t>,
}

impl AccessPolicy {
    fn allows(&self, uid: libc::uid_t, gid: libc::gid_t) -> bool {
        uid == 0
            || self.allow_uids.contains(&uid)
            || gid == self.gid
            || user_in_group(uid, self.gid)
    }
}

/// Bind `socket_path`, secure it to `group`, and serve connections until
/// SIGTERM/SIGINT. Fails (without leaving a socket behind) if `group` does
/// not exist or the socket can't be restricted to it.
pub async fn run(socket_path: &str, group: &str, allow_uids: &[u32]) -> anyhow::Result<()> {
    let gid = lookup_group_gid(group)
        .with_context(|| format!("looking up group '{group}'"))?
        .with_context(|| {
            format!(
                "group '{group}' does not exist; refusing to start (create it with \
                 `groupadd {group}` — see apps/desktop/README.md)"
            )
        })?;

    // A stale socket file from a previous crashed run would otherwise make
    // `bind` fail with `AddrInUse`.
    let _ = std::fs::remove_file(socket_path);
    let listener = tokio::net::UnixListener::bind(socket_path)
        .with_context(|| format!("binding helper socket at {socket_path}"))?;
    if let Err(e) = secure_socket(socket_path, gid) {
        let _ = std::fs::remove_file(socket_path);
        return Err(e.context(format!("restricting {socket_path} to group '{group}'")));
    }
    info!(socket = socket_path, group, "ferrum-helper listening");

    let policy = AccessPolicy {
        gid,
        allow_uids: allow_uids.to_vec(),
    };
    tokio::select! {
        _ = serve(listener, policy) => {}
        _ = shutdown_signal() => info!("ferrum-helper shutting down"),
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Accept connections forever, handling each on a blocking thread (the
/// request/response + `SCM_RIGHTS` work is synchronous libc, not
/// tokio-integrated — see `ferrum_tunnel::fdpass`).
async fn serve(listener: tokio::net::UnixListener, policy: AccessPolicy) {
    let policy = Arc::new(policy);
    let limiter = Arc::new(RateLimiter::default());
    let slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                error!("accept failed: {e}");
                continue;
            }
        };
        let peer = match stream.peer_cred() {
            Ok(cred) => Peer {
                uid: cred.uid(),
                gid: cred.gid(),
                pid: cred.pid(),
            },
            Err(e) => {
                warn!("reading peer credentials failed; dropping connection: {e}");
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            warn!(
                uid = peer.uid,
                "too many in-flight helper connections; dropping one"
            );
            continue;
        };
        let (policy, limiter) = (policy.clone(), limiter.clone());
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
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
            if let Err(e) = handle_connection(std_stream, peer, &policy, &limiter) {
                warn!(uid = peer.uid, "connection error: {e}");
            }
        });
    }
}

/// The connecting process's credentials, as captured by the kernel at
/// `connect` time.
#[derive(Debug, Clone, Copy)]
struct Peer {
    uid: libc::uid_t,
    gid: libc::gid_t,
    pid: Option<libc::pid_t>,
}

/// Service exactly one request on `stream`, then return (the client connects
/// fresh per request — see `device::open_via_helper` and the desktop's
/// kill-switch client). That one-request-per-connection rule is the
/// per-connection quota; [`RateLimiter`] bounds reconnect loops per uid.
fn handle_connection(
    mut stream: StdUnixStream,
    peer: Peer,
    policy: &AccessPolicy,
    limiter: &RateLimiter,
) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    // Read (size-capped, timed) before answering, so even a refusal is a
    // clean response rather than a reset over unread data.
    let req = recv_request(&mut stream)?;
    if !policy.allows(peer.uid, peer.gid) {
        warn!(
            uid = peer.uid,
            gid = peer.gid,
            pid = peer.pid,
            "refusing helper request from a caller outside the allow-list"
        );
        let resp = HelperResponse::Err("not authorized to use ferrum-helper".to_string());
        return send_response(&stream, &resp, None);
    }
    if !limiter.try_acquire(peer.uid, Instant::now()) {
        warn!(uid = peer.uid, "helper request rate limit exceeded");
        let resp = HelperResponse::Err("rate limited; retry shortly".to_string());
        return send_response(&stream, &resp, None);
    }
    if let Err(reason) = validate_request(&req) {
        warn!(
            uid = peer.uid,
            "refusing malformed helper request: {reason}"
        );
        return send_response(&stream, &HelperResponse::Err(reason), None);
    }
    let (resp, fd) = dispatch(req);
    // Send a duplicate of the TUN fd (if any); our copy is closed when `fd`
    // drops at the end of this function, on success and failure alike, so
    // the daemon never accumulates descriptors (SEC-012).
    send_response(&stream, &resp, fd.as_ref().map(AsRawFd::as_raw_fd))
}

/// Lowest / highest TUN MTU the helper will configure. 576 is the IPv4
/// minimum datagram size; 9000 covers jumbo frames. Anything outside is a
/// malformed (or hostile) request, not a real tunnel.
const MIN_TUN_MTU: u16 = 576;
const MAX_TUN_MTU: u16 = 9000;

/// Reject a request whose fields aren't safe to act on as root (SEC-012):
/// interface names are checked against [`ferrum_tunnel::ifname::validate`]
/// (they end up in nft scripts and `resolvectl` arguments) and the TUN MTU is
/// range-checked. IP addresses are parsed later by the handlers themselves.
fn validate_request(req: &HelperRequest) -> Result<(), String> {
    let iface = match req {
        HelperRequest::OpenTun { name, mtu, .. } => {
            if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(mtu) {
                return Err(format!(
                    "invalid MTU {mtu}: expected {MIN_TUN_MTU}-{MAX_TUN_MTU}"
                ));
            }
            name
        }
        HelperRequest::KillSwitchEngage { iface, .. }
        | HelperRequest::SetDns { iface, .. }
        | HelperRequest::RestoreDns { iface }
        | HelperRequest::LeakGuardEngage { iface, .. } => iface,
        HelperRequest::KillSwitchDisengage | HelperRequest::LeakGuardDisengage => return Ok(()),
    };
    ferrum_tunnel::ifname::validate(iface).map_err(|e| e.to_string())
}

/// Per-uid token buckets ([`RATE_BURST`] / [`RATE_REFILL_PER_SEC`]). Only
/// authorized uids ever get a bucket, so the map stays tiny.
#[derive(Default)]
struct RateLimiter {
    buckets: Mutex<HashMap<libc::uid_t, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn try_acquire(&self, uid: libc::uid_t, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let bucket = buckets.entry(uid).or_insert(Bucket {
            tokens: RATE_BURST,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * RATE_REFILL_PER_SEC).min(RATE_BURST);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Handle one request, returning the response and (for a successful
/// `OpenTun`) the fd to send alongside it.
fn dispatch(req: HelperRequest) -> (HelperResponse, Option<OwnedFd>) {
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

fn set_dns(iface: &str, servers: &[String]) -> (HelperResponse, Option<OwnedFd>) {
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
) -> (HelperResponse, Option<OwnedFd>) {
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

fn open_tun(name: &str, address: &str, mtu: u16) -> (HelperResponse, Option<OwnedFd>) {
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

fn kill_switch_engage(iface: &str, allow_ips: &[String]) -> (HelperResponse, Option<OwnedFd>) {
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

/// Restrict the socket to group `gid`, mode 0660. Any failure is an error —
/// the caller refuses to serve rather than run with a looser socket.
fn secure_socket(path: &str, gid: libc::gid_t) -> anyhow::Result<()> {
    let cpath = CString::new(path).context("socket path contains a NUL byte")?;
    // SAFETY: `cpath` is a valid NUL-terminated path; `uid_t::MAX` (all-ones)
    // is `(uid_t)-1`, POSIX's "leave the owner unchanged".
    let rc = unsafe { libc::chown(cpath.as_ptr(), libc::uid_t::MAX, gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("chown");
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).context("chmod 0660")
}

/// Whether `uid`'s passwd primary group is `gid` or the group database lists
/// the user as a member. A lookup failure counts as "not a member" (fail
/// closed).
fn user_in_group(uid: libc::uid_t, gid: libc::gid_t) -> bool {
    let check = || -> io::Result<bool> {
        let Some((name, primary)) = lookup_user(uid)? else {
            return Ok(false);
        };
        if primary == gid {
            return Ok(true);
        }
        Ok(group_members(gid)?.is_some_and(|members| members.contains(&name)))
    };
    check().unwrap_or_else(|e| {
        warn!(uid, gid, "group-membership lookup failed; denying: {e}");
        false
    })
}

/// `getgrnam_r`: the gid of group `name`, or `None` if there's no such group.
fn lookup_group_gid(name: &str) -> io::Result<Option<libc::gid_t>> {
    let cname = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "group name contains NUL"))?;
    nss_lookup(
        // SAFETY: all pointers are valid for the call (see `nss_lookup`).
        |rec, buf, len, res| unsafe { libc::getgrnam_r(cname.as_ptr(), rec, buf, len, res) },
        |g: &libc::group| g.gr_gid,
    )
}

/// `getpwuid_r`: `uid`'s login name and primary gid.
fn lookup_user(uid: libc::uid_t) -> io::Result<Option<(CString, libc::gid_t)>> {
    nss_lookup(
        // SAFETY: all pointers are valid for the call (see `nss_lookup`).
        |rec, buf, len, res| unsafe { libc::getpwuid_r(uid, rec, buf, len, res) },
        // SAFETY: on success `pw_name` points at a NUL-terminated string in
        // the scratch buffer, which outlives this closure.
        |p: &libc::passwd| (unsafe { CStr::from_ptr(p.pw_name) }.to_owned(), p.pw_gid),
    )
}

/// `getgrgid_r`: the login names the group database lists as members of `gid`.
fn group_members(gid: libc::gid_t) -> io::Result<Option<Vec<CString>>> {
    nss_lookup(
        // SAFETY: all pointers are valid for the call (see `nss_lookup`).
        |rec, buf, len, res| unsafe { libc::getgrgid_r(gid, rec, buf, len, res) },
        |g: &libc::group| {
            let mut members = Vec::new();
            let mut p = g.gr_mem;
            // SAFETY: on success `gr_mem` is a NULL-terminated array of
            // NUL-terminated strings, all in the scratch buffer, which
            // outlives this closure.
            unsafe {
                while !p.is_null() && !(*p).is_null() {
                    members.push(CStr::from_ptr(*p).to_owned());
                    p = p.add(1);
                }
            }
            members
        },
    )
}

/// Largest scratch buffer a `get*_r` lookup may grow to (huge groups can need
/// more than the initial 1 KiB).
const MAX_NSS_BUF: usize = 1 << 20;

/// Drive a reentrant `get{pw,gr}*_r` call (the non-`_r` forms return shared
/// static storage, unsafe with connections handled on several threads):
/// `call(record, buf, buflen, result)` fills `record`, `read` copies what we
/// need out of it while the scratch buffer is still alive, and the buffer is
/// doubled on `ERANGE`. `R` must be a plain C struct (`passwd`/`group`).
fn nss_lookup<R, T>(
    mut call: impl FnMut(*mut R, *mut libc::c_char, libc::size_t, *mut *mut R) -> libc::c_int,
    read: impl FnOnce(&R) -> T,
) -> io::Result<Option<T>> {
    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    loop {
        // SAFETY: `R` is a C struct of integers and raw pointers, for which
        // all-zero is a valid value; it's only read after `call` fills it.
        let mut rec: R = unsafe { std::mem::zeroed() };
        let mut result: *mut R = std::ptr::null_mut();
        match call(&mut rec, buf.as_mut_ptr(), buf.len(), &mut result) {
            0 if result.is_null() => return Ok(None),
            0 => return Ok(Some(read(&rec))),
            libc::ERANGE if buf.len() < MAX_NSS_BUF => {
                let len = buf.len() * 2;
                buf.resize(len, 0);
            }
            rc => return Err(io::Error::from_raw_os_error(rc)),
        }
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

    /// A gid no real account has, so the test process is never a member.
    const NOBODY_GID: libc::gid_t = libc::gid_t::MAX - 1;

    /// A policy that admits this test process by uid only.
    fn allow_self() -> AccessPolicy {
        AccessPolicy {
            gid: NOBODY_GID,
            // SAFETY: `geteuid` has no preconditions.
            allow_uids: vec![unsafe { libc::geteuid() }],
        }
    }

    /// Bind a private socket and serve it with `policy` (bypassing `run`'s
    /// group setup, which needs a group this process can `chown` to).
    async fn spawn_server(tag: &str, policy: AccessPolicy) -> std::path::PathBuf {
        let socket_path = temp_socket_path(tag);
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(serve(listener, policy));
        socket_path
    }

    fn disengage() -> HelperRequest {
        HelperRequest::KillSwitchDisengage
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_group_refuses_to_start_and_leaves_no_socket() {
        let socket_path = temp_socket_path("nogroup");
        let err = run(
            socket_path.to_str().unwrap(),
            "ferrum-test-nonexistent-group",
            &[],
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("does not exist"), "{err:#}");
        assert!(
            !socket_path.exists(),
            "no socket (0666 or otherwise) may be left behind"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn socket_is_group_owned_0660_and_members_are_admitted() {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: `getegid` has no preconditions.
        let gid = unsafe { libc::getegid() };
        let group_name = nss_lookup(
            // SAFETY: all pointers are valid for the call (see `nss_lookup`).
            |rec, buf, len, res| unsafe { libc::getgrgid_r(gid, rec, buf, len, res) },
            // SAFETY: `gr_name` is NUL-terminated in the live scratch buffer.
            |g: &libc::group| {
                unsafe { CStr::from_ptr(g.gr_name) }
                    .to_string_lossy()
                    .into_owned()
            },
        )
        .unwrap();
        let Some(group_name) = group_name else {
            eprintln!("skipping: primary gid {gid} has no group name");
            return;
        };

        let socket_path = temp_socket_path("grouped");
        let server_socket = socket_path.to_str().unwrap().to_string();
        tokio::spawn(async move {
            let _ = run(&server_socket, &group_name, &[]).await;
        });
        wait_for_socket(&socket_path).await;
        // `run` chmods right after bind; wait for that too.
        for _ in 0..100 {
            if std::fs::metadata(&socket_path).unwrap().mode() & 0o777 == 0o660 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let meta = std::fs::metadata(&socket_path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o660);
        assert_eq!(meta.gid(), gid);

        // Admitted via its egid: the request reaches dispatch (and fails, or
        // succeeds as root, on the privileged call itself).
        let (resp, _) = round_trip(&socket_path, &disengage()).await;
        assert!(
            !matches!(&resp, HelperResponse::Err(m) if m.contains("not authorized")),
            "{resp:?}"
        );
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn caller_outside_the_allow_list_is_refused() {
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: root is always allowed");
            return;
        }
        let policy = AccessPolicy {
            gid: NOBODY_GID,
            allow_uids: vec![],
        };
        let socket_path = spawn_server("denied", policy).await;
        let (resp, fd) = round_trip(&socket_path, &disengage()).await;
        assert!(fd.is_none());
        assert!(
            matches!(&resp, HelperResponse::Err(m) if m.contains("not authorized")),
            "{resp:?}"
        );
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn allow_listed_uid_is_admitted_without_group_membership() {
        let socket_path = spawn_server("allowuid", allow_self()).await;
        let (resp, _) = round_trip(&socket_path, &disengage()).await;
        assert!(
            !matches!(&resp, HelperResponse::Err(m) if m.contains("not authorized")),
            "{resp:?}"
        );
        let _ = std::fs::remove_file(&socket_path);
    }

    #[test]
    fn rate_limiter_allows_a_burst_then_refills() {
        let limiter = RateLimiter::default();
        let t0 = Instant::now();
        for _ in 0..RATE_BURST as usize {
            assert!(limiter.try_acquire(1000, t0));
        }
        assert!(!limiter.try_acquire(1000, t0), "burst exhausted");
        // Buckets are per uid.
        assert!(limiter.try_acquire(1001, t0));
        // One token back after 1/RATE_REFILL_PER_SEC seconds.
        let t1 = t0 + Duration::from_secs_f64(1.0 / RATE_REFILL_PER_SEC);
        assert!(limiter.try_acquire(1000, t1));
        assert!(!limiter.try_acquire(1000, t1));
    }

    #[test]
    fn policy_always_admits_root_and_listed_uids() {
        let policy = AccessPolicy {
            gid: NOBODY_GID,
            allow_uids: vec![4242],
        };
        assert!(policy.allows(0, 0));
        assert!(policy.allows(4242, 4242));
        assert!(policy.allows(4343, NOBODY_GID), "effective gid matches");
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
        let socket_path = spawn_server("opentun", allow_self()).await;

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
        let socket_path = spawn_server("killswitch", allow_self()).await;

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
        let socket_path = spawn_server("leakguard", allow_self()).await;

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

    /// SEC-012: hostile interface names and out-of-range MTUs are refused at
    /// the boundary with a clean error, before any privileged call (so the
    /// response never mentions nft or a TUN failure).
    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_requests_are_refused_before_any_privileged_call() {
        let socket_path = spawn_server("malformed", allow_self()).await;
        let inject = "x\" accept; flush ruleset".to_string();
        let open_tun = |name: &str, mtu| HelperRequest::OpenTun {
            name: name.to_string(),
            address: "10.99.0.1/24".to_string(),
            mtu,
        };
        let cases = [
            HelperRequest::KillSwitchEngage {
                iface: inject.clone(),
                allow_ips: vec![],
            },
            HelperRequest::LeakGuardEngage {
                iface: "ferrum0\nflush ruleset".to_string(),
                dns_servers: vec![],
                block_ipv6: true,
            },
            HelperRequest::SetDns {
                iface: "--help".to_string(),
                servers: vec!["10.99.0.53".to_string()],
            },
            HelperRequest::RestoreDns {
                iface: "a".repeat(16),
            },
            open_tun(&inject, 1420),
            open_tun("ferrum0", 0),
            open_tun("ferrum0", 65_000),
        ];
        for req in &cases {
            let (resp, fd) = round_trip(&socket_path, req).await;
            assert!(fd.is_none());
            match resp {
                HelperResponse::Err(msg) => assert!(
                    msg.starts_with("invalid interface name") || msg.starts_with("invalid MTU"),
                    "{req:?} -> {msg}"
                ),
                other => panic!("{req:?} must be refused, got {other:?}"),
            }
        }
        let _ = std::fs::remove_file(&socket_path);
    }

    #[test]
    fn well_formed_requests_pass_validation() {
        let ok = [
            HelperRequest::OpenTun {
                name: "ferrum0".into(),
                address: "10.8.0.2/32".into(),
                mtu: 1420,
            },
            HelperRequest::KillSwitchEngage {
                iface: "ferrum0".into(),
                allow_ips: vec!["203.0.113.7".into()],
            },
            HelperRequest::KillSwitchDisengage,
            HelperRequest::LeakGuardDisengage,
        ];
        for req in &ok {
            validate_request(req).unwrap_or_else(|e| panic!("{req:?}: {e}"));
        }
    }

    /// SEC-012: a successful `OpenTun` must not leave the daemon holding the
    /// TUN fd it handed out. Needs root to actually create a TUN, so it's
    /// skipped elsewhere (CI runs unprivileged); run it with `sudo -E cargo test`.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn open_tun_does_not_leak_the_daemons_fd() {
        use std::os::fd::FromRawFd;

        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: needs root to create a TUN device");
            return;
        }
        let open_fds = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let socket_path = spawn_server("fdleak", allow_self()).await;
        let req = HelperRequest::OpenTun {
            name: "ferrumleak0".to_string(),
            address: "10.99.7.1/24".to_string(),
            mtu: 1420,
        };
        // Warm up (runtime threads, the first connection) before measuring.
        let (_, fd) = round_trip(&socket_path, &req).await;
        // SAFETY: as below — a freshly received fd owned by nothing else.
        drop(fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }));
        let before = open_fds();
        for _ in 0..5 {
            let (resp, fd) = round_trip(&socket_path, &req).await;
            assert!(matches!(resp, HelperResponse::TunOpened), "{resp:?}");
            // Close the client's copy; only the daemon's copy could remain.
            // SAFETY: the fd was just received and is owned by nothing else.
            drop(fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }));
        }
        assert_eq!(open_fds(), before, "the daemon kept TUN fds open");
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
