//! Userspace loader for the relay's eBPF/XDP fast path (PRD:
//! `PRD/phase-6-ebpf-xdp-relay.md`). Linux-only, behind the `xdp` feature —
//! `aya` is declared as a `[target.'cfg(target_os = "linux")'.dependencies]`
//! dependency (matching this crate's existing Linux-only `libc` for the
//! GSO/GRO UDP batching), so this whole module is excluded from the
//! dependency graph entirely on any other host, including the one it was
//! authored on.
//!
//! **Cross-compile-checked, not built or run, on the authoring host** — see
//! the crate-level docs and `PRD/phase-6-ebpf-xdp-relay.md`'s Risks section.
//! `cargo check --target x86_64-unknown-linux-gnu -p ferrum-transport
//! --features xdp` type-checks this file (matching the existing GSO/GRO
//! precedent — CLAUDE.md's environment note) and passed against the actual
//! `aya = "0.14.0"` API (fetched to this host to check against — the crate
//! itself only *runs* on Linux, but its source doesn't need a Linux host to
//! read); running this module for real, including its own unit tests below,
//! still needs a Linux host or CI.
//!
//! This relay's [`RelayServer`](crate::relay::RelayServer) stays the single
//! source of truth for who's registered where (PRD FR3) — this loader only
//! ever mirrors that state into the kernel maps the XDP program reads; it
//! never makes an independent registration/eviction decision.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aya::maps::{Array, HashMap as AyaHashMap, PerCpuArray};
use aya::programs::{Xdp, XdpMode};
use aya::Ebpf;
use ferrum_relay_xdp_common::{AddrKey, GatewayInfo, PublicKey};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::relay::{RelayMetrics, RelayXdpHook};

/// How often the gateway MAC is re-resolved (it can change — a router
/// reboot, a DHCP renewal — and there's no push notification for that, so
/// this is a plain poll, mirroring the relay's own `Register` keepalive
/// cadence philosophy rather than trying to be event-driven).
const GATEWAY_REFRESH: Duration = Duration::from_secs(30);
/// How often the fast path's cumulative counters are read and merged into
/// `RelayMetrics` (PRD FR4).
const STATS_POLL: Duration = Duration::from_secs(5);

/// Errors bringing the XDP fast path up. Distinct from
/// [`crate::TransportError`] — every variant here means "the accelerator
/// didn't attach," which `ferrum relay` should treat as "log a warning and
/// keep running userspace-only" (PRD FR5 goal G4: additive, never a hard
/// requirement for the relay to function), not as a reason to exit.
#[derive(Debug, thiserror::Error)]
pub enum RelayXdpError {
    #[error("loading the eBPF object at {path}: {source}")]
    Load {
        path: String,
        source: aya::EbpfError,
    },
    #[error("attaching the XDP program to interface {iface}: {source}")]
    Attach {
        iface: String,
        source: anyhow::Error,
    },
    #[error("the eBPF object has no XDP program named {0:?}")]
    ProgramNotFound(&'static str),
    #[error("resolving the {0:?} map: {1}")]
    Map(&'static str, aya::maps::MapError),
    #[error("could not resolve this relay's gateway/interface info: {0}")]
    GatewayResolution(String),
}

/// Name the XDP program is exported under in the compiled object — must
/// match the `#[xdp] pub fn` name in `relay-ebpf/src/main.rs`.
const PROGRAM_NAME: &str = "ferrum_relay_fastpath";

/// Owns the loaded eBPF object, the attached XDP program, and typed handles
/// to its maps. Dropping this detaches the program and unloads the maps —
/// there is no explicit "stop" method; a `RelayXdpLoader`'s lifetime *is*
/// the fast path's lifetime.
pub struct RelayXdpLoader {
    // Kept alive so the loaded program/maps stay attached; never read after
    // construction (the typed map handles below are the working API).
    _ebpf: Ebpf,
    addr_to_key: Mutex<AyaHashMap<aya::maps::MapData, AddrKey, PublicKey>>,
    key_to_addr: Mutex<AyaHashMap<aya::maps::MapData, PublicKey, AddrKey>>,
    gateway: Mutex<Array<aya::maps::MapData, GatewayInfo>>,
    stats: Mutex<PerCpuArray<aya::maps::MapData, u64>>,
    metrics: Arc<RelayMetrics>,
    iface: String,
}

impl RelayXdpLoader {
    /// Load `program_path` (built per `relay-ebpf/README.md`), attach it to
    /// `iface` in generic (SKB) mode (the most broadly compatible — see the
    /// PRD's Risks section on native/driver mode as a deployment-time
    /// choice, not a code branch), configure the relay's own listen
    /// `port`, and spawn the background gateway-refresh and stats-poll
    /// tasks. `metrics` is the same handle `ferrum relay` already exposes
    /// on `/metrics` (PRD FR4).
    pub async fn attach(
        program_path: &Path,
        iface: &str,
        port: u16,
        metrics: Arc<RelayMetrics>,
    ) -> Result<Arc<Self>, RelayXdpError> {
        // `Ebpf::load_file` / `Xdp::load`/`attach` / the map extraction
        // below were checked against the real `aya = "0.14.0"` source (see
        // the module doc) — including catching that `XdpFlags` doesn't
        // actually exist in this version; the real type is `XdpMode`, with
        // a `Skb` variant, in the version that's really resolvable now.
        let mut ebpf = Ebpf::load_file(program_path).map_err(|source| RelayXdpError::Load {
            path: program_path.display().to_string(),
            source,
        })?;
        // Surface the eBPF program's `aya_log_ebpf::debug!` calls through
        // this process's own `tracing` output. Best-effort: an older
        // kernel/object without the log map just means no fast-path debug
        // lines, never a reason to fail attaching.
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            debug!("relay xdp: no eBPF logger to attach (continuing): {e}");
        }
        let program: &mut Xdp = ebpf
            .program_mut(PROGRAM_NAME)
            .ok_or(RelayXdpError::ProgramNotFound(PROGRAM_NAME))?
            .try_into()
            .map_err(|_| RelayXdpError::ProgramNotFound(PROGRAM_NAME))?;
        program.load().map_err(|e| RelayXdpError::Attach {
            iface: iface.to_string(),
            source: e.into(),
        })?;
        program
            .attach(iface, XdpMode::Skb)
            .map_err(|e| RelayXdpError::Attach {
                iface: iface.to_string(),
                source: e.into(),
            })?;

        let mut relay_port_map: Array<_, u16> = ebpf
            .take_map("RELAY_PORT")
            .ok_or(RelayXdpError::ProgramNotFound("RELAY_PORT"))?
            .try_into()
            .map_err(|e| RelayXdpError::Map("RELAY_PORT", e))?;
        relay_port_map
            .set(0, port, 0)
            .map_err(|e| RelayXdpError::Map("RELAY_PORT", e))?;

        let addr_to_key = ebpf
            .take_map("ADDR_TO_KEY")
            .ok_or(RelayXdpError::ProgramNotFound("ADDR_TO_KEY"))?
            .try_into()
            .map_err(|e| RelayXdpError::Map("ADDR_TO_KEY", e))?;
        let key_to_addr = ebpf
            .take_map("KEY_TO_ADDR")
            .ok_or(RelayXdpError::ProgramNotFound("KEY_TO_ADDR"))?
            .try_into()
            .map_err(|e| RelayXdpError::Map("KEY_TO_ADDR", e))?;
        let gateway = ebpf
            .take_map("GATEWAY")
            .ok_or(RelayXdpError::ProgramNotFound("GATEWAY"))?
            .try_into()
            .map_err(|e| RelayXdpError::Map("GATEWAY", e))?;
        let stats = ebpf
            .take_map("STATS")
            .ok_or(RelayXdpError::ProgramNotFound("STATS"))?
            .try_into()
            .map_err(|e| RelayXdpError::Map("STATS", e))?;

        let this = Arc::new(Self {
            _ebpf: ebpf,
            addr_to_key: Mutex::new(addr_to_key),
            key_to_addr: Mutex::new(key_to_addr),
            gateway: Mutex::new(gateway),
            stats: Mutex::new(stats),
            metrics,
            iface: iface.to_string(),
        });

        // Resolve the gateway once before returning — until it succeeds,
        // the XDP program treats `GATEWAY` as unresolved and always misses
        // (fails open to userspace), so a slow/failed first resolution is
        // safe, just temporarily accelerating nothing.
        if let Err(e) = this.refresh_gateway().await {
            warn!("relay xdp: initial gateway resolution failed (fast path stays inactive until it succeeds): {e}");
        }

        tokio::spawn({
            let this = this.clone();
            async move { this.gateway_refresh_loop().await }
        });
        tokio::spawn({
            let this = this.clone();
            async move { this.stats_poll_loop().await }
        });

        Ok(this)
    }

    async fn gateway_refresh_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(GATEWAY_REFRESH);
        loop {
            tick.tick().await;
            if let Err(e) = self.refresh_gateway().await {
                warn!("relay xdp: gateway refresh failed: {e}");
            }
        }
    }

    async fn refresh_gateway(&self) -> Result<(), RelayXdpError> {
        let info = resolve_gateway_info(&self.iface)
            .await
            .map_err(RelayXdpError::GatewayResolution)?;
        // `Array::set` on the single-entry `GATEWAY` map.
        self.gateway
            .lock()
            .await
            .set(0, info, 0)
            .map_err(|e| RelayXdpError::Map("GATEWAY", e))?;
        debug!("relay xdp: gateway info refreshed");
        Ok(())
    }

    async fn stats_poll_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(STATS_POLL);
        loop {
            tick.tick().await;
            match self.stats.lock().await.get(&0, 0) {
                // `PerCpuArray::get` returns `Result<PerCpuValues<u64>,
                // MapError>` (confirmed against the real source) — one
                // value per CPU; the total is just their sum (PRD FR4 — a
                // plain aggregate, no per-flow breakdown).
                Ok(per_cpu_frames) => {
                    let frames: u64 = per_cpu_frames.iter().sum();
                    // Byte counter lives at index 1 of the same map (see
                    // `relay-ebpf/src/main.rs`'s `STAT_BYTES`).
                    match self.stats.lock().await.get(&1, 0) {
                        Ok(per_cpu_bytes) => {
                            let bytes: u64 = per_cpu_bytes.iter().sum();
                            self.metrics.set_xdp_totals(frames, bytes);
                        }
                        Err(e) => warn!("relay xdp: reading byte counter failed: {e}"),
                    }
                }
                Err(e) => warn!("relay xdp: reading frame counter failed: {e}"),
            }
        }
    }
}

impl RelayXdpHook for RelayXdpLoader {
    fn on_register(
        &self,
        key: PublicKey,
        addr: std::net::SocketAddr,
        evicted_addr: Option<std::net::SocketAddr>,
        evicted_key: Option<PublicKey>,
    ) {
        // IPv6 registrations simply never get mirrored — the fast path is
        // IPv4-only (PRD Non-Goals), so an IPv6 client's traffic always
        // takes the userspace path, exactly as if this hook didn't exist.
        let std::net::SocketAddr::V4(addr_v4) = addr else {
            return;
        };
        let addr_key = AddrKey::from_v4(addr_v4.ip().octets(), addr_v4.port());

        // Mirror `Clients::register`'s exact update, including clearing
        // whatever it just made stale (PRD FR3) — using `try_lock` because
        // this is called synchronously from `RelayServer::serve`'s hot
        // path; a fast path update losing a race with itself under heavy
        // concurrent registration is a transient miss (fails open to
        // userspace), never a correctness problem.
        let Ok(mut addr_to_key) = self.addr_to_key.try_lock() else {
            debug!("relay xdp: addr_to_key busy; skipping this mirror (fails open)");
            return;
        };
        let Ok(mut key_to_addr) = self.key_to_addr.try_lock() else {
            debug!("relay xdp: key_to_addr busy; skipping this mirror (fails open)");
            return;
        };

        if let Some(std::net::SocketAddr::V4(old)) = evicted_addr {
            let old_key = AddrKey::from_v4(old.ip().octets(), old.port());
            let _ = addr_to_key.remove(&old_key);
        }
        if let Some(old_key) = evicted_key {
            let _ = key_to_addr.remove(&old_key);
        }
        if let Err(e) = addr_to_key.insert(addr_key, key, 0) {
            warn!("relay xdp: mirroring addr->key failed: {e}");
        }
        if let Err(e) = key_to_addr.insert(key, addr_key, 0) {
            warn!("relay xdp: mirroring key->addr failed: {e}");
        }
    }
}

/// Resolve this relay's own MAC/IP on `iface` plus its default gateway's
/// MAC, by shelling out to `ip` — matching this project's existing
/// convention of driving OS tools directly for platform state rather than
/// pulling a netlink client crate (see `crates/tunnel/src/device.rs`'s
/// `netsh` usage on Windows, `crates/tunnel/src/firewall.rs`'s `nft`).
async fn resolve_gateway_info(iface: &str) -> Result<GatewayInfo, String> {
    let relay_mac = read_iface_mac(iface).map_err(|e| format!("reading {iface}'s MAC: {e}"))?;
    let relay_ip = run_ip(&["-4", "-o", "addr", "show", "dev", iface])
        .await
        .ok()
        .and_then(|out| parse_iface_ipv4(&out))
        .ok_or_else(|| format!("no IPv4 address found on {iface}"))?;
    let gateway_ip = run_ip(&["route", "show", "default"])
        .await
        .ok()
        .and_then(|out| parse_default_gateway(&out))
        .ok_or_else(|| "no default IPv4 route found".to_string())?;
    let gateway_mac = resolve_neighbor_mac(gateway_ip).await?;

    Ok(GatewayInfo {
        relay_mac,
        relay_ip: u32::from_be_bytes(relay_ip.octets()),
        gateway_mac,
    })
}

/// Resolve `ip`'s MAC via its ARP/neighbor cache entry, pinging once first
/// to populate that cache if it's empty (a fresh boot, or a gateway the
/// kernel hasn't talked to in a while) — the standard nudge, since XDP
/// itself can't trigger ARP resolution on our behalf.
async fn resolve_neighbor_mac(ip: Ipv4Addr) -> Result<[u8; 6], String> {
    let ip_str = ip.to_string();
    if let Ok(out) = run_ip(&["neigh", "show", &ip_str]).await {
        if let Some(mac) = parse_neighbor_mac(&out) {
            return Ok(mac);
        }
    }
    // Nudge the kernel to resolve it, then check once more.
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", &ip_str])
        .output()
        .await;
    let out = run_ip(&["neigh", "show", &ip_str])
        .await
        .map_err(|e| format!("querying neighbor cache for {ip}: {e}"))?;
    parse_neighbor_mac(&out).ok_or_else(|| format!("could not resolve a MAC for gateway {ip}"))
}

async fn run_ip(args: &[&str]) -> Result<String, String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("running `ip {}`: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "`ip {}` exited with {}",
            args.join(" "),
            output.status
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| format!("`ip {}` output wasn't UTF-8: {e}", args.join(" ")))
}

fn read_iface_mac(iface: &str) -> Result<[u8; 6], String> {
    let path = format!("/sys/class/net/{iface}/address");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("reading {path}: {e}"))?;
    parse_mac(text.trim()).ok_or_else(|| format!("{path} did not contain a MAC address: {text:?}"))
}

/// Parse `ip route show default`'s output, e.g. `default via 192.168.1.1
/// dev eth0 proto dhcp metric 100`.
fn parse_default_gateway(route_show_output: &str) -> Option<Ipv4Addr> {
    for line in route_show_output.lines() {
        let rest = line.strip_prefix("default via ")?;
        let ip_str = rest.split_whitespace().next()?;
        if let Ok(ip) = ip_str.parse() {
            return Some(ip);
        }
    }
    None
}

/// Parse `ip neigh show <ip>`'s output, e.g. `192.168.1.1 dev eth0 lladdr
/// aa:bb:cc:dd:ee:ff REACHABLE`. Returns `None` for a state with no
/// resolved `lladdr` yet (e.g. `INCOMPLETE`/`FAILED`, or no entry at all).
fn parse_neighbor_mac(neigh_show_output: &str) -> Option<[u8; 6]> {
    for line in neigh_show_output.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "lladdr" {
                return parse_mac(tokens.next()?);
            }
        }
    }
    None
}

/// Parse `ip -4 -o addr show dev <iface>`'s output, e.g. `2: eth0    inet
/// 192.168.1.50/24 brd 192.168.1.255 scope global eth0\...`.
fn parse_iface_ipv4(addr_show_output: &str) -> Option<Ipv4Addr> {
    for line in addr_show_output.lines() {
        let idx = line.find("inet ")?;
        let rest = &line[idx + "inet ".len()..];
        let cidr = rest.split_whitespace().next()?;
        let ip_str = cidr.split('/').next()?;
        if let Ok(ip) = ip_str.parse() {
            return Some(ip);
        }
    }
    None
}

/// Parse a colon-separated MAC address string (`aa:bb:cc:dd:ee:ff`).
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are pure string-parsing functions with no `aya`/syscall
    // involvement, but this whole module only compiles on Linux (the `use
    // aya::...` above), so — like the rest of this file — these tests are
    // cross-compile-checked on the authoring host and run for real on a
    // Linux host/CI, not executed here. See the module doc.

    #[test]
    fn parses_default_gateway_from_ip_route_output() {
        let out = "default via 192.168.1.1 dev eth0 proto dhcp metric 100 \n";
        assert_eq!(
            parse_default_gateway(out),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn no_default_route_parses_to_none() {
        let out = "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n";
        assert_eq!(parse_default_gateway(out), None);
    }

    #[test]
    fn parses_resolved_neighbor_mac() {
        let out = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n";
        assert_eq!(
            parse_neighbor_mac(out),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn unresolved_neighbor_has_no_lladdr() {
        let out = "192.168.1.1 dev eth0  INCOMPLETE\n";
        assert_eq!(parse_neighbor_mac(out), None);
    }

    #[test]
    fn parses_iface_ipv4_from_ip_addr_output() {
        let out = "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever preferred_lft forever\n";
        assert_eq!(parse_iface_ipv4(out), Some("192.168.1.50".parse().unwrap()));
    }

    #[test]
    fn parses_mac_string() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(parse_mac("not-a-mac"), None);
        assert_eq!(parse_mac("aa:bb:cc"), None);
    }
}
