//! Kill-switch firewall enforcement (PRD Phase 5, FR5 — shell side).
//!
//! The shared core ([`ferrum_client_core::FerrumClient`]) decides *when* non-tunnel
//! traffic should be blocked — it emits [`ClientEvent::TrafficBlocked(bool)`] whenever
//! the derived signal (`kill-switch armed ∧ tunnel not Connected`) flips. This
//! module is the platform-specific half that *enforces* it: when the signal goes
//! true it installs leak-blocking firewall rules; when it goes false it removes
//! them.
//!
//! [`ClientEvent`]: ferrum_client_core::ClientEvent
//!
//! On Linux we drive `nftables` (`nft`): a dedicated `inet ferrum_killswitch`
//! table with an `output` chain whose policy is `drop`, accepting only loopback,
//! egress over the tunnel interface, and the coordinator endpoint(s) — so the
//! control plane can still reconnect while everything else is blocked. A dedicated
//! table makes teardown atomic (`nft delete table …`) and easy to clear by hand if
//! the app ever dies mid-engage.
//!
//! On other platforms enforcement is not yet implemented; the enforcer logs that
//! the signal was observed but leaves the OS untouched (the UI still reflects the
//! intent via the `kill-switch` event). macOS (`pf`) and Windows (WFP) are
//! per-platform follow-ups.

use std::net::IpAddr;

/// The dedicated firewall table/anchor name — namespaced so teardown never
/// touches unrelated rules and a stale ruleset is obvious and easy to drop.
pub const TABLE: &str = "ferrum_killswitch";

/// Build the `nft -f -` script that engages the kill-switch on `iface`, allowing
/// outbound only to loopback, the tunnel interface, and each address in
/// `allow_ips` (the coordinator/relay endpoints, so reconnect still works).
///
/// Pure (no I/O) so the rule logic is unit-testable without root or a live `nft`.
// Called by `engage` on Linux and by the unit tests on every platform; unused in
// a non-Linux, non-test build.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn engage_script(iface: &str, allow_ips: &[IpAddr]) -> String {
    let mut allow = String::new();
    for ip in allow_ips {
        match ip {
            IpAddr::V4(v4) => allow.push_str(&format!("    ip daddr {v4} accept\n")),
            IpAddr::V6(v6) => allow.push_str(&format!("    ip6 daddr {v6} accept\n")),
        }
    }
    // Flush first so re-engaging is idempotent (a prior table is replaced, not
    // duplicated). Policy `drop` blocks everything not explicitly accepted.
    format!(
        "add table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname \"lo\" accept
    oifname \"{iface}\" accept
{allow}  }}
}}
"
    )
}

/// Arguments to `nft` that remove the kill-switch table (disengage / teardown).
// Used by `disengage` on Linux and by the unit tests; unused otherwise.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn disengage_args() -> [&'static str; 4] {
    ["delete", "table", "inet", TABLE]
}

/// Tracks whether the kill-switch firewall rules are currently installed, so the
/// enforcer only shells out on a real change and can tear down on exit.
#[derive(Default)]
pub struct KillSwitch {
    applied: bool,
}

impl KillSwitch {
    /// Engage the kill-switch on `iface`, permitting outbound to `allow_ips`
    /// (typically the coordinator's resolved address[es]) in addition to loopback
    /// and the tunnel interface. Idempotent. A no-op success on platforms without
    /// an implementation (the signal is still surfaced to the UI).
    pub fn engage(&mut self, iface: &str, allow_ips: &[IpAddr]) {
        #[cfg(target_os = "linux")]
        {
            let script = engage_script(iface, allow_ips);
            match run_nft_script(&script) {
                Ok(()) => {
                    self.applied = true;
                    log::info!("kill-switch engaged on {iface} ({} allowed)", allow_ips.len());
                }
                Err(e) => log::error!("kill-switch engage failed: {e}"),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (iface, allow_ips);
            log::warn!(
                "kill-switch requested but firewall enforcement is not implemented on this platform"
            );
        }
    }

    /// Remove the kill-switch rules. Idempotent; safe to call when not engaged.
    pub fn disengage(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if !self.applied {
                return;
            }
            match run_nft(&disengage_args()) {
                Ok(()) => log::info!("kill-switch disengaged"),
                // A missing table on teardown is fine (already gone).
                Err(e) => log::warn!("kill-switch disengage: {e}"),
            }
            self.applied = false;
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.applied = false;
        }
    }

    /// Whether the rules are currently installed.
    // Exposed for tests/diagnostics; not read on the main path.
    #[allow(dead_code)]
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

/// Best-effort teardown on drop, so a crash/exit doesn't strand the network in a
/// blocked state. (Tauri does not guarantee managed-state `Drop` on exit, so the
/// app also disengages explicitly on `RunEvent::Exit`.)
impl Drop for KillSwitch {
    fn drop(&mut self) {
        self.disengage();
    }
}

#[cfg(target_os = "linux")]
fn run_nft_script(script: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("nft stdin piped")
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "nft exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(target_os = "linux")]
fn run_nft(args: &[&str]) -> std::io::Result<()> {
    use std::process::Command;

    let out = Command::new("nft").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "nft {args:?} exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engage_script_blocks_by_default_and_allows_loopback_and_iface() {
        let s = engage_script("ferrum0", &[]);
        assert!(s.contains("policy drop"), "default must drop");
        assert!(s.contains("oifname \"lo\" accept"));
        assert!(s.contains("oifname \"ferrum0\" accept"));
        // Replacing any prior table keeps re-engage idempotent.
        assert!(s.contains(&format!("delete table inet {TABLE}")));
        assert!(s.contains(&format!("table inet {TABLE}")));
    }

    #[test]
    fn engage_script_allowlists_coordinator_addresses() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let s = engage_script("ferrum0", &[v4, v6]);
        assert!(s.contains("ip daddr 203.0.113.7 accept"));
        assert!(s.contains("ip6 daddr 2001:db8::1 accept"));
    }

    #[test]
    fn disengage_targets_only_our_table() {
        assert_eq!(disengage_args(), ["delete", "table", "inet", TABLE]);
    }

    #[test]
    fn killswitch_tracks_applied_state_on_unsupported_platforms() {
        // On non-Linux the calls are no-ops; `applied` only flips on Linux. This
        // exercises the state machine without requiring `nft`.
        let mut ks = KillSwitch::default();
        assert!(!ks.is_applied());
        ks.disengage(); // safe when never engaged
        assert!(!ks.is_applied());
    }
}
