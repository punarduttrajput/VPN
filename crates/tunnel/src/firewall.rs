//! Linux (`nftables`) kill-switch firewall rules (Phase 5).
//!
//! A dedicated `inet ferrum_killswitch` table with an `output` chain whose
//! policy is `drop`, accepting only loopback, egress over the tunnel
//! interface, and the coordinator endpoint(s) — so the control plane can
//! still reconnect while everything else is blocked. A dedicated table makes
//! teardown atomic (`nft delete table …`) and easy to clear by hand if the
//! app ever dies mid-engage.
//!
//! This lives in `ferrum-tunnel` (rather than the Tauri desktop crate) so
//! both the desktop shell's direct/no-helper fallback path and the
//! privileged-helper daemon (Phase 5) share the exact same rule generation
//! and `nft` invocation instead of duplicating it.

use std::io;
use std::net::IpAddr;

/// The dedicated firewall table name — namespaced so teardown never touches
/// unrelated rules and a stale ruleset is obvious and easy to drop.
pub const TABLE: &str = "ferrum_killswitch";

/// Build the `nft -f -` script that engages the kill-switch on `iface`, allowing
/// outbound only to loopback, the tunnel interface, and each address in
/// `allow_ips` (the coordinator/relay endpoints, so reconnect still works).
///
/// Pure (no I/O) so the rule logic is unit-testable without root or a live `nft`.
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
pub fn disengage_args() -> [&'static str; 4] {
    ["delete", "table", "inet", TABLE]
}

/// Run `nft -f -`, feeding it `script` on stdin.
pub fn run_nft_script(script: &str) -> io::Result<()> {
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
        Err(io::Error::other(format!(
            "nft exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Run `nft` with plain arguments (e.g. [`disengage_args`]).
pub fn run_nft(args: &[&str]) -> io::Result<()> {
    use std::process::Command;

    let out = Command::new("nft").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft {args:?} exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Engage the kill-switch on `iface`: build and run the `nft` script in one call.
pub fn engage(iface: &str, allow_ips: &[IpAddr]) -> io::Result<()> {
    run_nft_script(&engage_script(iface, allow_ips))
}

/// Disengage the kill-switch: remove our dedicated table in one call.
pub fn disengage() -> io::Result<()> {
    run_nft(&disengage_args())
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
}
