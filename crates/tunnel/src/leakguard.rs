//! Linux (`nftables`) leak-guard firewall rules (PRD `leak-protection.md`, FR4).
//!
//! A dedicated `inet ferrum_leakguard` table, engaged for the lifetime of a
//! connection (unlike the opt-in kill-switch in [`crate::firewall`], which is
//! a coordinator-unreachable panic mode). Its `output` chain has **policy
//! `accept`** — ordinary traffic is untouched — and drops only the two leak
//! classes:
//!
//! * **DNS lock** (when resolvers are configured): plaintext DNS (53) and DoT
//!   (853) may leave only toward a configured resolver or out the tunnel
//!   interface — so no query reaches the LAN/ISP resolver. DoH is a documented
//!   non-goal (indistinguishable from HTTPS).
//! * **IPv6 block** (when the effective policy blocks — see
//!   [`ferrum_core::config::Ipv6LeakPolicy::blocks`]): all IPv6 output is
//!   dropped except loopback, the tunnel interface, link-local destinations,
//!   and ICMPv6 neighbor discovery — closing the classic "v4-only tunnel on a
//!   v6 network" bypass.
//!
//! A dedicated table keeps teardown atomic (`nft delete table …`) and
//! independent of the kill-switch table; both survive an app crash visibly
//! and are easy to clear by hand. Shared by the CLI, the desktop's
//! direct-fallback path, and the privileged-helper daemon — one rule
//! generation, no duplication (mirrors [`crate::firewall`]).

use std::io;
use std::net::IpAddr;

use crate::firewall::{run_nft, run_nft_script};

/// The dedicated leak-guard table name — namespaced so teardown never touches
/// unrelated rules (including the kill-switch's own table).
pub const TABLE: &str = "ferrum_leakguard";

/// Build the `nft -f -` script that engages the leak guard on `iface`.
///
/// `dns_servers` are the approved resolvers (the DNS lock is emitted only when
/// non-empty — locking DNS with nowhere approved to send it would just break
/// name resolution, not protect it); `block_ipv6` adds the IPv6 drop rules.
///
/// Pure (no I/O) so the rule logic is unit-testable without root or a live `nft`.
pub fn engage_script(iface: &str, dns_servers: &[IpAddr], block_ipv6: bool) -> String {
    let mut rules = String::new();
    if !dns_servers.is_empty() {
        for ip in dns_servers {
            let fam = match ip {
                IpAddr::V4(_) => "ip",
                IpAddr::V6(_) => "ip6",
            };
            rules.push_str(&format!(
                "    {fam} daddr {ip} meta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} accept\n"
            ));
        }
        rules.push_str("    meta l4proto { tcp, udp } th dport { 53, 853 } drop\n");
    }
    if block_ipv6 {
        // Link-local + neighbor discovery keep the physical interface's LAN
        // housekeeping alive; everything else v6 is the leak being closed.
        rules.push_str(
            "    ip6 daddr fe80::/10 accept\n    icmpv6 type { nd-router-solicit, \
             nd-neighbor-solicit, nd-neighbor-advert } accept\n    meta nfproto ipv6 drop\n",
        );
    }
    // Flush first so re-engaging is idempotent (a prior table is replaced, not
    // duplicated). Policy `accept`: only the listed leak classes are dropped.
    format!(
        "add table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
  chain output {{
    type filter hook output priority 0; policy accept;
    oifname \"lo\" accept
    oifname \"{iface}\" accept
{rules}  }}
}}
"
    )
}

/// Arguments to `nft` that remove the leak-guard table (disengage / teardown).
pub fn disengage_args() -> [&'static str; 4] {
    ["delete", "table", "inet", TABLE]
}

/// Engage the leak guard on `iface`: build and run the `nft` script in one call.
pub fn engage(iface: &str, dns_servers: &[IpAddr], block_ipv6: bool) -> io::Result<()> {
    run_nft_script(&engage_script(iface, dns_servers, block_ipv6))
}

/// Disengage the leak guard: remove our dedicated table in one call.
pub fn disengage() -> io::Result<()> {
    run_nft(&disengage_args())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engage_script_keeps_ordinary_traffic_flowing() {
        let s = engage_script("ferrum0", &[], true);
        assert!(s.contains("policy accept"), "leak guard must not block-all");
        assert!(s.contains("oifname \"lo\" accept"));
        assert!(s.contains("oifname \"ferrum0\" accept"));
        // Replacing any prior table keeps re-engage idempotent.
        assert!(s.contains(&format!("delete table inet {TABLE}")));
        assert!(s.contains(&format!("table inet {TABLE}")));
    }

    #[test]
    fn dns_lock_allows_configured_resolvers_then_drops_the_rest() {
        let v4: IpAddr = "10.99.0.53".parse().unwrap();
        let v6: IpAddr = "fd00::53".parse().unwrap();
        let s = engage_script("ferrum0", &[v4, v6], false);
        assert!(
            s.contains("ip daddr 10.99.0.53 meta l4proto { tcp, udp } th dport { 53, 853 } accept")
        );
        assert!(
            s.contains("ip6 daddr fd00::53 meta l4proto { tcp, udp } th dport { 53, 853 } accept")
        );
        let drop_rule = "meta l4proto { tcp, udp } th dport { 53, 853 } drop";
        assert!(s.contains(drop_rule));
        // Accepts must precede the drop, or the lock blocks its own resolvers.
        assert!(s.find("daddr 10.99.0.53").unwrap() < s.find(drop_rule).unwrap());
        // No v6 rules when blocking is off.
        assert!(!s.contains("meta nfproto ipv6 drop"));
    }

    #[test]
    fn no_dns_lock_without_approved_resolvers() {
        // Locking DNS with no approved resolver would break resolution outright.
        let s = engage_script("ferrum0", &[], true);
        assert!(!s.contains("th dport { 53, 853 } drop"));
    }

    #[test]
    fn ipv6_block_exempts_link_local_and_neighbor_discovery() {
        let s = engage_script("ferrum0", &[], true);
        assert!(s.contains("ip6 daddr fe80::/10 accept"));
        assert!(s.contains("nd-neighbor-solicit"));
        let v6_drop = "meta nfproto ipv6 drop";
        assert!(s.contains(v6_drop));
        // Exemptions must precede the drop.
        assert!(s.find("fe80::/10").unwrap() < s.find(v6_drop).unwrap());
    }

    #[test]
    fn disengage_targets_only_our_table() {
        assert_eq!(disengage_args(), ["delete", "table", "inet", TABLE]);
    }

    #[test]
    fn tables_are_distinct_from_the_kill_switch() {
        assert_ne!(TABLE, crate::firewall::TABLE);
    }
}
