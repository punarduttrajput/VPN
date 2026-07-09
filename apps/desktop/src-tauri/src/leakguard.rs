//! Leak-protection enforcement state (PRD `leak-protection.md`, M2 Linux /
//! M3 Windows): system DNS + a leak-guard firewall while a session is
//! connected.
//!
//! Unlike the opt-in kill-switch ([`crate::killswitch`], a coordinator-
//! unreachable panic mode that blocks everything), the leak guard engages for
//! the lifetime of every connection that has resolvers or an IPv6-block
//! policy, and never touches ordinary traffic — it only forces DNS through
//! the tunnel and closes the off-tunnel IPv6 bypass.
//!
//! **Linux** enforcement tries the privileged `ferrum-helper` daemon first
//! (the same trust boundary and fallback shape as the kill-switch), falling
//! back to in-process `ferrum_tunnel::{dns, leakguard}` calls (which need an
//! elevated GUI). **Windows** enforcement runs inside the already-elevated
//! helper service ([`crate::service`]): adapter DNS via `netsh`
//! (`ferrum_tunnel::dns`) plus WFP filters under the leak guard's own
//! provider/sublayer ([`crate::killswitch::wfp::LEAK_GUARD`]) — see
//! [`engage_leakguard_filters`]. macOS is deferred with the rest of the
//! Apple targets.

use std::net::IpAddr;

use crate::killswitch::FilterSpec;

/// Build the WFP filter set that engages the leak guard on `iface` — the
/// Windows analog of `ferrum_tunnel::leakguard::engage_script`. Pure (no WFP,
/// no admin) so the rule logic is unit-testable on any platform. Same shape
/// as the Linux table: loopback/tunnel permits, then the DNS lock (only when
/// resolvers exist — locking DNS with nowhere approved to send it would break
/// resolution, not protect it), then the v6 block with its link-local permit
/// (kernel neighbor discovery never reaches the ALE connect layer, so unlike
/// Linux it needs no explicit exemption).
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn engage_leakguard_filters(
    iface: &str,
    dns_servers: &[IpAddr],
    block_ipv6: bool,
) -> Vec<FilterSpec> {
    if dns_servers.is_empty() && !block_ipv6 {
        return Vec::new();
    }
    let mut specs = vec![
        FilterSpec::AllowLoopback,
        FilterSpec::AllowInterface(iface.to_string()),
    ];
    if !dns_servers.is_empty() {
        specs.push(FilterSpec::BlockDnsPorts);
        specs.extend(dns_servers.iter().copied().map(FilterSpec::AllowDnsTo));
    }
    if block_ipv6 {
        specs.push(FilterSpec::BlockAllV6);
        specs.push(FilterSpec::AllowV6LinkLocal);
    }
    specs
}

/// Tracks whether leak protection is applied (and on which interface), so
/// disengage/Drop tears down exactly once and on the right link.
#[derive(Default)]
pub struct LeakGuard {
    engaged_iface: Option<String>,
    /// Runtime ids of the WFP filters we installed, so teardown removes
    /// exactly those (mirrors [`crate::killswitch::KillSwitch`]).
    #[cfg(target_os = "windows")]
    filter_ids: Vec<u64>,
}

impl LeakGuard {
    /// Engage DNS + leak-guard enforcement on `iface`. A repeat call while
    /// engaged (a reconnect) is a no-op — the rules are connection-lifetime.
    /// With nothing to enforce it stays inactive and says so — an honest
    /// "unprotected", never a silent one.
    pub fn engage(&mut self, iface: &str, dns_servers: &[IpAddr], block_ipv6: bool) {
        if self.engaged_iface.is_some() {
            return;
        }
        if dns_servers.is_empty() && !block_ipv6 {
            log::warn!(
                "no DNS resolvers configured/advertised and IPv6 blocking is off — \
                 this session has no leak protection"
            );
            return;
        }
        #[cfg(target_os = "linux")]
        {
            use ferrum_tunnel::helper_proto::HelperRequest;

            if !dns_servers.is_empty() {
                let req = HelperRequest::SetDns {
                    iface: iface.to_string(),
                    servers: dns_servers.iter().map(ToString::to_string).collect(),
                };
                let result = match crate::killswitch::ask_helper(req) {
                    Some(r) => r,
                    None => {
                        ferrum_tunnel::dns::set_dns(iface, dns_servers).map_err(|e| e.to_string())
                    }
                };
                match result {
                    Ok(()) => log::info!(
                        "system DNS pointed at {} tunnel resolver(s)",
                        dns_servers.len()
                    ),
                    Err(e) => log::error!("setting system DNS failed: {e}"),
                }
            }
            let req = HelperRequest::LeakGuardEngage {
                iface: iface.to_string(),
                dns_servers: dns_servers.iter().map(ToString::to_string).collect(),
                block_ipv6,
            };
            let result = match crate::killswitch::ask_helper(req) {
                Some(r) => r,
                None => ferrum_tunnel::leakguard::engage(iface, dns_servers, block_ipv6)
                    .map_err(|e| e.to_string()),
            };
            match result {
                Ok(()) => log::info!("leak guard engaged on {iface} (block IPv6: {block_ipv6})"),
                Err(e) => log::error!("engaging leak guard failed: {e}"),
            }
            // Even after a partial failure, mark engaged so teardown runs — the
            // restore/disengage paths are safe when nothing was applied.
            self.engaged_iface = Some(iface.to_string());
        }
        #[cfg(target_os = "windows")]
        {
            use crate::killswitch::wfp;

            if !dns_servers.is_empty() {
                match ferrum_tunnel::dns::set_dns(iface, dns_servers) {
                    Ok(()) => log::info!(
                        "adapter DNS pointed at {} tunnel resolver(s)",
                        dns_servers.len()
                    ),
                    Err(e) => log::error!("setting adapter DNS failed: {e}"),
                }
            }
            match wfp::engage(
                &wfp::LEAK_GUARD,
                &engage_leakguard_filters(iface, dns_servers, block_ipv6),
            ) {
                Ok(ids) => {
                    self.filter_ids = ids;
                    log::info!("leak guard engaged on {iface} (block IPv6: {block_ipv6})");
                }
                // `wfp::engage` installs inside a transaction — a failure
                // aborts atomically, nothing is left half-applied.
                Err(e) => log::error!("engaging leak guard failed: {e}"),
            }
            // Mark engaged even after a partial failure so DNS restore runs.
            self.engaged_iface = Some(iface.to_string());
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = iface;
            log::warn!("leak protection is not enforced on this platform (macOS is deferred)");
        }
    }

    /// Restore pre-connection DNS and remove the leak-guard rules. Idempotent;
    /// safe to call when never engaged.
    pub fn disengage(&mut self) {
        let Some(iface) = self.engaged_iface.take() else {
            return;
        };
        #[cfg(target_os = "linux")]
        {
            use ferrum_tunnel::helper_proto::HelperRequest;

            let restore = match crate::killswitch::ask_helper(HelperRequest::RestoreDns {
                iface: iface.clone(),
            }) {
                Some(r) => r,
                None => ferrum_tunnel::dns::restore_dns(&iface).map_err(|e| e.to_string()),
            };
            if let Err(e) = restore {
                log::warn!("restoring system DNS: {e}");
            }
            let result = match crate::killswitch::ask_helper(HelperRequest::LeakGuardDisengage) {
                Some(r) => r,
                None => ferrum_tunnel::leakguard::disengage().map_err(|e| e.to_string()),
            };
            match result {
                Ok(()) => log::info!("leak guard disengaged"),
                // A missing table on teardown is fine (already gone).
                Err(e) => log::warn!("leak-guard disengage: {e}"),
            }
        }
        #[cfg(target_os = "windows")]
        {
            use crate::killswitch::wfp;

            if let Err(e) = ferrum_tunnel::dns::restore_dns(&iface) {
                log::warn!("restoring adapter DNS: {e}");
            }
            match wfp::disengage(&wfp::LEAK_GUARD, &self.filter_ids) {
                Ok(()) => log::info!("leak guard disengaged"),
                // Missing filters on teardown are fine (already gone).
                Err(e) => log::warn!("leak-guard disengage: {e}"),
            }
            self.filter_ids.clear();
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let _ = iface;
    }
}

/// Best-effort teardown on drop, so an exit path that skips the explicit
/// disengage never strands the resolver/rules (mirrors [`crate::killswitch`]).
impl Drop for LeakGuard {
    fn drop(&mut self) {
        self.disengage();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_enforce_stays_inactive() {
        let mut lg = LeakGuard::default();
        lg.engage("ferrum0", &[], false);
        assert!(lg.engaged_iface.is_none());
        lg.disengage(); // must be a clean no-op
    }

    #[test]
    fn filters_lock_dns_to_approved_resolvers() {
        let dns: IpAddr = "10.99.0.53".parse().unwrap();
        let specs = engage_leakguard_filters("ferrum0", &[dns], false);
        assert!(specs.contains(&FilterSpec::AllowLoopback));
        assert!(specs.contains(&FilterSpec::AllowInterface("ferrum0".into())));
        assert!(specs.contains(&FilterSpec::BlockDnsPorts));
        assert!(specs.contains(&FilterSpec::AllowDnsTo(dns)));
        // No v6 rules when blocking is off.
        assert!(!specs.contains(&FilterSpec::BlockAllV6));
    }

    #[test]
    fn filters_block_v6_with_link_local_exempt() {
        let specs = engage_leakguard_filters("ferrum0", &[], true);
        assert!(specs.contains(&FilterSpec::BlockAllV6));
        assert!(specs.contains(&FilterSpec::AllowV6LinkLocal));
        assert!(specs.contains(&FilterSpec::AllowInterface("ferrum0".into())));
        // No DNS lock without approved resolvers.
        assert!(!specs.contains(&FilterSpec::BlockDnsPorts));
    }

    #[test]
    fn no_filters_when_there_is_nothing_to_enforce() {
        assert!(engage_leakguard_filters("ferrum0", &[], false).is_empty());
    }

    #[test]
    fn filters_never_default_block_all_traffic() {
        // The leak guard must never behave like the kill-switch.
        let dns: IpAddr = "fd00::53".parse().unwrap();
        let specs = engage_leakguard_filters("ferrum0", &[dns], true);
        assert!(!specs.contains(&FilterSpec::BlockAll));
    }
}
