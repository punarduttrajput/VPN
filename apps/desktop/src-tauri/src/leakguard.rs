//! Leak-protection enforcement state (PRD `leak-protection.md`, M2): system
//! DNS + the `ferrum_leakguard` firewall table while a session is connected.
//!
//! Unlike the opt-in kill-switch ([`crate::killswitch`], a coordinator-
//! unreachable panic mode that blocks everything), the leak guard engages for
//! the lifetime of every connection that has resolvers or an IPv6-block
//! policy, and never touches ordinary traffic — it only forces DNS through
//! the tunnel and closes the off-tunnel IPv6 bypass.
//!
//! Linux enforcement tries the privileged `ferrum-helper` daemon first (the
//! same trust boundary and fallback shape as the kill-switch), falling back
//! to in-process `ferrum_tunnel::{dns, leakguard}` calls (which need an
//! elevated GUI). Windows enforcement belongs to the helper service (M3);
//! macOS is deferred with the rest of the Apple targets.

use std::net::IpAddr;

/// Tracks whether leak protection is applied (and on which interface), so
/// disengage/Drop tears down exactly once and on the right link.
#[derive(Default)]
pub struct LeakGuard {
    engaged_iface: Option<String>,
}

impl LeakGuard {
    /// Engage DNS + leak-guard enforcement on `iface`. Idempotent (re-engaging
    /// replaces the rules; the DNS backup from the first engage is preserved).
    /// With nothing to enforce it stays inactive and says so — an honest
    /// "unprotected", never a silent one.
    pub fn engage(&mut self, iface: &str, dns_servers: &[IpAddr], block_ipv6: bool) {
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
        #[cfg(not(target_os = "linux"))]
        {
            let _ = iface;
            log::warn!(
                "leak protection is not enforced on this platform yet \
                 (Windows lands with the helper service in M3; macOS is deferred)"
            );
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
        #[cfg(not(target_os = "linux"))]
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
}
