//! Access control for [`MasqueProxy`](crate::MasqueProxy) (SEC-015).
//!
//! A CONNECT-UDP proxy relays to whatever `host:port` its client names. Left
//! open, that makes it an SSRF hop into the proxy's own network (loopback
//! services, the LAN, cloud metadata at 169.254.169.254) and a UDP reflector.
//! [`TargetPolicy`] decides which targets are relayed:
//!
//! - **Default (empty allowlist):** any *public unicast* address. Loopback,
//!   private (RFC 1918, CGNAT, ULA), link-local, "this network", reserved and
//!   IPv4-mapped forms of those are refused.
//! - **With an allowlist:** only targets inside a listed CIDR, which is how an
//!   operator opens a private range deliberately (e.g. a mesh behind the proxy,
//!   or loopback in tests). Nothing else, public or private, is relayed.
//!
//! In both cases unspecified, multicast and broadcast addresses and port 0 are
//! always refused: those are never a legitimate peer.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::TransportError;

/// An IP network (`addr/prefix`), for [`TargetPolicy`] allowlists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parse `a.b.c.d/n`, `x::y/n`, or a bare address (a host route).
    pub fn parse(s: &str) -> Result<Self, TransportError> {
        let bad = || TransportError::Setup(format!("'{s}' is not an IP network (addr/prefix)"));
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((a, p)) => (a.parse().map_err(|_| bad())?, p.parse().map_err(|_| bad())?),
            None => {
                let a: IpAddr = s.trim().parse().map_err(|_| bad())?;
                (a, if a.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if matches!(addr, IpAddr::V4(_)) {
            32
        } else {
            128
        };
        if prefix > max {
            return Err(bad());
        }
        Ok(Self { addr, prefix })
    }

    /// Whether `ip` is inside this network. Mixed families never match.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Which CONNECT-UDP targets a proxy will relay to. See the module docs.
#[derive(Debug, Clone, Default)]
pub struct TargetPolicy {
    allow: Vec<IpNet>,
}

impl TargetPolicy {
    /// The default: public unicast targets only.
    pub fn public_only() -> Self {
        Self::default()
    }

    /// Relay only to targets inside `nets` (CIDR strings). Private and
    /// loopback ranges are allowed when, and only when, listed here.
    pub fn allowlist<I, S>(nets: I) -> Result<Self, TransportError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allow = nets
            .into_iter()
            .map(|s| IpNet::parse(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { allow })
    }

    /// Whether the proxy may relay to `target`.
    pub fn allows(&self, target: SocketAddr) -> bool {
        let ip = canonical(target.ip());
        if target.port() == 0 || never_a_peer(ip) {
            return false;
        }
        if self.allow.is_empty() {
            !is_special(ip)
        } else {
            self.allow.iter().any(|n| n.contains(ip))
        }
    }
}

/// Treat an IPv4-mapped IPv6 address as the IPv4 address it carries, so
/// `::ffff:127.0.0.1` can't slip past the IPv4 loopback rule.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Addresses no allowlist can open: unspecified, multicast, broadcast.
fn never_a_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}

/// Non-public ranges refused by the default policy.
fn is_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || o[0] == 0 // "this network" 0.0.0.0/8
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT 100.64.0.0/10
                || o[0] >= 240 // reserved 240.0.0.0/4
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || v6 == Ipv6Addr::UNSPECIFIED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_policy_relays_public_unicast_only() {
        let p = TargetPolicy::public_only();
        for ok in ["203.0.113.7:51820", "8.8.8.8:53", "[2001:db8::1]:443"] {
            assert!(p.allows(sa(ok)), "{ok}");
        }
        for bad in [
            "127.0.0.1:22",
            "10.0.0.5:51820",
            "172.16.1.1:1",
            "192.168.1.10:51820",
            "169.254.169.254:80", // cloud metadata
            "100.64.0.1:1",
            "0.1.2.3:1",
            "240.0.0.1:1",
            "[::1]:22",
            "[fd00::1]:1",
            "[fe80::1]:1",
            "[::ffff:127.0.0.1]:22", // mapped loopback
            "[::ffff:10.0.0.1]:22",
        ] {
            assert!(!p.allows(sa(bad)), "{bad}");
        }
    }

    #[test]
    fn never_relays_unspecified_multicast_broadcast_or_port_zero() {
        let p = TargetPolicy::allowlist(["0.0.0.0/0", "::/0"]).unwrap();
        for bad in [
            "0.0.0.0:1",
            "224.0.0.1:1",
            "255.255.255.255:1",
            "[::]:1",
            "[ff02::1]:1",
            "203.0.113.7:0",
        ] {
            assert!(!p.allows(sa(bad)), "{bad}");
        }
        assert!(
            p.allows(sa("10.0.0.5:51820")),
            "an explicit /0 opens private"
        );
    }

    #[test]
    fn allowlist_opens_exactly_the_listed_ranges() {
        let p = TargetPolicy::allowlist(["10.8.0.0/16", "127.0.0.1"]).unwrap();
        assert!(p.allows(sa("10.8.3.4:51820")));
        assert!(p.allows(sa("127.0.0.1:9")));
        assert!(!p.allows(sa("127.0.0.2:9")), "host route is exact");
        assert!(!p.allows(sa("10.9.0.1:51820")));
        assert!(
            !p.allows(sa("203.0.113.7:51820")),
            "an allowlist also closes public targets"
        );
        assert!(TargetPolicy::allowlist(["not-a-net"]).is_err());
        assert!(TargetPolicy::allowlist(["10.0.0.0/33"]).is_err());
    }

    #[test]
    fn ipnet_contains_handles_edges() {
        let all = IpNet::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("1.2.3.4".parse().unwrap()));
        assert!(!all.contains("::1".parse().unwrap()), "families don't mix");
        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }
}
