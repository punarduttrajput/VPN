//! Static TOML configuration for a tunnel instance (PRD FR4).
//!
//! Example:
//! ```toml
//! private_key = "<base64>"
//! listen_port = 51820
//! interface_address = "10.8.0.1/24"
//!
//! [peer]
//! public_key = "<base64>"
//! endpoint = "203.0.113.5:51820"
//! allowed_ips = ["10.8.0.2/32"]
//! ```

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::keys;

/// Top-level tunnel configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Base64 Curve25519 private key for this interface.
    pub private_key: String,
    /// UDP port to bind locally.
    pub listen_port: u16,
    /// CIDR address assigned to the local TUN interface, e.g. `10.8.0.1/24`.
    pub interface_address: String,
    /// The single remote peer (Phase 1 is point-to-point).
    pub peer: PeerConfig,
    /// Transport selection (Phase 2). Defaults to plain UDP when omitted, so
    /// Phase 1 configs keep working unchanged.
    #[serde(default)]
    pub transport: TransportConfig,
}

/// Which network transport carries the encrypted tunnel (PRD Phase 2, FR6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    /// Plain UDP (Phase 1 behavior).
    #[default]
    Udp,
    /// QUIC datagrams (Phase 2, FR2).
    Quic,
    /// MASQUE / HTTP3 CONNECT-UDP relay (Phase 2, FR3).
    Masque,
}

/// QUIC endpoint role for a point-to-point link: one peer accepts, one connects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportRole {
    /// Initiates the QUIC connection to the peer's endpoint.
    Client,
    /// Listens and accepts the peer's QUIC connection.
    Server,
}

/// The `[transport]` config block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TransportConfig {
    /// `udp` (default), `quic`, or `masque`.
    #[serde(default)]
    pub mode: TransportMode,
    /// Required for `quic`: this endpoint's role (`client` or `server`).
    #[serde(default)]
    pub role: Option<TransportRole>,
    /// TLS server name for QUIC / MASQUE (defaults to `vpn`).
    #[serde(default)]
    pub server_name: Option<String>,
    /// Required for `masque`: the MASQUE proxy's socket address (`ip:port`).
    #[serde(default)]
    pub masque_proxy: Option<String>,
    /// Pad datagrams to a uniform size to blunt size-fingerprinting (FR5).
    /// Both peers must set the same value. Defaults to off.
    #[serde(default)]
    pub padding: bool,
    /// Target padded size in bytes when `padding` is on (defaults to 1280).
    #[serde(default)]
    pub pad_to: Option<u16>,
    /// Add a random delay of up to this many milliseconds before each outgoing
    /// send to defeat timing-based traffic fingerprinting (FR5). Defaults to
    /// off. Both peers configure this independently.
    #[serde(default)]
    pub jitter_ms: Option<u16>,
}

/// Configuration for the remote peer.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Base64 Curve25519 public key of the peer.
    pub public_key: String,
    /// The peer's reachable UDP endpoint (`ip:port`).
    pub endpoint: String,
    /// CIDRs routed to this peer.
    pub allowed_ips: Vec<String>,
}

/// A parsed CIDR address: an IP plus prefix length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    /// The network/host address.
    pub addr: std::net::IpAddr,
    /// The prefix length in bits.
    pub prefix: u8,
}

impl Cidr {
    /// Whether `ip` falls within this CIDR (matching address family + prefix).
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let shift = 32 - u32::from(self.prefix.min(32));
                (u32::from(net) >> shift) == (u32::from(ip) >> shift)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let shift = 128 - u32::from(self.prefix.min(128));
                (u128::from(net) >> shift) == (u128::from(ip) >> shift)
            }
            _ => false, // mixed address families never match
        }
    }
}

impl FromStr for Cidr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (ip_part, prefix_part) = s.split_once('/').ok_or_else(|| {
            Error::ConfigInvalid(format!("'{s}' is not CIDR (expected ip/prefix)"))
        })?;
        let addr = ip_part
            .parse::<std::net::IpAddr>()
            .map_err(|e| Error::ConfigInvalid(format!("invalid IP '{ip_part}': {e}")))?;
        let prefix = prefix_part
            .parse::<u8>()
            .map_err(|e| Error::ConfigInvalid(format!("invalid prefix '{prefix_part}': {e}")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(Error::ConfigInvalid(format!(
                "prefix /{prefix} exceeds maximum /{max} for this address family"
            )));
        }
        Ok(Cidr { addr, prefix })
    }
}

impl Config {
    /// Load and validate config from a TOML file (PRD FR4: fail fast on bad input).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::ConfigRead {
            path: path.display().to_string(),
            source,
        })?;
        let config: Config = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate all fields: keys decode, port is non-zero, addresses are valid CIDR,
    /// and the peer endpoint parses as a socket address.
    pub fn validate(&self) -> Result<()> {
        keys::private_from_base64(&self.private_key)
            .map_err(|e| Error::ConfigInvalid(format!("private_key: {e}")))?;

        if self.listen_port == 0 {
            return Err(Error::ConfigInvalid("listen_port must be non-zero".into()));
        }

        self.interface_address
            .parse::<Cidr>()
            .map_err(|e| Error::ConfigInvalid(format!("interface_address: {e}")))?;

        keys::public_from_base64(&self.peer.public_key)
            .map_err(|e| Error::ConfigInvalid(format!("peer.public_key: {e}")))?;

        self.peer.endpoint.parse::<SocketAddr>().map_err(|e| {
            Error::ConfigInvalid(format!("peer.endpoint '{}': {e}", self.peer.endpoint))
        })?;

        if self.peer.allowed_ips.is_empty() {
            return Err(Error::ConfigInvalid(
                "peer.allowed_ips must not be empty".into(),
            ));
        }
        for cidr in &self.peer.allowed_ips {
            cidr.parse::<Cidr>()
                .map_err(|e| Error::ConfigInvalid(format!("peer.allowed_ips: {e}")))?;
        }

        // QUIC requires an explicit endpoint role (one peer accepts, one connects).
        if self.transport.mode == TransportMode::Quic && self.transport.role.is_none() {
            return Err(Error::ConfigInvalid(
                "transport.role (client|server) is required when transport.mode = quic".into(),
            ));
        }

        if self.transport.jitter_ms == Some(0) {
            return Err(Error::ConfigInvalid(
                "transport.jitter_ms must be > 0 when set (omit the field to disable jitter)"
                    .into(),
            ));
        }

        // MASQUE requires a proxy address that parses as a valid socket address.
        if self.transport.mode == TransportMode::Masque {
            let proxy = self.transport.masque_proxy.as_deref().ok_or_else(|| {
                Error::ConfigInvalid(
                    "transport.masque_proxy is required when transport.mode = masque".into(),
                )
            })?;
            proxy.parse::<SocketAddr>().map_err(|e| {
                Error::ConfigInvalid(format!("transport.masque_proxy '{proxy}': {e}"))
            })?;
        }

        Ok(())
    }

    /// The peer's endpoint as a parsed [`SocketAddr`] (validated beforehand).
    pub fn peer_endpoint(&self) -> Result<SocketAddr> {
        self.peer
            .endpoint
            .parse::<SocketAddr>()
            .map_err(|e| Error::ConfigInvalid(format!("peer.endpoint: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    fn valid_toml() -> String {
        let local = KeyPair::generate();
        let peer = KeyPair::generate();
        format!(
            r#"
            private_key = "{}"
            listen_port = 51820
            interface_address = "10.8.0.1/24"

            [peer]
            public_key = "{}"
            endpoint = "203.0.113.5:51820"
            allowed_ips = ["10.8.0.2/32"]
            "#,
            local.private_base64(),
            peer.public_base64(),
        )
    }

    #[test]
    fn parses_and_validates_good_config() {
        let cfg: Config = toml::from_str(&valid_toml()).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.listen_port, 51820);
        assert_eq!(cfg.peer.allowed_ips.len(), 1);
        assert_eq!(
            cfg.peer_endpoint().unwrap(),
            "203.0.113.5:51820".parse().unwrap()
        );
    }

    #[test]
    fn cidr_parses_ipv4_and_ipv6() {
        let v4: Cidr = "10.8.0.1/24".parse().unwrap();
        assert_eq!(v4.prefix, 24);
        let v6: Cidr = "fd00::1/64".parse().unwrap();
        assert_eq!(v6.prefix, 64);
    }

    #[test]
    fn cidr_contains_matches_within_prefix() {
        let net: Cidr = "10.8.0.0/24".parse().unwrap();
        assert!(net.contains("10.8.0.2".parse().unwrap()));
        assert!(net.contains("10.8.0.254".parse().unwrap()));
        assert!(!net.contains("10.8.1.1".parse().unwrap()));
        // host route
        let host: Cidr = "10.8.0.3/32".parse().unwrap();
        assert!(host.contains("10.8.0.3".parse().unwrap()));
        assert!(!host.contains("10.8.0.4".parse().unwrap()));
        // mixed families never match
        assert!(!net.contains("fd00::1".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_oversized_prefix() {
        assert!("10.0.0.1/33".parse::<Cidr>().is_err());
        assert!("fd00::1/129".parse::<Cidr>().is_err());
    }

    #[test]
    fn rejects_zero_port() {
        let mut cfg: Config = toml::from_str(&valid_toml()).unwrap();
        cfg.listen_port = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_bad_endpoint() {
        let mut cfg: Config = toml::from_str(&valid_toml()).unwrap();
        cfg.peer.endpoint = "not-a-socket".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_bad_private_key() {
        let mut cfg: Config = toml::from_str(&valid_toml()).unwrap();
        cfg.private_key = "tooshort".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_empty_allowed_ips() {
        let mut cfg: Config = toml::from_str(&valid_toml()).unwrap();
        cfg.peer.allowed_ips.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn defaults_to_udp_when_no_transport_block() {
        let cfg: Config = toml::from_str(&valid_toml()).unwrap();
        assert_eq!(cfg.transport.mode, TransportMode::Udp);
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_quic_transport_block() {
        let toml_str = format!(
            "{}\n[transport]\nmode = \"quic\"\nrole = \"client\"\nserver_name = \"vpn\"\n",
            valid_toml()
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.transport.mode, TransportMode::Quic);
        assert_eq!(cfg.transport.role, Some(TransportRole::Client));
        assert_eq!(cfg.transport.server_name.as_deref(), Some("vpn"));
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_quic_without_role() {
        let toml_str = format!("{}\n[transport]\nmode = \"quic\"\n", valid_toml());
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_padding_options() {
        let toml_str = format!(
            "{}\n[transport]\nmode = \"udp\"\npadding = true\npad_to = 1280\n",
            valid_toml()
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert!(cfg.transport.padding);
        assert_eq!(cfg.transport.pad_to, Some(1280));
        cfg.validate().unwrap();
    }

    #[test]
    fn padding_defaults_off() {
        let cfg: Config = toml::from_str(&valid_toml()).unwrap();
        assert!(!cfg.transport.padding);
        assert_eq!(cfg.transport.pad_to, None);
    }

    #[test]
    fn parses_jitter_ms() {
        let toml_str = format!(
            "{}\n[transport]\nmode = \"udp\"\njitter_ms = 20\n",
            valid_toml()
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.transport.jitter_ms, Some(20));
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_jitter_ms_zero() {
        let toml_str = format!(
            "{}\n[transport]\nmode = \"udp\"\njitter_ms = 0\n",
            valid_toml()
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_masque_transport_block() {
        let toml_str = format!(
            "{}\n[transport]\nmode = \"masque\"\nmasque_proxy = \"203.0.113.1:443\"\nserver_name = \"vpn\"\n",
            valid_toml()
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.transport.mode, TransportMode::Masque);
        assert_eq!(
            cfg.transport.masque_proxy.as_deref(),
            Some("203.0.113.1:443")
        );
        assert_eq!(cfg.transport.server_name.as_deref(), Some("vpn"));
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_masque_without_proxy() {
        let toml_str = format!("{}\n[transport]\nmode = \"masque\"\n", valid_toml());
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_masque_with_bad_proxy_addr() {
        let toml_str = format!(
            "{}\n[transport]\nmode = \"masque\"\nmasque_proxy = \"not-an-addr\"\n",
            valid_toml()
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }
}
