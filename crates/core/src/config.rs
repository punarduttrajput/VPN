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
}
