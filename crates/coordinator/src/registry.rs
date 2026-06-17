//! In-memory device registry and tunnel-IP allocator (PRD Phase 3, FR1/FR3).
//!
//! Holds only control metadata — public keys, endpoints, assigned tunnel IPs —
//! never user traffic (NFR4). Persistence (PostgreSQL) is a later increment;
//! this in-memory store is what the M1 coordinator runs on and is fully testable.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use thiserror::Error;

/// Errors from registry operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    /// The supplied public key was empty.
    #[error("public key must not be empty")]
    InvalidKey,
    /// No tunnel addresses remain in the pool.
    #[error("tunnel address pool exhausted")]
    PoolExhausted,
}

/// A registered device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Base64 Curve25519 public key (the device's identity).
    pub public_key: String,
    /// Human-friendly label.
    pub name: String,
    /// Reachable UDP endpoint `ip:port` (may be empty until known).
    pub endpoint: String,
    /// Assigned tunnel address.
    pub tunnel_ip: Ipv4Addr,
}

/// Registry of devices and their assigned tunnel addresses.
#[derive(Debug)]
pub struct Registry {
    base: Ipv4Addr,
    prefix: u8,
    next_host: u32,
    by_key: HashMap<String, Device>,
}

impl Registry {
    /// Create a registry allocating from `base`/`prefix` (host .1 is reserved).
    pub fn new(base: Ipv4Addr, prefix: u8) -> Self {
        Self {
            base,
            prefix,
            next_host: 2,
            by_key: HashMap::new(),
        }
    }

    /// Register or re-register a device. Re-registering the same public key is
    /// idempotent: the name/endpoint are refreshed and the existing IP retained.
    pub fn register(
        &mut self,
        public_key: &str,
        name: &str,
        endpoint: &str,
    ) -> Result<Ipv4Addr, RegistryError> {
        if public_key.trim().is_empty() {
            return Err(RegistryError::InvalidKey);
        }
        if let Some(existing) = self.by_key.get_mut(public_key) {
            existing.name = name.to_string();
            existing.endpoint = endpoint.to_string();
            return Ok(existing.tunnel_ip);
        }
        let ip = self.allocate()?;
        self.by_key.insert(
            public_key.to_string(),
            Device {
                public_key: public_key.to_string(),
                name: name.to_string(),
                endpoint: endpoint.to_string(),
                tunnel_ip: ip,
            },
        );
        Ok(ip)
    }

    /// Allocate the next free host address in the pool (excludes network,
    /// broadcast, and the reserved `.1`).
    fn allocate(&mut self) -> Result<Ipv4Addr, RegistryError> {
        let base = u32::from(self.base);
        let host_bits = 32 - self.prefix;
        let max_offset = if host_bits >= 32 {
            u32::MAX
        } else {
            1u32 << host_bits
        };
        while self.next_host < max_offset.saturating_sub(1) {
            let candidate = Ipv4Addr::from(base + self.next_host);
            self.next_host += 1;
            if !self.by_key.values().any(|d| d.tunnel_ip == candidate) {
                return Ok(candidate);
            }
        }
        Err(RegistryError::PoolExhausted)
    }

    /// Peers the requesting device may reach. Phase 3 M1 is a full mesh: every
    /// device sees every other. ACL/policy filtering arrives in a later increment.
    pub fn network_map(&self, requester: &str) -> Vec<Device> {
        self.by_key
            .values()
            .filter(|d| d.public_key != requester)
            .cloned()
            .collect()
    }

    /// Number of registered devices.
    pub fn device_count(&self) -> usize {
        self.by_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)
    }

    #[test]
    fn allocates_sequentially_from_host_2() {
        let mut r = registry();
        assert_eq!(
            r.register("a", "A", "").unwrap(),
            Ipv4Addr::new(10, 8, 0, 2)
        );
        assert_eq!(
            r.register("b", "B", "").unwrap(),
            Ipv4Addr::new(10, 8, 0, 3)
        );
        assert_eq!(r.device_count(), 2);
    }

    #[test]
    fn reregister_is_idempotent_and_refreshes_metadata() {
        let mut r = registry();
        let ip1 = r.register("a", "A", "1.1.1.1:51820").unwrap();
        let ip2 = r.register("a", "A2", "2.2.2.2:51820").unwrap();
        assert_eq!(ip1, ip2, "same key keeps its IP");
        assert_eq!(r.device_count(), 1);
        let peers = r.network_map("b");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].endpoint, "2.2.2.2:51820", "endpoint refreshed");
    }

    #[test]
    fn rejects_empty_key() {
        assert_eq!(
            registry().register("", "x", ""),
            Err(RegistryError::InvalidKey)
        );
    }

    #[test]
    fn network_map_excludes_self() {
        let mut r = registry();
        r.register("a", "A", "").unwrap();
        r.register("b", "B", "").unwrap();
        let map = r.network_map("a");
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].public_key, "b");
    }

    #[test]
    fn pool_exhaustion_is_reported() {
        // /30 => offsets 1..3; .1 reserved, so only .2 is allocatable before exhaustion.
        let mut r = Registry::new(Ipv4Addr::new(10, 0, 0, 0), 30);
        assert!(r.register("a", "A", "").is_ok());
        assert_eq!(r.register("b", "B", ""), Err(RegistryError::PoolExhausted));
    }
}
