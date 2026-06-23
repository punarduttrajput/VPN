//! Device registry and tunnel-IP allocator (PRD Phase 3, FR1/FR3/FR5).
//!
//! Holds only control metadata — public keys, endpoints, assigned tunnel IPs —
//! never user traffic (NFR4). Devices live in memory for fast lookups and are
//! written through to a [`Store`] for durability: in-memory by default, or SQLite
//! (the `sqlite` feature) so the registry survives a restart.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use thiserror::Error;

use crate::policy::Policy;
use crate::store::{MemoryStore, Store};

/// Errors from registry operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    /// The supplied public key was empty.
    #[error("public key must not be empty")]
    InvalidKey,
    /// No tunnel addresses remain in the pool.
    #[error("tunnel address pool exhausted")]
    PoolExhausted,
    /// An operation referenced a device that is not registered.
    #[error("device not registered")]
    UnknownDevice,
    /// The persistence backend failed.
    #[error("persistence error: {0}")]
    Store(String),
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
    /// Tags used for ACL/policy matching.
    pub tags: Vec<String>,
    /// ICE candidates this device has published (host + STUN reflexive
    /// `ip:port` strings), distributed to permitted peers for NAT traversal
    /// (PRD Phase 4). Empty until the device calls `set_candidates`.
    pub candidates: Vec<String>,
}

/// Registry of devices and their assigned tunnel addresses.
pub struct Registry {
    base: Ipv4Addr,
    prefix: u8,
    next_host: u32,
    by_key: HashMap<String, Device>,
    policy: Policy,
    store: Box<dyn Store>,
}

impl Registry {
    /// Create a full-mesh registry allocating from `base`/`prefix` (host .1 reserved).
    pub fn new(base: Ipv4Addr, prefix: u8) -> Self {
        Self::with_policy(base, prefix, Policy::allow_all())
    }

    /// Create an in-memory registry with an explicit access [`Policy`].
    pub fn with_policy(base: Ipv4Addr, prefix: u8, policy: Policy) -> Self {
        Self {
            base,
            prefix,
            next_host: 2,
            by_key: HashMap::new(),
            policy,
            store: Box::new(MemoryStore),
        }
    }

    /// Create a registry backed by a durable [`Store`], loading any persisted
    /// devices into memory at startup.
    pub fn with_store(
        base: Ipv4Addr,
        prefix: u8,
        policy: Policy,
        store: Box<dyn Store>,
    ) -> Result<Self, RegistryError> {
        let mut by_key = HashMap::new();
        for d in store
            .load_all()
            .map_err(|e| RegistryError::Store(e.to_string()))?
        {
            by_key.insert(d.public_key.clone(), d);
        }
        Ok(Self {
            base,
            prefix,
            next_host: 2,
            by_key,
            policy,
            store,
        })
    }

    /// Register or re-register a device. Re-registering the same public key is
    /// idempotent: the name/endpoint/tags are refreshed and the existing IP kept.
    pub fn register(
        &mut self,
        public_key: &str,
        name: &str,
        endpoint: &str,
        tags: &[String],
    ) -> Result<Ipv4Addr, RegistryError> {
        if public_key.trim().is_empty() {
            return Err(RegistryError::InvalidKey);
        }
        // Build (or refresh) the device, then write through to the store. The
        // device is cloned out so the `&mut self.by_key` borrow ends before the
        // `self.store` borrow.
        let device = if let Some(existing) = self.by_key.get_mut(public_key) {
            existing.name = name.to_string();
            existing.endpoint = endpoint.to_string();
            existing.tags = tags.to_vec();
            existing.clone()
        } else {
            let ip = self.allocate()?;
            let device = Device {
                public_key: public_key.to_string(),
                name: name.to_string(),
                endpoint: endpoint.to_string(),
                tunnel_ip: ip,
                tags: tags.to_vec(),
                // Candidates are published separately (after STUN), via
                // `set_candidates`; a fresh registration starts with none.
                candidates: Vec::new(),
            };
            self.by_key.insert(public_key.to_string(), device.clone());
            device
        };
        self.store
            .upsert(&device)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
        Ok(device.tunnel_ip)
    }

    /// Replace a registered device's published ICE candidates (PRD Phase 4).
    ///
    /// Called when a device has gathered its candidates (host + STUN
    /// server-reflexive) and wants peers to learn them. The device must already
    /// be registered. Re-registering does **not** clear candidates, so a device
    /// can register once and publish/refresh candidates independently.
    pub fn set_candidates(
        &mut self,
        public_key: &str,
        candidates: &[String],
    ) -> Result<(), RegistryError> {
        let device = {
            let device = self
                .by_key
                .get_mut(public_key)
                .ok_or(RegistryError::UnknownDevice)?;
            device.candidates = candidates.to_vec();
            device.clone()
        };
        self.store
            .upsert(&device)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
        Ok(())
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

    /// Peers the requesting device may reach, filtered by the access [`Policy`]
    /// (deny-by-default unless the policy is allow-all). The requester's tags are
    /// taken from its registration (empty if it is not registered).
    pub fn network_map(&self, requester: &str) -> Vec<Device> {
        let src_tags = self
            .by_key
            .get(requester)
            .map(|d| d.tags.clone())
            .unwrap_or_default();
        self.by_key
            .values()
            .filter(|d| d.public_key != requester)
            .filter(|d| self.policy.allows(&src_tags, &d.tags))
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

    fn tags(s: &[&str]) -> Vec<String> {
        s.iter().map(|t| t.to_string()).collect()
    }

    #[test]
    fn allocates_sequentially_from_host_2() {
        let mut r = registry();
        assert_eq!(
            r.register("a", "A", "", &[]).unwrap(),
            Ipv4Addr::new(10, 8, 0, 2)
        );
        assert_eq!(
            r.register("b", "B", "", &[]).unwrap(),
            Ipv4Addr::new(10, 8, 0, 3)
        );
        assert_eq!(r.device_count(), 2);
    }

    #[test]
    fn reregister_is_idempotent_and_refreshes_metadata() {
        let mut r = registry();
        let ip1 = r.register("a", "A", "1.1.1.1:51820", &[]).unwrap();
        let ip2 = r.register("a", "A2", "2.2.2.2:51820", &[]).unwrap();
        assert_eq!(ip1, ip2, "same key keeps its IP");
        assert_eq!(r.device_count(), 1);
        let peers = r.network_map("b");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].endpoint, "2.2.2.2:51820", "endpoint refreshed");
    }

    #[test]
    fn rejects_empty_key() {
        assert_eq!(
            registry().register("", "x", "", &[]),
            Err(RegistryError::InvalidKey)
        );
    }

    #[test]
    fn network_map_excludes_self() {
        let mut r = registry();
        r.register("a", "A", "", &[]).unwrap();
        r.register("b", "B", "", &[]).unwrap();
        let map = r.network_map("a");
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].public_key, "b");
    }

    #[test]
    fn set_candidates_updates_device_and_survives_reregister() {
        let mut r = registry();
        r.register("a", "A", "1.1.1.1:51820", &[]).unwrap();
        r.set_candidates("a", &["1.1.1.1:51820".into(), "203.0.113.5:7777".into()])
            .unwrap();

        // A peer's view of "a" now carries the published candidates.
        let map = r.network_map("b");
        assert_eq!(map.len(), 1);
        assert_eq!(
            map[0].candidates,
            vec!["1.1.1.1:51820".to_string(), "203.0.113.5:7777".to_string()]
        );

        // Re-registering refreshes metadata but does not wipe candidates.
        r.register("a", "A", "9.9.9.9:51820", &[]).unwrap();
        assert_eq!(r.network_map("b")[0].candidates.len(), 2);
    }

    #[test]
    fn set_candidates_rejects_unknown_device() {
        let mut r = registry();
        assert_eq!(
            r.set_candidates("ghost", &["1.1.1.1:1".into()]),
            Err(RegistryError::UnknownDevice)
        );
    }

    #[test]
    fn pool_exhaustion_is_reported() {
        // /30 => offsets 1..3; .1 reserved, so only .2 is allocatable before exhaustion.
        let mut r = Registry::new(Ipv4Addr::new(10, 0, 0, 0), 30);
        assert!(r.register("a", "A", "", &[]).is_ok());
        assert_eq!(
            r.register("b", "B", "", &[]),
            Err(RegistryError::PoolExhausted)
        );
    }

    #[test]
    fn network_map_is_filtered_by_policy() {
        // dev -> server allowed; not the reverse, and dev does not see other dev.
        let policy = Policy::from_rules(vec![crate::policy::AclRule {
            src: tags(&["dev"]),
            dst: tags(&["server"]),
        }]);
        let mut r = Registry::with_policy(Ipv4Addr::new(10, 8, 0, 0), 24, policy);
        r.register("devkey", "laptop", "", &tags(&["dev"])).unwrap();
        r.register("srvkey", "gateway", "", &tags(&["server"]))
            .unwrap();
        r.register("dev2key", "phone", "", &tags(&["dev"])).unwrap();

        // dev sees the server, but not the other dev.
        let dev_map = r.network_map("devkey");
        assert_eq!(dev_map.len(), 1);
        assert_eq!(dev_map[0].public_key, "srvkey");

        // server is not permitted to initiate to dev -> sees nobody.
        assert!(r.network_map("srvkey").is_empty());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn registry_persists_devices_across_restart() {
        use crate::sqlite::SqliteStore;

        let path = std::env::temp_dir().join(format!("ferrum-reg-test-{}.db", std::process::id()));
        let path = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        // First "run": register two devices through a SQLite-backed registry.
        {
            let store = SqliteStore::open(&path).unwrap();
            let mut r = Registry::with_store(
                Ipv4Addr::new(10, 8, 0, 0),
                24,
                Policy::allow_all(),
                Box::new(store),
            )
            .unwrap();
            assert_eq!(
                r.register("AAA", "a", "1.1.1.1:51820", &[]).unwrap(),
                Ipv4Addr::new(10, 8, 0, 2)
            );
            assert_eq!(
                r.register("BBB", "b", "2.2.2.2:51820", &[]).unwrap(),
                Ipv4Addr::new(10, 8, 0, 3)
            );
        }

        // "Restart": a fresh registry over the same store keeps devices + IPs.
        let store = SqliteStore::open(&path).unwrap();
        let mut r = Registry::with_store(
            Ipv4Addr::new(10, 8, 0, 0),
            24,
            Policy::allow_all(),
            Box::new(store),
        )
        .unwrap();
        assert_eq!(r.device_count(), 2);
        // Re-registering keeps the persisted address (idempotent across restart).
        assert_eq!(
            r.register("AAA", "a", "1.1.1.1:51820", &[]).unwrap(),
            Ipv4Addr::new(10, 8, 0, 2)
        );

        let _ = std::fs::remove_file(&path);
    }
}
