//! Device registry and tunnel-IP allocator (PRD Phase 3, FR1/FR3/FR5).
//!
//! Holds only control metadata — public keys, endpoints, assigned tunnel IPs —
//! never user traffic (NFR4). Devices live in memory for fast lookups and are
//! written through to a [`Store`] for durability: in-memory by default, or SQLite
//! (the `sqlite` feature) so the registry survives a restart.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::Serialize;
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
    /// A key rotation targeted a public key already used by another device.
    #[error("target public key already in use")]
    KeyInUse,
    /// An authenticated identity attempted to register or rotate to a public
    /// key already bound to a *different* identity (or attempted to move away
    /// from a key it does not own) — PRD security-hardening.md SEC-002.
    #[error("public key is not authorized for this identity")]
    IdentityKeyMismatch,
    /// The persistence backend failed.
    #[error("persistence error: {0}")]
    Store(String),
}

/// A registered device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// SHA-256 pin (64 lowercase hex) of the TLS cert this device presents to
    /// QUIC dialers (SEC-004), or empty. Distributed to permitted peers.
    pub tls_cert_sha256: String,
}

/// Normalize a TLS pin (SHA-256 of the device's TLS public key) to 64 lowercase
/// hex digits, or `""` for none; `None` if malformed. Parsing is shared with
/// the clients (`ferrum_transport::fingerprint`) so both accept exactly the
/// same forms.
pub fn normalize_tls_pin(s: &str) -> Option<String> {
    use ferrum_transport::fingerprint::{fingerprint_hex, parse_fingerprint};
    if s.trim().is_empty() {
        return Some(String::new());
    }
    parse_fingerprint(s).ok().map(|fp| fingerprint_hex(&fp))
}

/// Registry of devices and their assigned tunnel addresses.
pub struct Registry {
    base: Ipv4Addr,
    prefix: u8,
    next_host: u32,
    by_key: HashMap<String, Device>,
    policy: Policy,
    store: Box<dyn Store>,
    /// Authenticated-identity -> device-public-key bindings (PRD
    /// security-hardening.md SEC-002). Keyed by a namespaced identity string
    /// (e.g. `oidc:<sub>`, `mtls:<cert fingerprint>`) so an authenticated
    /// caller cannot register or rotate onto a public key it hasn't already
    /// claimed, and a public key already claimed by one identity cannot be
    /// claimed by another.
    identity_keys: HashMap<String, String>,
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
            identity_keys: HashMap::new(),
        }
    }

    /// Create a registry backed by a durable [`Store`], loading any persisted
    /// devices (and identity->key bindings) into memory at startup.
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
        let identity_keys = store
            .load_bindings()
            .map_err(|e| RegistryError::Store(e.to_string()))?
            .into_iter()
            .collect();
        Ok(Self {
            base,
            prefix,
            next_host: 2,
            by_key,
            policy,
            store,
            identity_keys,
        })
    }

    /// Enforce and record the identity -> public-key binding for an
    /// authenticated `register_device` call (PRD security-hardening.md
    /// SEC-002). The first registration for `identity` binds it to
    /// `public_key`; a later registration for the same identity with a
    /// *different* key, or for a key already bound to a *different* identity,
    /// is rejected. Re-registering the same (identity, public_key) pair is a
    /// no-op.
    pub fn bind_identity(&mut self, identity: &str, public_key: &str) -> Result<(), RegistryError> {
        if let Some(bound) = self.identity_keys.get(identity) {
            return if bound == public_key {
                Ok(())
            } else {
                Err(RegistryError::IdentityKeyMismatch)
            };
        }
        if self.identity_keys.values().any(|k| k == public_key) {
            return Err(RegistryError::IdentityKeyMismatch);
        }
        self.store
            .upsert_binding(identity, public_key)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
        self.identity_keys
            .insert(identity.to_string(), public_key.to_string());
        Ok(())
    }

    /// Move an identity's key binding from `old_key` to `new_key` — the
    /// authorized rotation path for SEC-002, called from the authenticated
    /// `rotate_key` RPC. Rejected if `identity` is bound to a key other than
    /// `old_key` (rotating away a key it doesn't own), or if `new_key` is
    /// already bound to a *different* identity. An identity with no prior
    /// binding for `old_key` is allowed through (first authoritative claim —
    /// covers a pre-SEC-002 device rotated for the first time under this
    /// identity).
    pub fn rebind_identity(
        &mut self,
        identity: &str,
        old_key: &str,
        new_key: &str,
    ) -> Result<(), RegistryError> {
        // If `old_key` already belongs to someone, only its owner may rotate
        // it away.
        match self.identity_keys.iter().find(|(_, k)| *k == old_key) {
            Some((owner, _)) if owner != identity => {
                return Err(RegistryError::IdentityKeyMismatch)
            }
            Some(_) => {} // this identity already owns old_key
            None => {
                // `old_key` isn't bound to anyone — allow only as this
                // identity's first-ever claim (a pre-SEC-002 device rotated
                // for the first time). An identity that already owns a
                // *different* key may not "rotate away" a key it never held.
                if self.identity_keys.contains_key(identity) {
                    return Err(RegistryError::IdentityKeyMismatch);
                }
            }
        }
        if self
            .identity_keys
            .iter()
            .any(|(id, k)| id != identity && k == new_key)
        {
            return Err(RegistryError::IdentityKeyMismatch);
        }
        self.store
            .upsert_binding(identity, new_key)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
        self.identity_keys
            .insert(identity.to_string(), new_key.to_string());
        Ok(())
    }

    /// Register or re-register a device. Re-registering the same public key is
    /// idempotent: the name/endpoint/tags are refreshed and the existing IP kept
    /// (and any existing TLS pin left as is — see [`register_with_pin`](Self::register_with_pin)).
    pub fn register(
        &mut self,
        public_key: &str,
        name: &str,
        endpoint: &str,
        tags: &[String],
    ) -> Result<Ipv4Addr, RegistryError> {
        self.register_with_pin(public_key, name, endpoint, tags, None)
    }

    /// [`register`](Self::register), also setting the device's TLS pin
    /// (SEC-004) in the same single store write when `pin` is `Some` (already
    /// normalized — see [`normalize_tls_pin`]; `Some("")` clears it).
    pub fn register_with_pin(
        &mut self,
        public_key: &str,
        name: &str,
        endpoint: &str,
        tags: &[String],
        pin: Option<&str>,
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
            if let Some(pin) = pin {
                existing.tls_cert_sha256 = pin.to_string();
            }
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
                tls_cert_sha256: pin.unwrap_or_default().to_string(),
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

    /// Record the TLS cert pin a registered device presents (SEC-004); `pin`
    /// must already be normalized ([`normalize_tls_pin`]) — empty clears it.
    pub fn set_tls_pin(&mut self, public_key: &str, pin: &str) -> Result<(), RegistryError> {
        let device = {
            let device = self
                .by_key
                .get_mut(public_key)
                .ok_or(RegistryError::UnknownDevice)?;
            if device.tls_cert_sha256 == pin {
                return Ok(()); // unchanged: skip the write
            }
            device.tls_cert_sha256 = pin.to_string();
            device.clone()
        };
        self.store
            .upsert(&device)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
        Ok(())
    }

    /// Rotate a device's static public key (PRD Phase 3, FR3 — key rotation).
    ///
    /// The device's identity in the network is preserved: its assigned tunnel
    /// IP, name, endpoint, tags, and published candidates all carry over to the
    /// new key. Only the key (its `by_key` entry, and the persisted row) changes.
    /// Rotating to the same key is a no-op that returns the current IP. The new
    /// key must be non-empty and not already used by another device.
    pub fn rotate_key(&mut self, old: &str, new: &str) -> Result<Ipv4Addr, RegistryError> {
        if new.trim().is_empty() {
            return Err(RegistryError::InvalidKey);
        }
        if old == new {
            // No change requested: report the existing assignment (or that the
            // device is unknown, mirroring the rotate-an-unknown-device case).
            return self
                .by_key
                .get(old)
                .map(|d| d.tunnel_ip)
                .ok_or(RegistryError::UnknownDevice);
        }
        if self.by_key.contains_key(new) {
            return Err(RegistryError::KeyInUse);
        }
        // Move the record from the old key to the new one, keeping everything
        // else. `remove` ends the `&mut by_key` borrow before we touch the store.
        let mut device = self
            .by_key
            .remove(old)
            .ok_or(RegistryError::UnknownDevice)?;
        device.public_key = new.to_string();
        let ip = device.tunnel_ip;
        self.by_key.insert(new.to_string(), device.clone());
        // Write-through: persist the record under the new key first (so the
        // device is never absent from the store), then drop the old key's row.
        self.store
            .upsert(&device)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
        self.store
            .remove(old)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
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

    /// All registered devices, for an operator surface to list. Unlike
    /// `network_map`, this is not filtered by policy — it's the full registry,
    /// not one device's view of its peers. Sorted by `(name, public_key)` for a
    /// stable display order.
    pub fn devices(&self) -> Vec<Device> {
        let mut list: Vec<Device> = self.by_key.values().cloned().collect();
        list.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.public_key.cmp(&b.public_key))
        });
        list
    }

    /// Revoke a device: evict it from the registry and the backing store.
    /// `allocate` never revisits addresses below `next_host`, so the freed
    /// tunnel IP is not immediately reused by a subsequent registration.
    pub fn remove(&mut self, public_key: &str) -> Result<(), RegistryError> {
        self.by_key
            .remove(public_key)
            .ok_or(RegistryError::UnknownDevice)?;
        self.store
            .remove(public_key)
            .map_err(|e| RegistryError::Store(e.to_string()))?;
        Ok(())
    }

    /// The current ACL policy, for an operator surface to inspect.
    pub fn policy(&self) -> Policy {
        self.policy.clone()
    }

    /// Replace the ACL policy at runtime. Not persisted: a coordinator restart
    /// reverts to the `--policy` file (or allow-all if none was given).
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
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
    fn rotate_key_preserves_ip_tags_and_candidates() {
        let mut r = registry();
        let ip = r
            .register("oldkey", "laptop", "1.1.1.1:51820", &tags(&["dev"]))
            .unwrap();
        r.set_candidates(
            "oldkey",
            &["1.1.1.1:51820".into(), "203.0.113.5:7777".into()],
        )
        .unwrap();

        let rotated_ip = r.rotate_key("oldkey", "newkey").unwrap();
        assert_eq!(rotated_ip, ip, "tunnel IP is preserved across rotation");
        assert_eq!(r.device_count(), 1, "rotation does not create a new device");

        // The old key is gone; a peer now sees the device under its new key with
        // everything else intact.
        let map = r.network_map("peer");
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].public_key, "newkey");
        assert_eq!(map[0].tunnel_ip, ip);
        assert_eq!(map[0].name, "laptop");
        assert_eq!(map[0].endpoint, "1.1.1.1:51820");
        assert_eq!(map[0].tags, tags(&["dev"]));
        assert_eq!(map[0].candidates.len(), 2);
    }

    #[test]
    fn rotate_key_rejects_unknown_device() {
        let mut r = registry();
        assert_eq!(
            r.rotate_key("ghost", "newkey"),
            Err(RegistryError::UnknownDevice)
        );
    }

    #[test]
    fn rotate_key_rejects_collision_with_existing_key() {
        let mut r = registry();
        r.register("a", "A", "", &[]).unwrap();
        r.register("b", "B", "", &[]).unwrap();
        assert_eq!(r.rotate_key("a", "b"), Err(RegistryError::KeyInUse));
        // Both devices are untouched.
        assert_eq!(r.device_count(), 2);
    }

    #[test]
    fn rotate_key_to_same_key_is_noop() {
        let mut r = registry();
        let ip = r.register("a", "A", "", &[]).unwrap();
        assert_eq!(r.rotate_key("a", "a").unwrap(), ip);
        assert_eq!(r.device_count(), 1);
    }

    #[test]
    fn rotate_key_rejects_empty_new_key() {
        let mut r = registry();
        r.register("a", "A", "", &[]).unwrap();
        assert_eq!(r.rotate_key("a", "   "), Err(RegistryError::InvalidKey));
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

    #[test]
    fn devices_lists_everyone_unfiltered_and_sorted() {
        let mut r = registry();
        r.register("bbb", "zeta", "", &tags(&["dev"])).unwrap();
        r.register("aaa", "alpha", "", &tags(&["server"])).unwrap();
        let devices = r.devices();
        assert_eq!(devices.len(), 2);
        // Sorted by name, not registration order.
        assert_eq!(devices[0].name, "alpha");
        assert_eq!(devices[1].name, "zeta");
    }

    #[test]
    fn remove_evicts_a_device() {
        let mut r = registry();
        r.register("a", "A", "", &[]).unwrap();
        r.register("b", "B", "", &[]).unwrap();
        assert_eq!(r.device_count(), 2);
        r.remove("a").unwrap();
        assert_eq!(r.device_count(), 1);
        let map = r.network_map("peer");
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].public_key, "b");
    }

    #[test]
    fn remove_rejects_unknown_device() {
        let mut r = registry();
        assert_eq!(r.remove("ghost"), Err(RegistryError::UnknownDevice));
    }

    #[test]
    fn policy_get_and_set_round_trip() {
        let policy = Policy::from_rules(vec![crate::policy::AclRule {
            src: tags(&["dev"]),
            dst: tags(&["server"]),
        }]);
        let mut r = Registry::with_policy(Ipv4Addr::new(10, 8, 0, 0), 24, policy.clone());
        assert_eq!(r.policy(), policy);

        let replacement = Policy::allow_all();
        r.set_policy(replacement.clone());
        assert_eq!(r.policy(), replacement);
    }

    #[test]
    fn bind_identity_first_use_then_rejects_key_swap() {
        let mut r = registry();
        r.bind_identity("oidc:alice", "keyA").unwrap();
        // Same identity, same key: idempotent.
        r.bind_identity("oidc:alice", "keyA").unwrap();
        // Same identity, different key: rejected.
        assert_eq!(
            r.bind_identity("oidc:alice", "keyB"),
            Err(RegistryError::IdentityKeyMismatch)
        );
    }

    #[test]
    fn bind_identity_rejects_key_already_claimed_by_another_identity() {
        let mut r = registry();
        r.bind_identity("oidc:alice", "keyA").unwrap();
        assert_eq!(
            r.bind_identity("oidc:bob", "keyA"),
            Err(RegistryError::IdentityKeyMismatch)
        );
    }

    #[test]
    fn rebind_identity_moves_binding_on_authorized_rotation() {
        let mut r = registry();
        r.bind_identity("oidc:alice", "keyA").unwrap();
        r.rebind_identity("oidc:alice", "keyA", "keyB").unwrap();
        // The binding now follows keyB; keyA is free for reuse by anyone.
        assert_eq!(
            r.bind_identity("oidc:bob", "keyA"),
            Ok(()),
            "old key is released once its identity has rotated away"
        );
        assert_eq!(
            r.bind_identity("oidc:alice", "keyB"),
            Ok(()),
            "the rotated key is now alice's"
        );
    }

    #[test]
    fn rebind_identity_rejects_rotating_a_key_owned_by_another_identity() {
        let mut r = registry();
        r.bind_identity("oidc:alice", "keyA").unwrap();
        assert_eq!(
            r.rebind_identity("oidc:bob", "keyA", "keyC"),
            Err(RegistryError::IdentityKeyMismatch),
            "bob does not own keyA"
        );
    }

    #[test]
    fn rebind_identity_rejects_grabbing_an_unbound_key_once_already_established() {
        let mut r = registry();
        r.bind_identity("oidc:alice", "keyA").unwrap();
        // alice already owns keyA; "legacyKey" belongs to no one on record.
        // alice may not also grab it via a bogus rotation.
        assert_eq!(
            r.rebind_identity("oidc:alice", "legacyKey", "keyD"),
            Err(RegistryError::IdentityKeyMismatch)
        );
    }

    #[test]
    fn rebind_identity_allows_first_claim_of_an_unbound_legacy_key() {
        let mut r = registry();
        // charlie has never been bound to anything; rotating an unbound
        // (pre-SEC-002) device's key is allowed as a first claim.
        r.rebind_identity("oidc:charlie", "legacyKey", "keyD")
            .unwrap();
        assert_eq!(
            r.bind_identity("oidc:other", "keyD"),
            Err(RegistryError::IdentityKeyMismatch),
            "keyD is now charlie's"
        );
    }

    #[test]
    fn rebind_identity_rejects_stealing_a_key_bound_to_another_identity() {
        let mut r = registry();
        r.bind_identity("oidc:alice", "keyA").unwrap();
        r.bind_identity("oidc:bob", "keyB").unwrap();
        assert_eq!(
            r.rebind_identity("oidc:alice", "keyA", "keyB"),
            Err(RegistryError::IdentityKeyMismatch),
            "keyB already belongs to bob"
        );
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

    #[cfg(feature = "sqlite")]
    #[test]
    fn rotate_key_persists_through_the_store() {
        use crate::sqlite::SqliteStore;

        let store = SqliteStore::open_in_memory().unwrap();
        let mut r = Registry::with_store(
            Ipv4Addr::new(10, 8, 0, 0),
            24,
            Policy::allow_all(),
            Box::new(store),
        )
        .unwrap();
        let ip = r
            .register("oldkey", "laptop", "1.1.1.1:51820", &[])
            .unwrap();
        r.rotate_key("oldkey", "newkey").unwrap();

        // A fresh registry over the same store sees only the new key, same IP.
        let store = r.store;
        let mut r2 =
            Registry::with_store(Ipv4Addr::new(10, 8, 0, 0), 24, Policy::allow_all(), store)
                .unwrap();
        assert_eq!(r2.device_count(), 1);
        // The new key keeps the same IP; re-registering it is idempotent.
        assert_eq!(
            r2.register("newkey", "laptop", "1.1.1.1:51820", &[])
                .unwrap(),
            ip
        );
        // The old key is gone.
        let map = r2.network_map("peer");
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].public_key, "newkey");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn identity_bindings_persist_through_the_store() {
        use crate::sqlite::SqliteStore;

        let store = SqliteStore::open_in_memory().unwrap();
        let mut r = Registry::with_store(
            Ipv4Addr::new(10, 8, 0, 0),
            24,
            Policy::allow_all(),
            Box::new(store),
        )
        .unwrap();
        r.bind_identity("oidc:alice", "keyA").unwrap();

        // A fresh registry over the same store still enforces the binding.
        let store = r.store;
        let mut r2 =
            Registry::with_store(Ipv4Addr::new(10, 8, 0, 0), 24, Policy::allow_all(), store)
                .unwrap();
        assert_eq!(
            r2.bind_identity("oidc:alice", "keyB"),
            Err(RegistryError::IdentityKeyMismatch),
            "binding survived the restart"
        );
        assert_eq!(r2.bind_identity("oidc:alice", "keyA"), Ok(()));
    }
}
