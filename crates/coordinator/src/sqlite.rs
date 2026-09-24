//! SQLite-backed [`Store`] (PRD Phase 3, FR5) — durable device persistence.
//!
//! Uses bundled SQLite (no system library needed), so it builds on any host.
//! Behind the `sqlite` feature. Tags are stored as a JSON array.

use std::net::Ipv4Addr;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::registry::Device;
use crate::store::{Store, StoreError};

fn backend(e: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// A device store backed by a SQLite database.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (creating if needed) a SQLite database at `path` and ensure the schema.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(backend)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                 public_key TEXT PRIMARY KEY,
                 name       TEXT NOT NULL,
                 endpoint   TEXT NOT NULL,
                 tunnel_ip  TEXT NOT NULL,
                 tags       TEXT NOT NULL,
                 candidates TEXT NOT NULL DEFAULT '[]',
                 tls_cert_sha256 TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS identity_bindings (
                 identity   TEXT PRIMARY KEY,
                 public_key TEXT NOT NULL
             );",
        )
        .map_err(backend)?;
        // Migrate databases created before the candidates / TLS-pin (SEC-004)
        // columns existed. A duplicate-column error just means the schema is
        // already current.
        for migration in [
            "ALTER TABLE devices ADD COLUMN candidates TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE devices ADD COLUMN tls_cert_sha256 TEXT NOT NULL DEFAULT ''",
        ] {
            if let Err(e) = conn.execute(migration, []) {
                if !e.to_string().contains("duplicate column name") {
                    return Err(backend(e));
                }
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (tests).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::open(":memory:")
    }
}

impl Store for SqliteStore {
    fn load_all(&self) -> Result<Vec<Device>, StoreError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT public_key, name, endpoint, tunnel_ip, tags, candidates, tls_cert_sha256 \
                 FROM devices",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(backend)?;

        let mut devices = Vec::new();
        for row in rows {
            let (public_key, name, endpoint, ip_str, tags_json, candidates_json, tls_cert_sha256) =
                row.map_err(backend)?;
            let tunnel_ip: Ipv4Addr = ip_str
                .parse()
                .map_err(|e| StoreError::Backend(format!("bad tunnel_ip '{ip_str}': {e}")))?;
            let tags: Vec<String> = serde_json::from_str(&tags_json).map_err(backend)?;
            let candidates: Vec<String> =
                serde_json::from_str(&candidates_json).map_err(backend)?;
            devices.push(Device {
                public_key,
                name,
                endpoint,
                tunnel_ip,
                tags,
                candidates,
                tls_cert_sha256,
            });
        }
        Ok(devices)
    }

    fn upsert(&self, device: &Device) -> Result<(), StoreError> {
        let tags = serde_json::to_string(&device.tags).map_err(backend)?;
        let candidates = serde_json::to_string(&device.candidates).map_err(backend)?;
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO devices
                 (public_key, name, endpoint, tunnel_ip, tags, candidates, tls_cert_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(public_key) DO UPDATE SET
                 name = ?2, endpoint = ?3, tunnel_ip = ?4, tags = ?5, candidates = ?6,
                 tls_cert_sha256 = ?7",
            params![
                device.public_key,
                device.name,
                device.endpoint,
                device.tunnel_ip.to_string(),
                tags,
                candidates,
                device.tls_cert_sha256
            ],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn remove(&self, public_key: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "DELETE FROM devices WHERE public_key = ?1",
            params![public_key],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn load_bindings(&self) -> Result<Vec<(String, String)>, StoreError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn
            .prepare("SELECT identity, public_key FROM identity_bindings")
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn upsert_binding(&self, identity: &str, public_key: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO identity_bindings (identity, public_key)
             VALUES (?1, ?2)
             ON CONFLICT(identity) DO UPDATE SET public_key = ?2",
            params![identity, public_key],
        )
        .map_err(backend)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(pk: &str, ip: [u8; 4], tags: &[&str]) -> Device {
        Device {
            public_key: pk.to_string(),
            name: format!("dev-{pk}"),
            endpoint: "1.2.3.4:51820".to_string(),
            tunnel_ip: Ipv4Addr::from(ip),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            candidates: Vec::new(),
            tls_cert_sha256: String::new(),
        }
    }

    #[test]
    fn upsert_then_load_roundtrips() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .upsert(&device("AAA", [10, 8, 0, 2], &["dev"]))
            .unwrap();
        store
            .upsert(&device("BBB", [10, 8, 0, 3], &["server"]))
            .unwrap();
        // Update AAA's metadata; should not duplicate.
        store
            .upsert(&device("AAA", [10, 8, 0, 2], &["dev", "admin"]))
            .unwrap();

        let mut loaded = store.load_all().unwrap();
        loaded.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].public_key, "AAA");
        assert_eq!(loaded[0].tags, vec!["dev".to_string(), "admin".to_string()]);
        assert_eq!(loaded[1].tunnel_ip, Ipv4Addr::new(10, 8, 0, 3));
    }

    #[test]
    fn candidates_roundtrip_through_the_store() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut d = device("AAA", [10, 8, 0, 2], &["dev"]);
        d.candidates = vec!["1.1.1.1:51820".into(), "203.0.113.9:7777".into()];
        store.upsert(&d).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].candidates, d.candidates);
    }

    /// SEC-004: a device's TLS cert pin survives a coordinator restart.
    #[test]
    fn tls_pin_roundtrips_through_the_store() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut d = device("AAA", [10, 8, 0, 2], &[]);
        d.tls_cert_sha256 = "ab".repeat(32);
        store.upsert(&d).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded[0].tls_cert_sha256, d.tls_cert_sha256);
    }

    #[test]
    fn remove_deletes_a_device() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.upsert(&device("AAA", [10, 8, 0, 2], &[])).unwrap();
        store.upsert(&device("BBB", [10, 8, 0, 3], &[])).unwrap();
        store.remove("AAA").unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].public_key, "BBB");
        // Removing an absent key is a no-op, not an error.
        store.remove("AAA").unwrap();
    }

    #[test]
    fn identity_bindings_roundtrip_and_upsert() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.load_bindings().unwrap(), Vec::new());

        store.upsert_binding("oidc:alice", "keyA").unwrap();
        store.upsert_binding("oidc:bob", "keyB").unwrap();
        let mut loaded = store.load_bindings().unwrap();
        loaded.sort();
        assert_eq!(
            loaded,
            vec![
                ("oidc:alice".to_string(), "keyA".to_string()),
                ("oidc:bob".to_string(), "keyB".to_string()),
            ]
        );

        // Re-binding the same identity updates in place, not duplicates.
        store.upsert_binding("oidc:alice", "keyC").unwrap();
        let loaded = store.load_bindings().unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&("oidc:alice".to_string(), "keyC".to_string())));
    }

    #[test]
    fn persists_across_reopen() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ferrum-coord-test-{}.db", std::process::id()));
        let path_str = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        {
            let store = SqliteStore::open(&path_str).unwrap();
            store
                .upsert(&device("AAA", [10, 8, 0, 2], &["dev"]))
                .unwrap();
        }
        // Reopen the same file: the device is still there.
        let store = SqliteStore::open(&path_str).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].public_key, "AAA");

        let _ = std::fs::remove_file(&path);
    }
}
