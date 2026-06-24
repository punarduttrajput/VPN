//! Persistence abstraction for the device registry (PRD Phase 3, FR5).
//!
//! The registry keeps devices in memory for fast lookups but writes through to a
//! [`Store`] for durability: on startup it loads all devices, and on each
//! registration it upserts. [`MemoryStore`] is the no-op default; a SQLite
//! implementation lives behind the `sqlite` feature.

use crate::registry::Device;
use thiserror::Error;

/// Errors from a persistence backend.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The backend failed (I/O, query, serialization, …).
    #[error("store backend error: {0}")]
    Backend(String),
}

/// A durable device store. Implementations must be cheap to call per
/// registration (control-plane write rates are low).
pub trait Store: Send + Sync {
    /// Load all persisted devices (called once at startup).
    fn load_all(&self) -> Result<Vec<Device>, StoreError>;
    /// Insert or update a device by its public key.
    fn upsert(&self, device: &Device) -> Result<(), StoreError>;
    /// Remove the device with this public key, if present (used by key
    /// rotation, PRD Phase 3 FR3, to drop the record under the old key after the
    /// new one is written). Removing an absent key is not an error.
    fn remove(&self, public_key: &str) -> Result<(), StoreError>;
}

/// A no-op store: devices live only in memory (lost on restart).
#[derive(Default)]
pub struct MemoryStore;

impl Store for MemoryStore {
    fn load_all(&self) -> Result<Vec<Device>, StoreError> {
        Ok(Vec::new())
    }
    fn upsert(&self, _device: &Device) -> Result<(), StoreError> {
        Ok(())
    }
    fn remove(&self, _public_key: &str) -> Result<(), StoreError> {
        Ok(())
    }
}
