//! Control-plane coordinator (PRD Phase 3): an in-memory device [`Registry`]
//! and the gRPC [`CoordinatorService`] over it.
//!
//! M1 scope: device registration, tunnel-IP allocation, and a full-mesh network
//! map. Persistence, OIDC auth, mTLS, live update streams, and ACL/policy
//! filtering are later increments.
#![forbid(unsafe_code)]

pub mod policy;
pub mod registry;
pub mod service;
pub mod store;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use policy::{AclRule, Policy};
pub use registry::{Device, Registry, RegistryError};
pub use service::CoordinatorService;
pub use store::{MemoryStore, Store, StoreError};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;
