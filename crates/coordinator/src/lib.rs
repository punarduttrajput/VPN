//! Control-plane coordinator (PRD Phase 3): an in-memory device [`Registry`]
//! and the gRPC [`CoordinatorService`] over it.
//!
//! Covers device registration, tunnel-IP allocation, full-mesh network map with
//! ACL/policy filtering, live `WatchNetworkMap` streaming, SQLite persistence
//! (`sqlite`), mutual TLS (`mtls`), and OIDC bearer-token auth (`oidc`).
#![forbid(unsafe_code)]

pub mod metrics;
pub mod policy;
pub mod registry;
pub mod service;
pub mod store;
pub mod telemetry;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "mtls")]
pub mod pki;

#[cfg(feature = "oidc")]
pub mod auth;

pub use metrics::Metrics;
pub use policy::{AclRule, Policy};
pub use registry::{Device, Registry, RegistryError};
pub use service::{CoordinatorService, VerifiedClaims};
pub use store::{MemoryStore, Store, StoreError};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

#[cfg(feature = "oidc")]
pub use auth::{AuthError, Jwks, OidcVerifier};
