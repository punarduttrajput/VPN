//! Control-plane coordinator (PRD Phase 3): an in-memory device [`Registry`]
//! and the gRPC [`CoordinatorService`] over it.
//!
//! M1 scope: device registration, tunnel-IP allocation, and a full-mesh network
//! map. Persistence, OIDC auth, mTLS, live update streams, and ACL/policy
//! filtering are later increments.
#![forbid(unsafe_code)]

pub mod registry;
pub mod service;

pub use registry::{Device, Registry, RegistryError};
pub use service::CoordinatorService;
