//! Control-plane coordinator (PRD Phase 3): an in-memory device [`Registry`]
//! and the gRPC [`CoordinatorService`] over it.
//!
//! Covers device registration, tunnel-IP allocation, full-mesh network map with
//! ACL/policy filtering, live `WatchNetworkMap` streaming, SQLite persistence
//! (`sqlite`), mutual TLS (`mtls`), OIDC bearer-token auth (`oidc`), and an
//! admin HTTP API + panel for device/ACL management (`admin-api`).
#![forbid(unsafe_code)]

pub mod limits;
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

#[cfg(feature = "admin-api")]
pub mod admin;

pub use limits::{LimitsConfig, RateSpec};
pub use metrics::Metrics;
pub use policy::{AclRule, Policy};
pub use registry::{Device, Registry, RegistryError};
pub use service::{CoordinatorService, VerifiedClaims};
pub use store::{MemoryStore, Store, StoreError};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

#[cfg(feature = "oidc")]
pub use auth::{AuthError, Jwks, OidcVerifier};

/// The coordinator's authentication posture, decided once at startup
/// (PRD security-hardening.md SEC-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// An OIDC verifier is configured; every RPC requires a valid bearer
    /// token and ACL tags come only from its verified claims.
    Authenticated,
    /// The operator explicitly opted out of authentication
    /// (`--insecure-no-auth`); any client may join and self-declare tags.
    InsecureNoAuth,
}

/// Decide the coordinator's [`AuthMode`] from CLI-style inputs, failing
/// closed by default (PRD security-hardening.md SEC-001 / FR1): an operator
/// must either configure OIDC or explicitly opt out with
/// `--insecure-no-auth`. Passing both is rejected as a likely
/// misconfiguration rather than silently preferring one. Pure and
/// feature-independent so a non-`oidc` build enforces the same fail-closed
/// default (pass `oidc_configured = false`).
pub fn resolve_auth_mode(
    oidc_configured: bool,
    insecure_no_auth: bool,
) -> Result<AuthMode, String> {
    match (oidc_configured, insecure_no_auth) {
        (true, true) => Err(
            "--insecure-no-auth cannot be combined with --oidc-issuer/--oidc-audience/--oidc-jwks"
                .into(),
        ),
        (true, false) => Ok(AuthMode::Authenticated),
        (false, true) => Ok(AuthMode::InsecureNoAuth),
        (false, false) => Err(
            "authentication is required by default: configure --oidc-issuer, --oidc-audience, \
             and --oidc-jwks, or pass --insecure-no-auth to run without authentication \
             (any client can then join and self-assign ACL tags — not recommended)"
                .into(),
        ),
    }
}

#[cfg(test)]
mod auth_mode_tests {
    use super::*;

    #[test]
    fn fails_closed_with_neither_oidc_nor_opt_out() {
        assert!(resolve_auth_mode(false, false).is_err());
    }

    #[test]
    fn oidc_alone_is_authenticated() {
        assert_eq!(resolve_auth_mode(true, false), Ok(AuthMode::Authenticated));
    }

    #[test]
    fn opt_out_alone_is_insecure_no_auth() {
        assert_eq!(resolve_auth_mode(false, true), Ok(AuthMode::InsecureNoAuth));
    }

    #[test]
    fn both_at_once_is_rejected() {
        assert!(resolve_auth_mode(true, true).is_err());
    }
}
