//! Shared foundation for the VPN: keys, config, protocol types and errors.
//!
//! This crate holds no `unsafe` and no platform/network I/O — it is the audited
//! core that the tunnel and CLI build on (PRD Phase 1, FR4 / NFR3).
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod keys;

pub use error::{Error, Result};
