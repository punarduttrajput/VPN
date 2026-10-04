//! The Phase 1 data plane: a WireGuard session ([`session`]) bridging a TUN
//! device ([`device`]) and a UDP socket via an async event loop ([`run`]).
#![cfg_attr(not(unix), allow(dead_code))]
// SEC-016: fd passing and the fd-TUN's I/O go through `rustix`, leaving two
// `OwnedFd::from_raw_fd` conversions (in `device`), each explicitly allowed.
#![deny(unsafe_code)]

pub mod device;
pub mod ice;
pub mod ifname;
pub mod mesh;
pub mod path;
pub mod session;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod dns;
#[cfg(unix)]
pub mod fdpass;
#[cfg(target_os = "linux")]
pub mod firewall;
#[cfg(all(unix, feature = "helper-ipc"))]
pub mod helper_proto;
#[cfg(target_os = "linux")]
pub mod leakguard;

mod runner;

pub use mesh::{run_mesh, run_mesh_relayed, spoofed_source_drops, MeshPeer};
pub use path::{Path, PathMachine, PathState};
pub use runner::{run, RunHandle};

use thiserror::Error;

/// Errors from the tunnel data plane.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// A core (key/config) error.
    #[error(transparent)]
    Core(#[from] ferrum_core::Error),

    /// boringtun reported a WireGuard protocol error.
    #[error("wireguard error: {0:?}")]
    WireGuard(boringtun::noise::errors::WireGuardError),

    /// boringtun failed to construct a session.
    #[error("failed to create wireguard session: {0}")]
    Session(String),

    /// An I/O error (socket or device).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A transport (UDP/QUIC) error.
    #[error(transparent)]
    Transport(#[from] ferrum_transport::TransportError),

    /// The TUN device is not available on this platform.
    #[error("TUN device is not supported on this platform (Phase 1: Linux/macOS only)")]
    UnsupportedPlatform,
}

/// Convenience result type for the tunnel crate.
pub type Result<T> = std::result::Result<T, TunnelError>;
