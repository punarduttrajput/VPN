//! Pluggable transport layer for the VPN data plane (PRD Phase 2, FR1).
//!
//! The tunnel event loop moves opaque, already-encrypted datagrams; *how* those
//! datagrams cross the network is abstracted behind [`Transport`] (point-to-point)
//! and [`MeshTransport`] (multi-peer, for Phase 3/4's mesh data plane). Phase 1's
//! plain UDP becomes one implementation ([`UdpTransport`] / [`UdpMeshTransport`]);
//! QUIC ([`quic`]) adds roaming and DPI-evasion. MASQUE/HTTP3, connection
//! migration, and padding are later Phase 2 increments.
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use thiserror::Error;

pub mod pad;
pub use pad::PaddedTransport;

pub mod udp;
pub use udp::{UdpMeshTransport, UdpTransport};

#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub use quic::QuicTransport;

#[cfg(feature = "masque")]
pub mod masque;
#[cfg(feature = "masque")]
pub use masque::{MasqueProxy, MasqueTransport};

/// Errors produced by a transport.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Underlying socket / I/O error.
    #[error("transport io error: {0}")]
    Io(#[from] std::io::Error),

    /// The transport connection failed or was lost.
    #[error("transport connection error: {0}")]
    Connection(String),

    /// Setup (binding, TLS, certificate) failed.
    #[error("transport setup error: {0}")]
    Setup(String),
}

/// A bidirectional datagram channel to a single peer.
///
/// Methods take `&self` so the event loop can `send` and `recv` concurrently
/// without splitting the value (UDP sockets and QUIC connections both allow it),
/// and return `Send` futures so they can be driven from spawned tasks.
pub trait Transport: Send + Sync {
    /// Send one datagram to the peer.
    fn send(
        &self,
        datagram: &[u8],
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Receive one datagram from the peer into `buf`, returning its length.
    fn recv(
        &self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, TransportError>> + Send;
}

/// A multi-peer datagram fabric for the mesh data plane (PRD Phase 3/4).
///
/// Unlike [`Transport`] (a single peer), a `MeshTransport` carries datagrams to
/// and from *many* peers over one local resource (a shared UDP socket, or a QUIC
/// endpoint multiplexing several connections). Peers are addressed by their
/// reachable [`SocketAddr`]; `recv_from` reports which peer a datagram came from
/// so the mesh runner can route it to that peer's crypto session.
///
/// Methods take `&self` so the mesh loop can send and receive concurrently, and
/// return `Send` futures so they can be driven from spawned tasks.
pub trait MeshTransport: Send + Sync {
    /// Send one datagram to the peer reachable at `dst`.
    fn send_to(
        &self,
        dst: SocketAddr,
        datagram: &[u8],
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Receive one datagram into `buf`, returning its length and the address of
    /// the peer it came from.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = Result<(usize, SocketAddr), TransportError>> + Send;
}
