//! Pluggable transport layer for the VPN data plane (PRD Phase 2, FR1).
//!
//! The tunnel event loop moves opaque, already-encrypted datagrams; *how* those
//! datagrams cross the network is abstracted behind [`Transport`]. Phase 1's
//! plain UDP becomes one implementation ([`UdpTransport`]); QUIC ([`quic`]) adds
//! roaming and DPI-evasion. MASQUE/HTTP3, connection migration, and padding are
//! later Phase 2 increments.
#![forbid(unsafe_code)]

use thiserror::Error;

pub mod udp;
pub use udp::UdpTransport;

#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub use quic::QuicTransport;

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
