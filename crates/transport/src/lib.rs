//! Pluggable transport layer for the VPN data plane (PRD Phase 2, FR1).
//!
//! The tunnel event loop moves opaque, already-encrypted datagrams; *how* those
//! datagrams cross the network is abstracted behind [`Transport`] (point-to-point)
//! and [`MeshTransport`] (multi-peer, for Phase 3/4's mesh data plane). Phase 1's
//! plain UDP becomes one implementation ([`UdpTransport`] / [`UdpMeshTransport`]);
//! QUIC ([`quic`]) adds roaming and DPI-evasion. MASQUE/HTTP3, connection
//! migration, and padding are later Phase 2 increments.
//!
//! `unsafe` is denied crate-wide; the only exceptions are the two Linux-only
//! `sendmmsg(2)` FFI helpers in [`udp`], each annotated `#[allow(unsafe_code)]`
//! with a `// SAFETY:` justification. (`deny`, not `forbid`, so those localized
//! allows are permitted; everything else still fails to compile on `unsafe`.)
#![deny(unsafe_code)]

use std::net::SocketAddr;

use thiserror::Error;

pub mod jitter;
pub use jitter::JitteredTransport;

pub mod pad;
pub use pad::PaddedTransport;

pub mod udp;
pub use udp::{UdpMeshTransport, UdpTransport};

pub mod stun;

pub mod relay;
pub use relay::{RelayMeshTransport, RelayMetrics, RelayServer, RelayXdpHook};

// The relay's eBPF/XDP fast path (PRD `phase-6-ebpf-xdp-relay.md`) — Linux
// and `xdp`-feature gated; `aya` is a `[target.'cfg(target_os =
// "linux")'.dependencies]` dependency (see that Cargo.toml section), so
// this is a no-op on every other host, including the one it was authored
// on. See `crates/transport/src/relay_xdp.rs`'s module doc.
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub mod relay_xdp;
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub use relay_xdp::{RelayXdpError, RelayXdpLoader};

pub mod fingerprint;
pub use fingerprint::Fingerprint;

#[cfg(feature = "quic")]
pub mod tls;
#[cfg(feature = "quic")]
pub use tls::TlsIdentity;

#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub use quic::QuicTransport;

#[cfg(feature = "quic")]
pub mod quic_mesh;
#[cfg(feature = "quic")]
pub use quic_mesh::QuicMeshTransport;

#[cfg(feature = "masque")]
pub mod masque;
#[cfg(feature = "masque")]
pub use masque::{MasqueMeshTransport, MasqueProxy, MasqueTransport};

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

/// Maximum datagrams in one `send_batch` call (caps allocation in hot path).
pub const BATCH_SIZE: usize = 64;

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

    /// Non-blocking receive attempt. Returns `Some(n)` if a datagram was
    /// immediately available, `None` if the socket would block (EWOULDBLOCK).
    /// Transports that do not support non-blocking receive always return `None`.
    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        let _ = buf;
        Ok(None)
    }

    /// Send a batch of datagrams in one call. Implementors may override with
    /// an efficient multi-message syscall (e.g. `sendmmsg` on Linux).
    /// Default: sends each datagram sequentially.
    fn send_batch<'a>(
        &'a self,
        datagrams: &'a [Vec<u8>],
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send + 'a {
        async move {
            for d in datagrams {
                self.send(d).await?;
            }
            Ok(())
        }
    }
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

    /// Tell the transport which TLS certificate pins to expect when it dials
    /// each peer address (SEC-004), replacing any previous set. The mesh runner
    /// calls this whenever the peer set changes. Only transports whose peers are
    /// TLS servers (`QuicMeshTransport`) act on it; the default ignores it.
    fn set_peer_pins(&self, pins: &[(SocketAddr, Vec<Fingerprint>)]) {
        let _ = pins;
    }

    /// The pin of the TLS identity peers must expect when they dial *this*
    /// node over this transport (SEC-004), or `None` when peers don't dial it
    /// as a TLS server (UDP, relay, MASQUE). Registration publishes exactly
    /// this, so the advertised pin always matches the key actually in use.
    fn tls_fingerprint(&self) -> Option<Fingerprint> {
        None
    }
}
