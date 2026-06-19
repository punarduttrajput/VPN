//! Plain UDP transport (PRD Phase 1 behavior, now behind the [`Transport`] trait).

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::{MeshTransport, Transport, TransportError};

/// Carries datagrams over UDP to a fixed peer endpoint.
pub struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl UdpTransport {
    /// Bind a local UDP socket and target `peer`.
    pub async fn bind(local: SocketAddr, peer: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(local).await?;
        Ok(Self { socket, peer })
    }

    /// Wrap an already-bound socket targeting `peer` (used by tests).
    pub fn from_socket(socket: UdpSocket, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }
}

impl Transport for UdpTransport {
    async fn send(&self, datagram: &[u8]) -> Result<(), TransportError> {
        self.socket.send_to(datagram, self.peer).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let (n, _from) = self.socket.recv_from(buf).await?;
        Ok(n)
    }
}

/// A shared UDP socket serving many mesh peers (one local endpoint, peers
/// distinguished by address). This is the natural fit for UDP: every node
/// advertises a single endpoint, so the source address of an inbound datagram
/// identifies the peer that sent it.
pub struct UdpMeshTransport {
    socket: UdpSocket,
}

impl UdpMeshTransport {
    /// Bind a local UDP socket to serve the whole mesh.
    pub async fn bind(local: SocketAddr) -> Result<Self, TransportError> {
        Ok(Self {
            socket: UdpSocket::bind(local).await?,
        })
    }

    /// Wrap an already-bound socket (used by tests and the CLI).
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self { socket }
    }
}

impl MeshTransport for UdpMeshTransport {
    async fn send_to(&self, dst: SocketAddr, datagram: &[u8]) -> Result<(), TransportError> {
        self.socket.send_to(datagram, dst).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        let (n, from) = self.socket.recv_from(buf).await?;
        Ok((n, from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_datagram_roundtrip() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();

        let ta = UdpTransport::from_socket(a, addr_b);
        let tb = UdpTransport::from_socket(b, addr_a);

        ta.send(b"hello").await.unwrap();
        let mut buf = [0u8; 32];
        let n = tb.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }
}
