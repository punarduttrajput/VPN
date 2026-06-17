//! Plain UDP transport (PRD Phase 1 behavior, now behind the [`Transport`] trait).

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::{Transport, TransportError};

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
