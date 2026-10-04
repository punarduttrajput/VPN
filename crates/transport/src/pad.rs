//! Packet-padding transport decorator (PRD Phase 2, FR5 — obfuscation).
//!
//! Wraps any [`Transport`] and pads every outgoing datagram up to a target size
//! so that the encrypted WireGuard packets — whose lengths otherwise leak
//! information (handshake vs keepalive vs data) — present a uniform size on the
//! wire, blunting size-based traffic fingerprinting.
//!
//! Wire framing (little-endian): `[u16 real_len][payload][zero padding…]`.
//! Both peers must agree on padding (and it composes under, not over, the inner
//! transport): the receiver strips the frame before the bytes reach WireGuard.
//!
//! Trade-off: padding adds bytes on the wire and a per-`recv` buffer allocation;
//! it is opt-in and meant for hostile networks, not maximum throughput.

use crate::{Transport, TransportError};

/// Max datagram we will buffer when receiving a padded frame.
const MAX_FRAMED: usize = 65_535 + 64;

/// Frame `payload` with a length prefix, padded with zeros up to `pad_to` bytes.
/// Packets already larger than `pad_to` are sent at their natural size (+2).
fn frame(payload: &[u8], pad_to: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(pad_to.max(payload.len() + 2));
    buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    buf.extend_from_slice(payload);
    if buf.len() < pad_to {
        buf.resize(pad_to, 0);
    }
    buf
}

/// Recover the original payload slice from a padded frame.
pub(crate) fn deframe(buf: &[u8]) -> Result<&[u8], TransportError> {
    if buf.len() < 2 {
        return Err(TransportError::Connection("padded frame too short".into()));
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if 2 + len > buf.len() {
        return Err(TransportError::Connection(
            "padded frame length exceeds datagram".into(),
        ));
    }
    Ok(&buf[2..2 + len])
}

/// A [`Transport`] decorator that pads outgoing datagrams to a uniform size.
pub struct PaddedTransport<T> {
    inner: T,
    pad_to: usize,
}

impl<T: Transport> PaddedTransport<T> {
    /// Wrap `inner`, padding each datagram up to `pad_to` bytes (a minimum).
    pub fn new(inner: T, pad_to: usize) -> Self {
        Self { inner, pad_to }
    }
}

impl<T: Transport> Transport for PaddedTransport<T> {
    async fn send(&self, datagram: &[u8]) -> Result<(), TransportError> {
        if datagram.len() > u16::MAX as usize {
            return Err(TransportError::Connection(
                "datagram too large to pad-frame".into(),
            ));
        }
        let framed = frame(datagram, self.pad_to);
        self.inner.send(&framed).await
    }

    async fn recv(&self, out: &mut [u8]) -> Result<usize, TransportError> {
        let mut buf = vec![0u8; MAX_FRAMED];
        let n = self.inner.recv(&mut buf).await?;
        let payload = deframe(&buf[..n])?;
        let m = payload.len().min(out.len());
        out[..m].copy_from_slice(&payload[..m]);
        Ok(m)
    }

    fn try_recv(&self, out: &mut [u8]) -> Result<Option<usize>, TransportError> {
        let mut buf = vec![0u8; MAX_FRAMED];
        match self.inner.try_recv(&mut buf)? {
            None => Ok(None),
            Some(n) => {
                let payload = deframe(&buf[..n])?;
                let m = payload.len().min(out.len());
                out[..m].copy_from_slice(&payload[..m]);
                Ok(Some(m))
            }
        }
    }

    async fn send_batch(&self, datagrams: &[Vec<u8>]) -> Result<(), TransportError> {
        let framed: Vec<Vec<u8>> = datagrams.iter().map(|d| frame(d, self.pad_to)).collect();
        self.inner.send_batch(&framed).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UdpTransport;
    use tokio::net::UdpSocket;

    #[test]
    fn frames_pad_small_payloads_to_target() {
        let framed = frame(b"hi", 64);
        assert_eq!(framed.len(), 64, "small payload padded up to pad_to");
        assert_eq!(deframe(&framed).unwrap(), b"hi");
    }

    #[test]
    fn large_payloads_pass_through_unpadded() {
        let payload = vec![7u8; 200];
        let framed = frame(&payload, 64);
        assert_eq!(framed.len(), 202, "len prefix + payload, no padding");
        assert_eq!(deframe(&framed).unwrap(), &payload[..]);
    }

    #[test]
    fn deframe_rejects_corrupt_frames() {
        assert!(deframe(&[0]).is_err()); // too short for length prefix
        assert!(deframe(&[10, 0, 1, 2]).is_err()); // claims 10 bytes, has 2
    }

    #[tokio::test]
    async fn padded_transport_roundtrip_over_udp() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();

        let ta = PaddedTransport::new(UdpTransport::from_socket(a, addr_b), 256);
        let tb = PaddedTransport::new(UdpTransport::from_socket(b, addr_a), 256);

        // A small payload survives padding + stripping intact.
        ta.send(b"wireguard").await.unwrap();
        let mut out = [0u8; 64];
        let n = tb.recv(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"wireguard");
    }
}
