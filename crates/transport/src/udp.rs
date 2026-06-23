//! Plain UDP transport (PRD Phase 1 behavior, now behind the [`Transport`] trait).
//!
//! Batch I/O (NFR1): on Linux, [`UdpTransport::send_batch`] uses `sendmmsg(2)`
//! to hand multiple datagrams to the kernel in a single syscall, cutting
//! per-packet overhead roughly proportional to batch size. `try_recv` exposes
//! a non-blocking receive so the tunnel runner can drain the socket between
//! async yields. On non-Linux platforms both fall back to the default
//! sequential implementations.

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

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        match self.socket.try_recv_from(buf) {
            Ok((n, _)) => Ok(Some(n)),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(TransportError::Io(e)),
        }
    }

    async fn send_batch(&self, datagrams: &[Vec<u8>]) -> Result<(), TransportError> {
        if datagrams.is_empty() {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            let sent =
                sendmmsg_once(&self.socket, self.peer, datagrams).map_err(TransportError::Io)?;
            // Fall back to sequential async sends for anything not sent
            // (e.g. partial send or EAGAIN on first attempt).
            for d in &datagrams[sent..] {
                self.send(d).await?;
            }
            // Tail expression: on Linux this block is the function's tail (the
            // non-Linux block is `cfg`-stripped), so no `return` is needed.
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            for d in datagrams {
                self.send(d).await?;
            }
            Ok(())
        }
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

/// One-shot `sendmmsg(2)` call (Linux only). Returns the number of datagrams
/// actually sent. Does not block: on `EAGAIN`/`EWOULDBLOCK` returns `Ok(0)`.
/// The caller is responsible for sending remaining datagrams.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // raw sendmmsg(2) FFI; see SAFETY notes below
fn sendmmsg_once(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagrams: &[Vec<u8>],
) -> std::io::Result<usize> {
    use std::os::unix::io::AsRawFd;

    // Build the destination sockaddr once; all messages go to the same peer.
    let (peer_storage, peer_len) = sockaddr_of(peer);

    // iovecs and msghdrs must outlive the sendmmsg call.
    // SAFETY: datagrams are heap-allocated Vec<u8>; their data pointers remain
    // valid for the synchronous duration of the sendmmsg syscall.
    let mut iovecs: Vec<libc::iovec> = datagrams
        .iter()
        .map(|d| libc::iovec {
            iov_base: d.as_ptr() as *mut libc::c_void,
            iov_len: d.len(),
        })
        .collect();

    let mut hdrs: Vec<libc::mmsghdr> = iovecs
        .iter_mut()
        .map(|iov| libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: &peer_storage as *const _ as *mut libc::c_void,
                msg_namelen: peer_len,
                msg_iov: iov as *mut _,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        })
        .collect();

    let ret = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            hdrs.as_mut_ptr(),
            hdrs.len() as libc::c_uint,
            libc::MSG_NOSIGNAL,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Ok(0);
        }
        return Err(err);
    }
    Ok(ret as usize)
}

/// Convert a [`SocketAddr`] to a `sockaddr_storage` + length pair.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // sockaddr_storage transmute for the syscall; see SAFETY notes
fn sockaddr_of(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: zeroing a sockaddr_storage is always valid.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in = unsafe { &mut *(&mut storage as *mut _ as *mut _) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 = unsafe { &mut *(&mut storage as *mut _ as *mut _) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_scope_id = v6.scope_id();
            sin6.sin6_flowinfo = v6.flowinfo();
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
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
