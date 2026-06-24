//! Plain UDP transport (PRD Phase 1 behavior, now behind the [`Transport`] trait).
//!
//! Batch I/O (NFR1): on Linux, [`UdpTransport::send_batch`] first tries **UDP
//! segmentation offload** (GSO, `UDP_SEGMENT`) for a leading run of equal-sized
//! datagrams — coalescing them into one buffer handed to the kernel in a single
//! `sendmsg`, which the kernel (or NIC) segments back into individual datagrams.
//! That amortizes the per-packet syscall + stack-traversal cost over the whole
//! run, which matters under load when the tunnel emits a burst of MTU-sized
//! WireGuard packets. Anything not GSO-eligible (mixed sizes, a full send buffer,
//! or a kernel without `UDP_SEGMENT`) falls back to `sendmmsg(2)` (still one
//! syscall for many datagrams), then to sequential async sends. `try_recv`
//! exposes a non-blocking receive so the runner can drain the socket between
//! async yields. On non-Linux platforms all of this falls back to the default
//! sequential implementations.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::{MeshTransport, Transport, TransportError};

/// Maximum segments the kernel accepts in one UDP GSO send (`UDP_MAX_SEGMENTS`).
const MAX_GSO_SEGMENTS: usize = 64;
/// Maximum total bytes in one GSO send buffer (a single UDP datagram's max).
const MAX_GSO_BYTES: usize = 65_535;
/// The `UDP_SEGMENT` control-message type (level `SOL_UDP`). Defined here because
/// older `libc` versions don't expose it as a constant.
#[cfg(target_os = "linux")]
const UDP_SEGMENT: libc::c_int = 103;

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
            // First, try UDP GSO on a leading run of equal-sized datagrams: one
            // `sendmsg` hands the whole run to the kernel, which segments it into
            // individual datagrams. Whatever GSO doesn't cover (mixed sizes, a
            // GSO failure, or EAGAIN) is handed to `sendmmsg`, then to async sends.
            let mut sent = 0;
            if let Some((count, gso_size)) = leading_gso_run(datagrams) {
                let mut buf = Vec::with_capacity(gso_size.saturating_mul(count));
                for d in &datagrams[..count] {
                    buf.extend_from_slice(d);
                }
                match sendmsg_gso(&self.socket, self.peer, &buf, gso_size as u16) {
                    Ok(()) => sent = count,
                    // Any GSO failure (including a kernel without `UDP_SEGMENT`) is
                    // non-fatal — fall through and let `sendmmsg` send the batch.
                    Err(e) => tracing::debug!("udp gso send failed, using sendmmsg: {e}"),
                }
            }
            let remaining = &datagrams[sent..];
            if !remaining.is_empty() {
                let m = sendmmsg_once(&self.socket, self.peer, remaining)
                    .map_err(TransportError::Io)?;
                // Sequential async sends for anything still unsent (partial send
                // or EAGAIN on the first attempt) — this also applies backpressure.
                for d in &remaining[m..] {
                    self.send(d).await?;
                }
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

/// The longest leading run of `datagrams` that can be sent as one UDP GSO buffer,
/// returned as `(count, gso_size)`, or `None` if the front isn't GSO-eligible.
///
/// GSO requires every segment to be exactly `gso_size` except the last, which may
/// be smaller. So the run is: a prefix of equal-sized (`L`) datagrams, optionally
/// followed by one smaller datagram as the final segment — capped at
/// [`MAX_GSO_SEGMENTS`] and [`MAX_GSO_BYTES`]. Only returned when it covers at
/// least 2 datagrams (a single datagram gains nothing from GSO). Pure (no I/O) so
/// the grouping logic is unit-tested on every platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn leading_gso_run(datagrams: &[Vec<u8>]) -> Option<(usize, usize)> {
    if datagrams.len() < 2 {
        return None;
    }
    let l = datagrams[0].len();
    if l == 0 || l > MAX_GSO_BYTES {
        return None;
    }
    let mut count = 1;
    let mut bytes = l;
    // Extend over equal-sized datagrams, within the segment/byte caps.
    while count < datagrams.len()
        && datagrams[count].len() == l
        && count < MAX_GSO_SEGMENTS
        && bytes + l <= MAX_GSO_BYTES
    {
        bytes += l;
        count += 1;
    }
    // Optionally take one smaller datagram as the final (short) segment.
    if count < datagrams.len()
        && count < MAX_GSO_SEGMENTS
        && (1..l).contains(&datagrams[count].len())
        && bytes + datagrams[count].len() <= MAX_GSO_BYTES
    {
        count += 1;
    }
    (count >= 2).then_some((count, l))
}

/// Send one UDP GSO datagram-run (Linux only): `buf` is the concatenation of the
/// run's segments, each `gso_size` bytes (the last may be smaller). A
/// `UDP_SEGMENT` control message tells the kernel to segment `buf` back into
/// individual datagrams to `peer`. Errors (including a kernel without
/// `UDP_SEGMENT`) are returned for the caller to fall back on.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // raw sendmsg(2) + cmsg FFI; see SAFETY notes below
fn sendmsg_gso(
    socket: &UdpSocket,
    peer: SocketAddr,
    buf: &[u8],
    gso_size: u16,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let (peer_storage, peer_len) = sockaddr_of(peer);
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    const SEG_SZ: u32 = std::mem::size_of::<u16>() as u32;
    // Control buffer for a single `UDP_SEGMENT` cmsg; 64 bytes comfortably
    // exceeds `CMSG_SPACE(2)`.
    let mut control = [0u8; 64];

    // SAFETY: `msg` is zeroed then fully populated; `msg_name`/`msg_iov`/
    // `msg_control` point to locals that outlive the synchronous syscall, and
    // `control` is large enough for one `u16` cmsg.
    let ret = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &peer_storage as *const _ as *mut libc::c_void;
        msg.msg_namelen = peer_len;
        msg.msg_iov = &mut iov as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(SEG_SZ) as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("no control-message space"));
        }
        // cmsg level for UDP options is SOL_UDP (17); use IPPROTO_UDP, which has
        // the same value and is always present in `libc`.
        (*cmsg).cmsg_level = libc::IPPROTO_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(SEG_SZ) as _;
        std::ptr::copy_nonoverlapping(
            &gso_size as *const u16 as *const u8,
            libc::CMSG_DATA(cmsg),
            SEG_SZ as usize,
        );

        libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL)
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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

    fn dgrams(sizes: &[usize]) -> Vec<Vec<u8>> {
        sizes.iter().map(|&n| vec![0u8; n]).collect()
    }

    #[test]
    fn gso_run_groups_a_uniform_batch() {
        // All equal → one run covering the whole batch, gso_size = element size.
        assert_eq!(leading_gso_run(&dgrams(&[1200; 4])), Some((4, 1200)));
    }

    #[test]
    fn gso_run_allows_a_smaller_final_segment() {
        // Equal-sized prefix + one smaller tail is a valid GSO run.
        assert_eq!(
            leading_gso_run(&dgrams(&[1200, 1200, 500])),
            Some((3, 1200))
        );
    }

    #[test]
    fn gso_run_stops_at_a_larger_or_mismatched_datagram() {
        // A larger datagram after the first ends the run; the leading two match.
        assert_eq!(
            leading_gso_run(&dgrams(&[1200, 1200, 1400])),
            Some((2, 1200))
        );
        // A bigger second datagram → no eligible run of >= 2.
        assert_eq!(leading_gso_run(&dgrams(&[1200, 1400])), None);
        // A smaller second datagram is taken as the tail (run of 2).
        assert_eq!(leading_gso_run(&dgrams(&[1200, 800])), Some((2, 1200)));
    }

    #[test]
    fn gso_run_declines_trivial_or_oversized_inputs() {
        assert_eq!(leading_gso_run(&dgrams(&[])), None);
        assert_eq!(leading_gso_run(&dgrams(&[1200])), None); // single
        assert_eq!(leading_gso_run(&dgrams(&[0, 0])), None); // zero-length
    }

    #[test]
    fn gso_run_respects_the_segment_cap() {
        // More equal segments than the cap → run is capped at MAX_GSO_SEGMENTS.
        let many = dgrams(&[100; MAX_GSO_SEGMENTS + 10]);
        assert_eq!(leading_gso_run(&many), Some((MAX_GSO_SEGMENTS, 100)));
    }

    /// On Linux, a uniform `send_batch` goes out as one GSO `sendmsg` and the
    /// kernel segments it back into individual datagrams the peer receives whole.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gso_send_batch_delivers_individual_datagrams() {
        use std::time::Duration;

        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_b = b.local_addr().unwrap();
        let ta = UdpTransport::from_socket(a, addr_b);

        // Four equal segments + one smaller tail → a single GSO run of 5.
        let seg = vec![0x5au8; 1200];
        let tail = vec![0x5au8; 400];
        let batch = vec![
            seg.clone(),
            seg.clone(),
            seg.clone(),
            seg.clone(),
            tail.clone(),
        ];
        ta.send_batch(&batch).await.unwrap();

        // The kernel segments the GSO buffer into 5 separate datagrams.
        let mut sizes = Vec::new();
        let mut buf = [0u8; 2048];
        for _ in 0..5 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
                .await
                .expect("expected a segmented datagram")
                .unwrap();
            assert!(buf[..n].iter().all(|&x| x == 0x5a), "payload corrupted");
            sizes.push(n);
        }
        sizes.sort_unstable();
        assert_eq!(sizes, vec![400, 1200, 1200, 1200, 1200]);
    }
}
