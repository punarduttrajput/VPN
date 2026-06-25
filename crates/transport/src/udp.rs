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
//! syscall for many datagrams), then to sequential async sends.
//!
//! The receive side is symmetric: on Linux [`UdpTransport`] enables **UDP generic
//! receive offload** (GRO, `UDP_GRO`) on its socket, so the kernel coalesces a run
//! of same-flow datagrams into one `recvmsg` (a `UDP_GRO` control message reports
//! the per-segment size). That one syscall is split back into individual datagrams
//! and buffered ([`GroBuffer`]), which `recv`/`try_recv` then drain one at a time
//! with no further syscalls — amortizing the per-packet receive cost the same way
//! GSO amortizes the send cost. `try_recv` exposes a non-blocking receive so the
//! runner can drain the socket between async yields. On non-Linux platforms all of
//! this falls back to the default sequential implementations.

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
/// The `UDP_GRO` socket option / control-message type (level `SOL_UDP`). Like
/// `UDP_SEGMENT`, defined here for libc-version portability.
#[cfg(target_os = "linux")]
const UDP_GRO: libc::c_int = 104;

/// Carries datagrams over UDP to a fixed peer endpoint.
pub struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
    /// Segments left over from a coalesced UDP GRO `recvmsg`, drained one per
    /// `recv`/`try_recv` (Linux only).
    #[cfg(target_os = "linux")]
    gro: std::sync::Mutex<GroBuffer>,
}

impl UdpTransport {
    /// Bind a local UDP socket and target `peer`.
    pub async fn bind(local: SocketAddr, peer: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(local).await?;
        Ok(Self::wrap(socket, peer))
    }

    /// Wrap an already-bound socket targeting `peer` (used by tests).
    pub fn from_socket(socket: UdpSocket, peer: SocketAddr) -> Self {
        Self::wrap(socket, peer)
    }

    /// Construct from a bound socket, enabling UDP GRO on Linux (best-effort).
    fn wrap(socket: UdpSocket, peer: SocketAddr) -> Self {
        #[cfg(target_os = "linux")]
        enable_gro(&socket);
        Self {
            socket,
            peer,
            #[cfg(target_os = "linux")]
            gro: std::sync::Mutex::new(GroBuffer::default()),
        }
    }
}

impl Transport for UdpTransport {
    async fn send(&self, datagram: &[u8]) -> Result<(), TransportError> {
        self.socket.send_to(datagram, self.peer).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        #[cfg(target_os = "linux")]
        {
            self.recv_gro(buf).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let (n, _from) = self.socket.recv_from(buf).await?;
            Ok(n)
        }
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        #[cfg(target_os = "linux")]
        {
            self.try_recv_gro(buf)
        }
        #[cfg(not(target_os = "linux"))]
        {
            match self.socket.try_recv_from(buf) {
                Ok((n, _)) => Ok(Some(n)),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(TransportError::Io(e)),
            }
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

/// Buffers the segments of one coalesced UDP GRO `recvmsg` so the single-datagram
/// `recv`/`try_recv` API can hand them out across calls without further syscalls.
///
/// A GRO read delivers a run of datagrams as one buffer plus a segment size: every
/// segment is exactly `seg_size` bytes except possibly the last (mirrors GSO on the
/// send side). This type owns that buffer and tracks how far it has been drained.
/// Pure (no I/O), so the split logic is unit-tested on every platform.
#[derive(Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct GroBuffer {
    pending: Option<Coalesced>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Coalesced {
    /// The coalesced bytes from one `recvmsg`.
    data: Vec<u8>,
    /// Per-segment size (all segments but the last are this long).
    seg_size: usize,
    /// Offset of the next undrained segment.
    offset: usize,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl GroBuffer {
    /// Copy the next buffered segment into `buf`, returning its length, or `None`
    /// if nothing is buffered (the caller must perform a `recvmsg`).
    fn take(&mut self, buf: &mut [u8]) -> Option<usize> {
        let c = self.pending.as_mut()?;
        let end = (c.offset + c.seg_size).min(c.data.len());
        let seg = &c.data[c.offset..end];
        let n = seg.len().min(buf.len());
        buf[..n].copy_from_slice(&seg[..n]);
        c.offset = end;
        if c.offset >= c.data.len() {
            self.pending = None;
        }
        Some(n)
    }

    /// Ingest a coalesced `recvmsg` result (`data`) with GRO `seg_size` (0 or
    /// `>= data.len()` means "not coalesced — a single datagram"), copy the first
    /// segment into `buf`, and buffer any remainder. Returns the first segment's
    /// length.
    fn fill(&mut self, data: Vec<u8>, seg_size: usize, buf: &mut [u8]) -> usize {
        let total = data.len();
        let seg = if seg_size == 0 || seg_size >= total {
            total
        } else {
            seg_size
        };
        // `seg.max(1)` keeps a zero-length datagram from looping; `take` then
        // returns a single 0-length segment and clears `pending`.
        self.pending = Some(Coalesced {
            data,
            seg_size: seg.max(1),
            offset: 0,
        });
        self.take(buf).unwrap_or(0)
    }
}

/// Enable UDP GRO on `socket` (Linux, best-effort). A kernel without `UDP_GRO`
/// just won't coalesce — receives still work one datagram at a time — so failure
/// is ignored.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // setsockopt FFI; see SAFETY note
fn enable_gro(socket: &UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let on: libc::c_int = 1;
    // SAFETY: `socket` owns a valid fd for the call; `&on` points to a `c_int`
    // that outlives the synchronous syscall, and the length matches its size.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_UDP,
            UDP_GRO,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(target_os = "linux")]
impl UdpTransport {
    /// GRO-aware blocking receive: drain a previously coalesced read first, else
    /// `recvmsg` (awaiting readiness) and split the result into segments.
    async fn recv_gro(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        use tokio::io::Interest;
        if let Some(n) = self.gro.lock().unwrap().take(buf) {
            return Ok(n);
        }
        // A coalesced GRO read can be up to a full datagram's worth of segments,
        // so receive into a max-size scratch buffer, not the caller's `buf`.
        let mut scratch = vec![0u8; MAX_GSO_BYTES];
        loop {
            self.socket.readable().await.map_err(TransportError::Io)?;
            match self.socket.try_io(Interest::READABLE, || {
                recvmsg_gro(&self.socket, &mut scratch)
            }) {
                Ok((total, seg)) => {
                    scratch.truncate(total);
                    return Ok(self.gro.lock().unwrap().fill(scratch, seg, buf));
                }
                // Spurious readiness: clear it (try_io did) and wait again.
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(TransportError::Io(e)),
            }
        }
    }

    /// GRO-aware non-blocking receive (drain buffer, else one `recvmsg`).
    fn try_recv_gro(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        use tokio::io::Interest;
        if let Some(n) = self.gro.lock().unwrap().take(buf) {
            return Ok(Some(n));
        }
        let mut scratch = vec![0u8; MAX_GSO_BYTES];
        match self.socket.try_io(Interest::READABLE, || {
            recvmsg_gro(&self.socket, &mut scratch)
        }) {
            Ok((total, seg)) => {
                scratch.truncate(total);
                Ok(Some(self.gro.lock().unwrap().fill(scratch, seg, buf)))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(TransportError::Io(e)),
        }
    }
}

/// One `recvmsg(2)` reading a (possibly GRO-coalesced) datagram into `scratch`,
/// returning `(bytes_received, segment_size)`. `segment_size` is the `UDP_GRO`
/// control message's value when the kernel coalesced a run, else 0 (a single
/// datagram). Returns a `WouldBlock` error when no datagram is ready, which the
/// caller's `try_io` translates into "wait for readiness".
#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // raw recvmsg(2) + cmsg FFI; see SAFETY notes below
fn recvmsg_gro(socket: &UdpSocket, scratch: &mut [u8]) -> std::io::Result<(usize, usize)> {
    use std::os::unix::io::AsRawFd;

    let mut iov = libc::iovec {
        iov_base: scratch.as_mut_ptr() as *mut libc::c_void,
        iov_len: scratch.len(),
    };
    // Control buffer for a single `UDP_GRO` (int) cmsg; 64 bytes is ample.
    let mut control = [0u8; 64];

    // SAFETY: `msg` is zeroed then populated; `msg_iov`/`msg_control` point to
    // locals that outlive the synchronous syscall, and `control` is large enough
    // for one `c_int` cmsg. The cmsg walk uses the kernel's reported lengths.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;

        let ret = libc::recvmsg(socket.as_raw_fd(), &mut msg, 0);
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Scan control messages for UDP_GRO, whose payload is the segment size
        // as a `c_int`. Absent → not coalesced (segment size 0).
        let mut seg_size = 0usize;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_UDP && (*cmsg).cmsg_type == UDP_GRO {
                let mut s: libc::c_int = 0;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    &mut s as *mut libc::c_int as *mut u8,
                    std::mem::size_of::<libc::c_int>(),
                );
                if s > 0 {
                    seg_size = s as usize;
                }
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        Ok((ret as usize, seg_size))
    }
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

    /// Drain a GRO buffer one segment at a time, just as `recv` would.
    fn drain_all(g: &mut GroBuffer) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        while let Some(n) = g.take(&mut buf) {
            out.push(buf[..n].to_vec());
        }
        out
    }

    #[test]
    fn gro_buffer_splits_a_coalesced_read() {
        // 2500 bytes coalesced at seg_size 1200 → 1200, 1200, 100.
        let mut data = vec![0u8; 2500];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut g = GroBuffer::default();
        let mut first = [0u8; 2048];
        let n0 = g.fill(data.clone(), 1200, &mut first);
        assert_eq!(n0, 1200);
        assert_eq!(&first[..1200], &data[..1200]);
        // Remaining two segments come from the buffer with no further `fill`.
        let rest = drain_all(&mut g);
        assert_eq!(rest.len(), 2);
        assert_eq!(rest[0], data[1200..2400]);
        assert_eq!(rest[1], data[2400..2500]);
        // Fully drained.
        assert_eq!(g.take(&mut first), None);
    }

    #[test]
    fn gro_buffer_treats_zero_segsize_as_single_datagram() {
        // seg_size 0 (no UDP_GRO cmsg) → exactly one segment of the whole read.
        let mut g = GroBuffer::default();
        let mut buf = [0u8; 2048];
        let n = g.fill(vec![7u8; 900], 0, &mut buf);
        assert_eq!(n, 900);
        assert_eq!(g.take(&mut buf), None);
    }

    #[test]
    fn gro_buffer_handles_segsize_at_or_above_total() {
        // seg_size >= total is also a single datagram (not coalesced).
        let mut g = GroBuffer::default();
        let mut buf = [0u8; 2048];
        assert_eq!(g.fill(vec![1u8; 500], 500, &mut buf), 500);
        assert_eq!(g.take(&mut buf), None);
        assert_eq!(g.fill(vec![1u8; 500], 9000, &mut buf), 500);
        assert_eq!(g.take(&mut buf), None);
    }

    #[test]
    fn gro_buffer_empty_take_is_none() {
        let mut g = GroBuffer::default();
        let mut buf = [0u8; 16];
        assert_eq!(g.take(&mut buf), None);
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

    /// On Linux, a GRO-enabled `UdpTransport` receives a GSO-sent batch correctly
    /// whether or not the kernel coalesced the datagrams — the GRO-aware `recv`
    /// drains a coalesced read segment-by-segment, and falls back to one datagram
    /// per `recvmsg` otherwise. Asserts reassembly, not that coalescing occurred.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gro_recv_reassembles_a_gso_batch() {
        use std::time::Duration;

        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();
        let ta = UdpTransport::from_socket(a, addr_b);
        let tb = UdpTransport::from_socket(b, addr_a); // GRO enabled in `from_socket`

        // Three equal segments + one smaller tail → a GSO run of 4 datagrams.
        let seg = vec![0x5au8; 1200];
        let tail = vec![0x5au8; 400];
        let batch = vec![seg.clone(), seg.clone(), seg.clone(), tail.clone()];
        ta.send_batch(&batch).await.unwrap();

        // The GRO-aware recv yields the 4 original datagrams (coalesced or not).
        let mut sizes = Vec::new();
        let mut buf = vec![0u8; 2048];
        for _ in 0..4 {
            let n = tokio::time::timeout(Duration::from_secs(2), tb.recv(&mut buf))
                .await
                .expect("expected a datagram")
                .unwrap();
            assert!(buf[..n].iter().all(|&x| x == 0x5a), "payload corrupted");
            sizes.push(n);
        }
        sizes.sort_unstable();
        assert_eq!(sizes, vec![400, 1200, 1200, 1200]);
    }
}
