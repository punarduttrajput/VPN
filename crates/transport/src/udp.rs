//! Plain UDP transport (PRD Phase 1 behavior, now behind the [`Transport`] trait).
//!
//! Batch I/O (NFR1): on Linux, [`UdpTransport::send_batch`] uses **UDP
//! segmentation offload** (GSO) for each run of equal-sized datagrams, coalescing
//! the run into one buffer handed to the kernel in a single `sendmsg`, which the
//! kernel (or NIC) segments back into individual datagrams. That amortizes the
//! per-packet syscall + stack-traversal cost over the whole run, which matters
//! under load when the tunnel emits a burst of MTU-sized WireGuard packets. A
//! datagram that isn't part of a run is sent on its own.
//!
//! The receive side is symmetric: **UDP generic receive offload** (GRO) lets the
//! kernel coalesce a run of same-flow datagrams into one `recvmsg`. That one
//! syscall is split back into individual datagrams and buffered ([`GroBuffer`]),
//! which `recv`/`try_recv` then drain one at a time with no further syscalls.
//! `try_recv` exposes a non-blocking receive so the runner can drain the socket
//! between async yields.
//!
//! Both offloads go through **`quinn-udp`** (SEC-016), the widely deployed
//! socket layer under quinn, rather than hand-rolled `sendmsg`/`recvmsg`/cmsg
//! FFI: it builds properly aligned control messages, detects kernels that
//! refuse GSO and stops using it, and enables GRO itself. This module has no
//! `unsafe`. Trade-off: `quinn-udp` has no `sendmmsg(2)`, so on a kernel without
//! GSO a batch costs one `sendmsg` per datagram (previously one `sendmmsg`).
//! Every supported kernel (Linux >= 4.18) has GSO. On non-Linux platforms all of
//! this falls back to the default sequential implementations.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

#[cfg(target_os = "linux")]
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};

use crate::{MeshTransport, Transport, TransportError};

/// Maximum segments the kernel accepts in one UDP GSO send (`UDP_MAX_SEGMENTS`).
const MAX_GSO_SEGMENTS: usize = 64;
/// Maximum total bytes in one GSO send buffer (a single UDP datagram's max).
const MAX_GSO_BYTES: usize = 65_535;

/// Carries datagrams over UDP to a fixed peer endpoint.
pub struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
    /// Segments left over from a coalesced UDP GRO `recvmsg`, drained one per
    /// `recv`/`try_recv` (Linux only).
    #[cfg(target_os = "linux")]
    gro: std::sync::Mutex<GroBuffer>,
    /// `quinn-udp`'s per-socket GSO/GRO state (Linux only). `None` if it
    /// couldn't be set up, in which case plain sends/receives are used.
    #[cfg(target_os = "linux")]
    offload: Option<UdpSocketState>,
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

    /// Construct from a bound socket, setting up GSO/GRO on Linux (best-effort:
    /// `quinn-udp` enables GRO and probes GSO support itself).
    fn wrap(socket: UdpSocket, peer: SocketAddr) -> Self {
        #[cfg(target_os = "linux")]
        let offload = match UdpSocketState::new((&socket).into()) {
            Ok(state) => Some(state),
            Err(e) => {
                tracing::debug!("udp offload unavailable, using plain socket I/O: {e}");
                None
            }
        };
        Self {
            socket,
            peer,
            #[cfg(target_os = "linux")]
            gro: std::sync::Mutex::new(GroBuffer::default()),
            #[cfg(target_os = "linux")]
            offload,
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
            let Some(state) = &self.offload else {
                for d in datagrams {
                    self.send(d).await?;
                }
                return Ok(());
            };
            // Each run of equal-sized datagrams goes out as one GSO send; a
            // datagram outside any run is sent on its own.
            let mut rest = datagrams;
            while !rest.is_empty() {
                let max = state.max_gso_segments();
                let run = leading_gso_run(rest)
                    .filter(|_| max > 1)
                    .map(|(count, size)| (count.min(max), size));
                let Some((count, gso_size)) = run else {
                    self.send(&rest[0]).await?;
                    rest = &rest[1..];
                    continue;
                };
                let mut buf = Vec::with_capacity(gso_size.saturating_mul(count));
                for d in &rest[..count] {
                    buf.extend_from_slice(d);
                }
                let transmit = Transmit {
                    destination: self.peer,
                    ecn: None,
                    contents: &buf,
                    segment_size: Some(gso_size),
                    src_ip: None,
                };
                // `send` waits for writability; other errors are logged by
                // quinn-udp and treated like any lost UDP datagram.
                self.socket
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        state.send((&self.socket).into(), &transmit)
                    })
                    .await?;
                // A kernel that refuses GSO makes quinn-udp turn it off (and drop
                // that run): resend the run datagram by datagram so nothing is
                // lost, and later batches skip GSO.
                if state.max_gso_segments() < max {
                    tracing::debug!("udp gso refused by the kernel; resending the run unsegmented");
                    for d in &rest[..count] {
                        self.send(d).await?;
                    }
                }
                rest = &rest[count..];
            }
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

#[cfg(target_os = "linux")]
impl UdpTransport {
    /// GRO-aware blocking receive: drain a previously coalesced read first, else
    /// receive one (possibly coalesced) datagram, awaiting readiness, and split
    /// it into segments.
    async fn recv_gro(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        if let Some(n) = self.gro.lock().unwrap().take(buf) {
            return Ok(n);
        }
        loop {
            self.socket.readable().await.map_err(TransportError::Io)?;
            match self.try_recv_gro(buf)? {
                Some(n) => return Ok(n),
                // Spurious readiness: try_io cleared it; wait again.
                None => continue,
            }
        }
    }

    /// GRO-aware non-blocking receive (drain buffer, else one receive).
    fn try_recv_gro(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        use tokio::io::Interest;
        if let Some(n) = self.gro.lock().unwrap().take(buf) {
            return Ok(Some(n));
        }
        // A coalesced GRO read can be up to a full datagram's worth of segments,
        // so receive into a max-size scratch buffer, not the caller's `buf`.
        let mut scratch = vec![0u8; MAX_GSO_BYTES];
        let mut meta = [RecvMeta::default()];
        let received = self
            .socket
            .try_io(Interest::READABLE, || match &self.offload {
                Some(state) => {
                    let mut iov = [std::io::IoSliceMut::new(&mut scratch)];
                    state.recv((&self.socket).into(), &mut iov, &mut meta)
                }
                None => {
                    let (n, from) = self.socket.try_recv_from(&mut scratch)?;
                    meta[0].len = n;
                    meta[0].stride = n;
                    meta[0].addr = from;
                    Ok(1)
                }
            });
        match received {
            Ok(_) => {
                // `stride` is the per-segment size (== `len` when not coalesced).
                let RecvMeta { len, stride, .. } = meta[0];
                scratch.truncate(len);
                Ok(Some(self.gro.lock().unwrap().fill(scratch, stride, buf)))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(TransportError::Io(e)),
        }
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
