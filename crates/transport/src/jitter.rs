//! Timing-jitter transport decorator (PRD Phase 2, FR5 — obfuscation).
//!
//! Wraps any [`Transport`] and inserts a random delay (0 … `max_ms` ms) before
//! each outgoing send so that an observer cannot fingerprint the tunnel by
//! inter-packet timing patterns. Receive is passed through unchanged — jitter
//! on the send side is sufficient and keeps latency impact bounded.
//!
//! Randomness uses a lock-free LCG seeded from system-time nanoseconds at
//! construction. This is not cryptographically secure, but timing obfuscation
//! does not require it — any unguessable-looking distribution prevents an
//! observer from correlating packets by fixed inter-arrival times.
//!
//! Both peers do *not* need to agree on jitter settings; it is applied
//! independently on each side.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::{Transport, TransportError};

/// A lock-free linear-congruential generator (Knuth MMIX constants).
struct Lcg(AtomicU64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(AtomicU64::new(seed | 1)) // odd seed keeps the LCG full-period
    }

    /// Return a random value in `0..max` (0 when `max == 0`).
    fn next_millis(&self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        let s = self.0.fetch_add(6_364_136_223_846_793_005, Ordering::Relaxed);
        s.wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407)
            % max
    }
}

fn time_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs().wrapping_mul(0x9e37_79b9_7f4a_7c15)))
        .unwrap_or(0xdead_beef_cafe_babe)
}

/// A [`Transport`] decorator that randomises outgoing packet timing (FR5).
pub struct JitteredTransport<T> {
    inner: T,
    max_ms: u64,
    rng: Lcg,
}

impl<T: Transport> JitteredTransport<T> {
    /// Wrap `inner`, delaying each send by a uniform random duration in
    /// `[0, max_ms)` milliseconds.
    pub fn new(inner: T, max_ms: u64) -> Self {
        Self {
            inner,
            max_ms,
            rng: Lcg::new(time_seed()),
        }
    }
}

impl<T: Transport> Transport for JitteredTransport<T> {
    async fn send(&self, datagram: &[u8]) -> Result<(), TransportError> {
        let delay = self.rng.next_millis(self.max_ms);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        self.inner.send(datagram).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.inner.recv(buf).await
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        self.inner.try_recv(buf)
    }

    fn send_batch<'a>(
        &'a self,
        datagrams: &'a [Vec<u8>],
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send + 'a {
        async move {
            // One random delay for the burst — still obfuscates inter-burst
            // timing without multiplying latency by batch size.
            let delay = self.rng.next_millis(self.max_ms);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            self.inner.send_batch(datagrams).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UdpTransport;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn jitter_does_not_corrupt_payload() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();

        // Use max_ms = 1 so the test does not take too long.
        let ta = JitteredTransport::new(UdpTransport::from_socket(a, addr_b), 1);
        let tb = UdpTransport::from_socket(b, addr_a);

        ta.send(b"wireguard").await.unwrap();
        let mut out = [0u8; 64];
        let n = tb.recv(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"wireguard");
    }

    #[test]
    fn lcg_stays_within_range() {
        let rng = Lcg::new(42);
        let max = 50u64;
        for _ in 0..10_000 {
            let v = rng.next_millis(max);
            assert!(v < max, "LCG output {v} exceeds max {max}");
        }
    }

    #[test]
    fn lcg_returns_zero_for_zero_max() {
        let rng = Lcg::new(1);
        assert_eq!(rng.next_millis(0), 0);
    }
}
