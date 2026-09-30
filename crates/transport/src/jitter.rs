//! Timing-jitter transport decorator (PRD Phase 2, FR5 — obfuscation).
//!
//! Wraps any [`Transport`] and inserts a random delay (0 … `max_ms` ms) before
//! each outgoing send so that an observer cannot fingerprint the tunnel by
//! inter-packet timing patterns. Receive is passed through unchanged — jitter
//! on the send side is sufficient and keeps latency impact bounded.
//!
//! Each delay is drawn from the OS CSPRNG (SEC-018). It used to come from an
//! LCG seeded with the clock, so an observer who could guess the seed could
//! predict every delay and subtract the jitter back out. The per-draw syscall
//! is negligible next to the sleep it decides.
//!
//! Both peers do *not* need to agree on jitter settings; it is applied
//! independently on each side.

use std::time::Duration;

use crate::{Transport, TransportError};

/// A uniformly random delay in `0..max` milliseconds (0 when `max == 0`),
/// from the OS CSPRNG. Rejection sampling avoids modulo bias. If the RNG is
/// unavailable, no delay (the packet still goes out; only the jitter is lost).
fn random_millis(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    // The largest multiple of `max` that fits, so `v % max` is uniform below it.
    let zone = u64::MAX - (u64::MAX % max);
    loop {
        let mut bytes = [0u8; 8];
        if getrandom::getrandom(&mut bytes).is_err() {
            return 0;
        }
        let v = u64::from_le_bytes(bytes);
        if v < zone {
            return v % max;
        }
    }
}

/// A [`Transport`] decorator that randomises outgoing packet timing (FR5).
pub struct JitteredTransport<T> {
    inner: T,
    max_ms: u64,
}

impl<T: Transport> JitteredTransport<T> {
    /// Wrap `inner`, delaying each send by a uniform random duration in
    /// `[0, max_ms)` milliseconds.
    pub fn new(inner: T, max_ms: u64) -> Self {
        Self { inner, max_ms }
    }
}

impl<T: Transport> Transport for JitteredTransport<T> {
    async fn send(&self, datagram: &[u8]) -> Result<(), TransportError> {
        let delay = random_millis(self.max_ms);
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

    async fn send_batch(&self, datagrams: &[Vec<u8>]) -> Result<(), TransportError> {
        // One random delay for the burst — still obfuscates inter-burst
        // timing without multiplying latency by batch size.
        let delay = random_millis(self.max_ms);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        self.inner.send_batch(datagrams).await
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
    fn delays_stay_in_range_and_vary() {
        let max = 50u64;
        let draws: Vec<u64> = (0..2_000).map(|_| random_millis(max)).collect();
        assert!(draws.iter().all(|&v| v < max), "a delay exceeded max");
        // Not a statistical test, just a guard against a constant generator.
        let distinct: std::collections::HashSet<_> = draws.iter().collect();
        assert!(
            distinct.len() > 25,
            "only {} distinct delays",
            distinct.len()
        );
    }

    #[test]
    fn zero_max_means_no_delay() {
        assert_eq!(random_millis(0), 0);
        assert_eq!(random_millis(1), 0);
    }
}
