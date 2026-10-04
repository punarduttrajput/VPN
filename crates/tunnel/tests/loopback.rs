//! End-to-end loopback test (PRD M5): two full tunnel runners on localhost UDP
//! sockets, each with a mock TUN device. A packet injected into peer A's TUN
//! must arrive, decrypted and intact, at peer B's TUN — proving the complete
//! handshake + encapsulate + transport + decapsulate path without needing a
//! real OS interface (which Phase 1 scopes to Linux/macOS only).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum_core::config::Cidr;
use ferrum_core::keys::KeyPair;
use ferrum_transport::UdpTransport;
use ferrum_tunnel::device::mock::MockTun;
use ferrum_tunnel::session::Session;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// A running A↔B tunnel pair: inject at A's TUN, observe B's.
struct Pair {
    inject_a: Arc<Mutex<VecDeque<Vec<u8>>>>,
    received_b: Arc<Mutex<Vec<Vec<u8>>>>,
    stops: Vec<oneshot::Sender<()>>,
    runs: Vec<JoinHandle<ferrum_tunnel::Result<()>>>,
}

impl Pair {
    /// A is 10.8.0.1, B is 10.8.0.2; each allows its peer's /32.
    async fn start() -> Self {
        let a = KeyPair::generate();
        let b = KeyPair::generate();

        // Bind both UDP sockets first so we know each other's port.
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let sess_a = Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap();
        let sess_b = Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 2).unwrap();

        // Mock TUN devices; keep clones to inject/observe packets.
        let tun_a = MockTun::default();
        let tun_b = MockTun::default();
        let inject_a = tun_a.to_runner.clone();
        let received_b = tun_b.from_runner.clone();

        let trans_a = UdpTransport::from_socket(sock_a, addr_b);
        let trans_b = UdpTransport::from_socket(sock_b, addr_a);

        let (stop_a_tx, stop_a_rx) = oneshot::channel();
        let (stop_b_tx, stop_b_rx) = oneshot::channel();
        let run_a = tokio::spawn(async move {
            ferrum_tunnel::run(sess_a, vec![cidr("10.8.0.2/32")], tun_a, trans_a, async {
                stop_a_rx.await.ok();
            })
            .await
        });
        let run_b = tokio::spawn(async move {
            ferrum_tunnel::run(sess_b, vec![cidr("10.8.0.1/32")], tun_b, trans_b, async {
                stop_b_rx.await.ok();
            })
            .await
        });

        // Give the handshake time to complete.
        tokio::time::sleep(Duration::from_millis(400)).await;
        Self {
            inject_a,
            received_b,
            stops: vec![stop_a_tx, stop_b_tx],
            runs: vec![run_a, run_b],
        }
    }

    /// Poll B's TUN for up to ~3 s until it has received `n` packets.
    async fn wait_for_b(&self, n: usize) -> Vec<Vec<u8>> {
        for _ in 0..60 {
            if self.received_b.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.received_b.lock().unwrap().clone()
    }

    async fn stop(self) {
        for s in self.stops {
            let _ = s.send(());
        }
        for r in self.runs {
            let _ = r.await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_traverses_tunnel_between_two_peers() {
    let pair = Pair::start().await;
    let packet = ipv4([10, 8, 0, 1], [10, 8, 0, 2]);
    pair.inject_a.lock().unwrap().push_back(packet.clone());

    let got = pair.wait_for_b(1).await;
    pair.stop().await;
    assert_eq!(
        got.first()
            .expect("packet did not traverse the tunnel within timeout"),
        &packet,
        "decrypted packet at B must match what A sent"
    );
}

/// SEC-011: B drops a packet that decrypts fine under A's session but claims a
/// source outside A's `allowed_ips`, and still delivers A's genuine traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_with_a_source_outside_allowed_ips_is_dropped() {
    let pair = Pair::start().await;
    let before = ferrum_tunnel::spoofed_source_drops();
    let spoofed = ipv4([10, 8, 0, 9], [10, 8, 0, 2]);
    let genuine = ipv4([10, 8, 0, 1], [10, 8, 0, 2]);
    // Spoofed first: once the genuine packet has arrived, the spoofed one has
    // been processed too (one peer, one ordered session).
    pair.inject_a.lock().unwrap().push_back(spoofed);
    pair.inject_a.lock().unwrap().push_back(genuine.clone());

    let got = pair.wait_for_b(1).await;
    pair.stop().await;
    assert_eq!(
        got,
        vec![genuine],
        "only A's genuine packet may reach B's TUN"
    );
    assert!(ferrum_tunnel::spoofed_source_drops() > before);
}

fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2] = 0;
    p[3] = 20;
    p[8] = 64;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p
}

fn cidr(s: &str) -> Cidr {
    s.parse().unwrap()
}
