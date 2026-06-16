//! End-to-end loopback test (PRD M5): two full tunnel runners on localhost UDP
//! sockets, each with a mock TUN device. A packet injected into peer A's TUN
//! must arrive, decrypted and intact, at peer B's TUN — proving the complete
//! handshake + encapsulate + transport + decapsulate path without needing a
//! real OS interface (which Phase 1 scopes to Linux/macOS only).

use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use vpn_core::keys::KeyPair;
use vpn_tunnel::device::mock::MockTun;
use vpn_tunnel::session::Session;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_traverses_tunnel_between_two_peers() {
    // Keys for both peers.
    let a = KeyPair::generate();
    let b = KeyPair::generate();

    // Bind both UDP sockets first so we know each other's port.
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // Sessions pointing at each other.
    let sess_a = Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap();
    let sess_b = Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 2).unwrap();

    // Mock TUN devices; keep clones to inject/observe packets.
    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let received_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();

    let run_a = tokio::spawn(async move {
        vpn_tunnel::run(sess_a, tun_a, sock_a, addr_b, async {
            stop_a_rx.await.ok();
        })
        .await
    });
    let run_b = tokio::spawn(async move {
        vpn_tunnel::run(sess_b, tun_b, sock_b, addr_a, async {
            stop_b_rx.await.ok();
        })
        .await
    });

    // Give the handshake time to complete.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Inject an IP packet at A's TUN; the runner should encrypt + send it to B.
    let packet = sample_ipv4_packet();
    inject_a.lock().unwrap().push_back(packet.clone());

    // Poll B's TUN write side for the decrypted packet (up to ~3s).
    let mut got = None;
    for _ in 0..60 {
        if let Some(p) = received_b.lock().unwrap().first().cloned() {
            got = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Shut both runners down cleanly.
    let _ = stop_a_tx.send(());
    let _ = stop_b_tx.send(());
    let _ = run_a.await;
    let _ = run_b.await;

    let got = got.expect("packet did not traverse the tunnel within timeout");
    assert_eq!(got, packet, "decrypted packet at B must match what A sent");
}

fn sample_ipv4_packet() -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2] = 0;
    p[3] = 20;
    p[8] = 64;
    p[12..16].copy_from_slice(&[10, 8, 0, 1]);
    p[16..20].copy_from_slice(&[10, 8, 0, 2]);
    p
}
