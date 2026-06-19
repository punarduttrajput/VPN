//! Mesh integration test: one node (A) routes packets to two different peers
//! (B and C) by destination IP, over real UDP sockets with mock TUN devices.
//! Proves multi-peer routing end-to-end without a real OS interface.

use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use vpn_core::config::Cidr;
use vpn_core::keys::KeyPair;
use vpn_transport::UdpMeshTransport;
use vpn_tunnel::device::mock::MockTun;
use vpn_tunnel::session::Session;
use vpn_tunnel::{run_mesh, MeshPeer};

fn ipv4(dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[3] = 20;
    p[8] = 64;
    p[12..16].copy_from_slice(&[10, 8, 0, 1]); // src = A
    p[16..20].copy_from_slice(&dst);
    p
}

fn cidr(s: &str) -> Cidr {
    s.parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn mesh_routes_packets_to_the_right_peer() {
    let (a, b, c) = (
        KeyPair::generate(),
        KeyPair::generate(),
        KeyPair::generate(),
    );

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();
    let addr_c = sock_c.local_addr().unwrap();

    // A is meshed with B (10.8.0.2) and C (10.8.0.3).
    let a_peers = vec![
        MeshPeer {
            session: Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
            endpoint: addr_b,
            allowed_ips: vec![cidr("10.8.0.2/32")],
        },
        MeshPeer {
            session: Session::from_bytes(a.private.to_bytes(), c.public.to_bytes(), 2).unwrap(),
            endpoint: addr_c,
            allowed_ips: vec![cidr("10.8.0.3/32")],
        },
    ];
    let b_peers = vec![MeshPeer {
        session: Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        endpoint: addr_a,
        allowed_ips: vec![cidr("10.8.0.1/32")],
    }];
    let c_peers = vec![MeshPeer {
        session: Session::from_bytes(c.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        endpoint: addr_a,
        allowed_ips: vec![cidr("10.8.0.1/32")],
    }];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let tun_c = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();
    let recv_c = tun_c.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (stop_c_tx, stop_c_rx) = oneshot::channel();

    // Static mesh: hold the update senders so the receivers stay pending (never
    // delivering a new peer set) for the lifetime of the run.
    let (upd_a_tx, upd_a_rx) = tokio::sync::mpsc::channel(1);
    let (upd_b_tx, upd_b_rx) = tokio::sync::mpsc::channel(1);
    let (upd_c_tx, upd_c_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh(
            tun_a,
            UdpMeshTransport::from_socket(sock_a),
            a_peers,
            upd_a_rx,
            async {
                stop_a_rx.await.ok();
            },
        )
        .await
    });
    let jb = tokio::spawn(async move {
        run_mesh(
            tun_b,
            UdpMeshTransport::from_socket(sock_b),
            b_peers,
            upd_b_rx,
            async {
                stop_b_rx.await.ok();
            },
        )
        .await
    });
    let jc = tokio::spawn(async move {
        run_mesh(
            tun_c,
            UdpMeshTransport::from_socket(sock_c),
            c_peers,
            upd_c_rx,
            async {
                stop_c_rx.await.ok();
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(400)).await; // handshakes

    // Inject two packets at A: one for B, one for C.
    let to_b = ipv4([10, 8, 0, 2]);
    let to_c = ipv4([10, 8, 0, 3]);
    inject_a.lock().unwrap().push_back(to_b.clone());
    inject_a.lock().unwrap().push_back(to_c.clone());

    let got = |slot: &std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>| {
        slot.lock().unwrap().first().cloned()
    };
    let mut b_pkt = None;
    let mut c_pkt = None;
    for _ in 0..60 {
        b_pkt = b_pkt.or_else(|| got(&recv_b));
        c_pkt = c_pkt.or_else(|| got(&recv_c));
        if b_pkt.is_some() && c_pkt.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = stop_a_tx.send(());
    let _ = stop_b_tx.send(());
    let _ = stop_c_tx.send(());
    let _ = ja.await;
    let _ = jb.await;
    let _ = jc.await;
    drop((upd_a_tx, upd_b_tx, upd_c_tx)); // held until after the run

    assert_eq!(b_pkt.expect("B should receive its packet"), to_b);
    assert_eq!(c_pkt.expect("C should receive its packet"), to_c);
}

/// A starts with an EMPTY mesh and learns about B only via a live update on the
/// channel (the shape of a coordinator `WatchNetworkMap` push). Once applied, a
/// packet for B's tunnel IP routes correctly — proving dynamic reconfiguration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_applies_peers_from_a_live_update() {
    let (a, b) = (KeyPair::generate(), KeyPair::generate());

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // B is statically configured with A as its peer (it answers the handshake).
    let b_peers = vec![MeshPeer {
        session: Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        endpoint: addr_a,
        allowed_ips: vec![cidr("10.8.0.1/32")],
    }];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (upd_a_tx, upd_a_rx) = tokio::sync::mpsc::channel(1);
    let (_upd_b_tx, upd_b_rx) = tokio::sync::mpsc::channel(1);

    // A starts with NO peers.
    let ja = tokio::spawn(async move {
        run_mesh(
            tun_a,
            UdpMeshTransport::from_socket(sock_a),
            Vec::new(),
            upd_a_rx,
            async {
                stop_a_rx.await.ok();
            },
        )
        .await
    });
    let jb = tokio::spawn(async move {
        run_mesh(
            tun_b,
            UdpMeshTransport::from_socket(sock_b),
            b_peers,
            upd_b_rx,
            async {
                stop_b_rx.await.ok();
            },
        )
        .await
    });

    // Deliver B as a peer to A over the update channel (as a watch push would).
    upd_a_tx
        .send(vec![MeshPeer {
            session: Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
            endpoint: addr_b,
            allowed_ips: vec![cidr("10.8.0.2/32")],
        }])
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await; // apply + handshake

    let to_b = ipv4([10, 8, 0, 2]);
    inject_a.lock().unwrap().push_back(to_b.clone());

    let mut b_pkt = None;
    for _ in 0..60 {
        b_pkt = b_pkt.or_else(|| recv_b.lock().unwrap().first().cloned());
        if b_pkt.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = stop_a_tx.send(());
    let _ = stop_b_tx.send(());
    let _ = ja.await;
    let _ = jb.await;

    assert_eq!(
        b_pkt.expect("B should receive the packet after A applies the live update"),
        to_b
    );
}

/// The same multi-peer routing, but over the **QUIC** mesh transport instead of
/// UDP: real WireGuard handshakes + datagram routing across QUIC connections,
/// with peers identified by their advertised address (the hello attribution).
#[cfg(feature = "quic")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_mesh_routes_packets_to_the_right_peer() {
    use vpn_transport::QuicMeshTransport;

    let (a, b, c) = (
        KeyPair::generate(),
        KeyPair::generate(),
        KeyPair::generate(),
    );

    // Build the QUIC endpoints first so we know each node's advertised address.
    let qa = QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let qb = QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let qc = QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (addr_a, addr_b, addr_c) = (qa.local_addr(), qb.local_addr(), qc.local_addr());

    let a_peers = vec![
        MeshPeer {
            session: Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
            endpoint: addr_b,
            allowed_ips: vec![cidr("10.8.0.2/32")],
        },
        MeshPeer {
            session: Session::from_bytes(a.private.to_bytes(), c.public.to_bytes(), 2).unwrap(),
            endpoint: addr_c,
            allowed_ips: vec![cidr("10.8.0.3/32")],
        },
    ];
    let b_peers = vec![MeshPeer {
        session: Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        endpoint: addr_a,
        allowed_ips: vec![cidr("10.8.0.1/32")],
    }];
    let c_peers = vec![MeshPeer {
        session: Session::from_bytes(c.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        endpoint: addr_a,
        allowed_ips: vec![cidr("10.8.0.1/32")],
    }];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let tun_c = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();
    let recv_c = tun_c.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (stop_c_tx, stop_c_rx) = oneshot::channel();
    let (upd_a_tx, upd_a_rx) = tokio::sync::mpsc::channel(1);
    let (upd_b_tx, upd_b_rx) = tokio::sync::mpsc::channel(1);
    let (upd_c_tx, upd_c_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh(tun_a, qa, a_peers, upd_a_rx, async {
            stop_a_rx.await.ok();
        })
        .await
    });
    let jb = tokio::spawn(async move {
        run_mesh(tun_b, qb, b_peers, upd_b_rx, async {
            stop_b_rx.await.ok();
        })
        .await
    });
    let jc = tokio::spawn(async move {
        run_mesh(tun_c, qc, c_peers, upd_c_rx, async {
            stop_c_rx.await.ok();
        })
        .await
    });

    tokio::time::sleep(Duration::from_millis(700)).await; // QUIC + WG handshakes

    let to_b = ipv4([10, 8, 0, 2]);
    let to_c = ipv4([10, 8, 0, 3]);
    inject_a.lock().unwrap().push_back(to_b.clone());
    inject_a.lock().unwrap().push_back(to_c.clone());

    let mut b_pkt = None;
    let mut c_pkt = None;
    for _ in 0..80 {
        b_pkt = b_pkt.or_else(|| recv_b.lock().unwrap().first().cloned());
        c_pkt = c_pkt.or_else(|| recv_c.lock().unwrap().first().cloned());
        if b_pkt.is_some() && c_pkt.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = stop_a_tx.send(());
    let _ = stop_b_tx.send(());
    let _ = stop_c_tx.send(());
    let _ = ja.await;
    let _ = jb.await;
    let _ = jc.await;
    drop((upd_a_tx, upd_b_tx, upd_c_tx));

    assert_eq!(b_pkt.expect("B should receive its packet over QUIC"), to_b);
    assert_eq!(c_pkt.expect("C should receive its packet over QUIC"), to_c);
}
