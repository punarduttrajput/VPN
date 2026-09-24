//! Mesh integration test: one node (A) routes packets to two different peers
//! (B and C) by destination IP, over real UDP sockets with mock TUN devices.
//! Proves multi-peer routing end-to-end without a real OS interface.

use std::time::Duration;

use ferrum_core::config::Cidr;
use ferrum_core::keys::KeyPair;
use ferrum_transport::{RelayMeshTransport, RelayServer, UdpMeshTransport};
use ferrum_tunnel::device::mock::MockTun;
use ferrum_tunnel::session::Session;
use ferrum_tunnel::{run_mesh, run_mesh_relayed, MeshPeer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

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
        MeshPeer::new(
            Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
            addr_b,
            vec![cidr("10.8.0.2/32")],
        ),
        MeshPeer::new(
            Session::from_bytes(a.private.to_bytes(), c.public.to_bytes(), 2).unwrap(),
            addr_c,
            vec![cidr("10.8.0.3/32")],
        ),
    ];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        addr_a,
        vec![cidr("10.8.0.1/32")],
    )];
    let c_peers = vec![MeshPeer::new(
        Session::from_bytes(c.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        addr_a,
        vec![cidr("10.8.0.1/32")],
    )];

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

/// Crypto-demux: routing works even when a datagram's **source address is not
/// the peer's advertised endpoint**. A reaches B through a one-way relay (so B
/// sees A's traffic coming from the relay, not from A), while B replies to A
/// directly. Source-based demux would drop these; crypto-demux routes by which
/// session decrypts the packet. This is the property MASQUE relaying and NAT
/// rewriting depend on.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn mesh_routes_via_relay_with_mismatched_source() {
    let (a, b) = (KeyPair::generate(), KeyPair::generate());

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // One-way relay: everything it receives is forwarded to B. So A->relay->B
    // makes B see source = relay (not A); B->A goes direct.
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, _from)) = relay.recv_from(&mut buf).await {
            let _ = relay.send_to(&buf[..n], addr_b).await;
        }
    });

    // A sends to B *via the relay*; B sends to A directly. Neither side's inbound
    // source will equal the peer's configured endpoint.
    let a_peers = vec![MeshPeer::new(
        Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
        relay_addr,
        vec![cidr("10.8.0.2/32")],
    )];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        addr_a,
        vec![cidr("10.8.0.1/32")],
    )];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (_ua_tx, ua_rx) = tokio::sync::mpsc::channel(1);
    let (_ub_tx, ub_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh(
            tun_a,
            UdpMeshTransport::from_socket(sock_a),
            a_peers,
            ua_rx,
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
            ub_rx,
            async {
                stop_b_rx.await.ok();
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(500)).await; // handshake via relay

    let to_b = ipv4([10, 8, 0, 2]);
    inject_a.lock().unwrap().push_back(to_b.clone());

    let mut b_pkt = None;
    for _ in 0..80 {
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
        b_pkt.expect("B should receive A's packet relayed through a mismatched source"),
        to_b
    );
}

/// Endpoint roaming: a node that starts with a *wrong* (blackhole) endpoint for
/// a peer can still reach it, by learning the peer's real address from an
/// authenticated inbound packet. A (the initiator) has B's correct address, but
/// B's endpoint for A points at a dead port. A's handshake reaches B; only after
/// B roams A's endpoint to the observed source can B's response get back to A and
/// the handshake complete — then A delivers data to B. Without roaming, B's reply
/// vanishes into the blackhole and the tunnel never comes up.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn mesh_roams_peer_endpoint_to_observed_source() {
    let (a, b) = (KeyPair::generate(), KeyPair::generate());

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // A "sink": a bound socket that silently drains. We point B's endpoint for A
    // here so B's packets to A go nowhere useful (but, unlike a dead port, don't
    // trigger an ICMP unreachable that would reset the sender's socket). B can
    // only actually reach A after roaming to A's real source.
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while sink.recv_from(&mut buf).await.is_ok() {}
    });

    // A initiates and knows B's real address; B's endpoint for A is the sink.
    let a_peers = vec![MeshPeer::new(
        Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
        addr_b,
        vec![cidr("10.8.0.2/32")],
    )];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        sink_addr,
        vec![cidr("10.8.0.1/32")],
    )];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (_ua_tx, ua_rx) = tokio::sync::mpsc::channel(1);
    let (_ub_tx, ub_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh(
            tun_a,
            UdpMeshTransport::from_socket(sock_a),
            a_peers,
            ua_rx,
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
            ub_rx,
            async {
                stop_b_rx.await.ok();
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(500)).await; // B initiates -> A roams

    // A injects a packet for B; it can only arrive if A roamed B's endpoint away
    // from the blackhole to B's real address.
    let to_b = ipv4([10, 8, 0, 2]);
    inject_a.lock().unwrap().push_back(to_b.clone());

    let mut b_pkt = None;
    for _ in 0..80 {
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
        b_pkt.expect("A should reach B only after roaming off the blackhole endpoint"),
        to_b
    );
}

/// Connectivity check (Phase 4 M2): a peer's *primary* endpoint is unreachable,
/// and the only working path is carried as an extra ICE **candidate**. A must fan
/// its handshake out across the candidate to reach B — endpoint roaming then locks
/// onto the candidate that answered. To isolate the candidate path, B's endpoint
/// for A is also a dead sink, so B cannot bring the tunnel up on its own: the only
/// way data flows is A reaching B via the candidate, B learning A's address from
/// that authenticated handshake, and the session completing. Without candidate
/// fan-out the tunnel never comes up.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn mesh_probes_candidates_to_reach_a_peer() {
    let (a, b) = (KeyPair::generate(), KeyPair::generate());

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // Two draining sinks: bound sockets that silently swallow datagrams (so sends
    // don't trigger an ICMP unreachable that resets the sender on Windows). One is
    // A's bogus primary endpoint for B; the other is B's bogus endpoint for A.
    let sink_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_b_addr = sink_b.local_addr().unwrap();
    let sink_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_a_addr = sink_a.local_addr().unwrap();
    for sink in [sink_b, sink_a] {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while sink.recv_from(&mut buf).await.is_ok() {}
        });
    }

    // A's *primary* endpoint for B is the dead sink; B's real address is only
    // reachable as a candidate. B's endpoint for A is also a dead sink, with no
    // candidates — so B cannot reach A until it learns A's path from A's handshake.
    let a_peers = vec![MeshPeer::with_candidates(
        Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
        sink_b_addr,
        vec![cidr("10.8.0.2/32")],
        vec![addr_b],
    )];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        sink_a_addr,
        vec![cidr("10.8.0.1/32")],
    )];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (_ua_tx, ua_rx) = tokio::sync::mpsc::channel(1);
    let (_ub_tx, ub_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh(
            tun_a,
            UdpMeshTransport::from_socket(sock_a),
            a_peers,
            ua_rx,
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
            ub_rx,
            async {
                stop_b_rx.await.ok();
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(500)).await; // probe candidate + handshake

    // A injects a packet for B; it can only arrive if A reached B via the
    // candidate and roamed B's endpoint onto it.
    let to_b = ipv4([10, 8, 0, 2]);
    inject_a.lock().unwrap().push_back(to_b.clone());

    let mut b_pkt = None;
    for _ in 0..80 {
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
        b_pkt.expect("A should reach B by probing the candidate, not the dead endpoint"),
        to_b
    );
}

/// Capstone: a node whose data plane runs over **MASQUE** (every peer tunnelled
/// through an HTTP/3 proxy) reaches a normal UDP mesh peer end-to-end. Exercises
/// the whole stack at once — `MasqueMeshTransport` + the multi-session proxy +
/// crypto-demux + endpoint roaming. M initiates over MASQUE; X (plain UDP) sees
/// the traffic arrive from the proxy, attributes it to M by decryption, roams M's
/// endpoint to the proxy path, and the tunnel comes up so M's packet reaches X.
#[cfg(feature = "masque")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn masque_mesh_node_reaches_udp_peer() {
    use ferrum_transport::{MasqueMeshTransport, MasqueProxy};

    let (m, x) = (KeyPair::generate(), KeyPair::generate());

    // X is a normal UDP mesh node.
    let sock_x = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_x = sock_x.local_addr().unwrap();

    // Sink: X's (wrong) endpoint for M, until X roams to the proxy path.
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while sink.recv_from(&mut b).await.is_ok() {}
    });

    // MASQUE proxy M tunnels through.
    let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_pin = proxy.fingerprint();
    tokio::spawn(async move {
        let _ = proxy.serve().await;
    });

    // X (tunnel 10.8.0.1) peers with M (tunnel 10.8.0.2). M reaches X at addr_x
    // via the proxy; X must roam to learn M's path.
    let x_peers = vec![MeshPeer::new(
        Session::from_bytes(x.private.to_bytes(), m.public.to_bytes(), 1).unwrap(),
        sink_addr,
        vec![cidr("10.8.0.2/32")],
    )];
    let m_peers = vec![MeshPeer::new(
        Session::from_bytes(m.private.to_bytes(), x.public.to_bytes(), 1).unwrap(),
        addr_x,
        vec![cidr("10.8.0.1/32")],
    )];

    let tun_x = MockTun::default();
    let tun_m = MockTun::default();
    let recv_x = tun_x.from_runner.clone();
    let inject_m = tun_m.to_runner.clone();

    let (stop_x_tx, stop_x_rx) = oneshot::channel();
    let (stop_m_tx, stop_m_rx) = oneshot::channel();
    let (_ux_tx, ux_rx) = tokio::sync::mpsc::channel(1);
    let (_um_tx, um_rx) = tokio::sync::mpsc::channel(1);

    let jx = tokio::spawn(async move {
        run_mesh(
            tun_x,
            UdpMeshTransport::from_socket(sock_x),
            x_peers,
            ux_rx,
            async {
                stop_x_rx.await.ok();
            },
        )
        .await
    });
    let jm = tokio::spawn(async move {
        run_mesh(
            tun_m,
            MasqueMeshTransport::new(proxy_addr, "ferrum", vec![proxy_pin]),
            m_peers,
            um_rx,
            async {
                stop_m_rx.await.ok();
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(1200)).await; // MASQUE + WG handshake

    // M sends a packet to X's tunnel IP; it must traverse MASQUE -> proxy -> X.
    let to_x = ipv4([10, 8, 0, 1]);
    inject_m.lock().unwrap().push_back(to_x.clone());

    let mut x_pkt = None;
    for _ in 0..100 {
        x_pkt = x_pkt.or_else(|| recv_x.lock().unwrap().first().cloned());
        if x_pkt.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = stop_x_tx.send(());
    let _ = stop_m_tx.send(());
    let _ = jx.await;
    let _ = jm.await;

    assert_eq!(
        x_pkt.expect("X should receive M's packet over the MASQUE mesh path"),
        to_x
    );
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
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        addr_a,
        vec![cidr("10.8.0.1/32")],
    )];

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
        .send(vec![MeshPeer::new(
            Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
            addr_b,
            vec![cidr("10.8.0.2/32")],
        )])
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
    use ferrum_transport::{QuicMeshTransport, TlsIdentity};

    let (a, b, c) = (
        KeyPair::generate(),
        KeyPair::generate(),
        KeyPair::generate(),
    );

    // Build the QUIC endpoints first so we know each node's advertised address.
    // Each presents the stable TLS identity derived from its WireGuard key.
    async fn quic_node(kp: &KeyPair) -> QuicMeshTransport {
        let id = TlsIdentity::from_wireguard_key(&kp.private.to_bytes()).unwrap();
        QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap(), &id)
            .await
            .unwrap()
    }
    let qa = quic_node(&a).await;
    let qb = quic_node(&b).await;
    let qc = quic_node(&c).await;
    let (addr_a, addr_b, addr_c) = (qa.local_addr(), qb.local_addr(), qc.local_addr());
    // Each peer carries its expected TLS pin (as `build_mesh_peers` does from the
    // coordinator's map); `run_mesh` hands them to the transport (SEC-004), so
    // every dial below is pinned.
    let (pin_a, pin_b, pin_c) = (qa.fingerprint(), qb.fingerprint(), qc.fingerprint());

    let a_peers = vec![
        MeshPeer::new(
            Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
            addr_b,
            vec![cidr("10.8.0.2/32")],
        )
        .with_tls_pins(vec![pin_b]),
        MeshPeer::new(
            Session::from_bytes(a.private.to_bytes(), c.public.to_bytes(), 2).unwrap(),
            addr_c,
            vec![cidr("10.8.0.3/32")],
        )
        .with_tls_pins(vec![pin_c]),
    ];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        addr_a,
        vec![cidr("10.8.0.1/32")],
    )
    .with_tls_pins(vec![pin_a])];
    let c_peers = vec![MeshPeer::new(
        Session::from_bytes(c.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        addr_a,
        vec![cidr("10.8.0.1/32")],
    )
    .with_tls_pins(vec![pin_a])];

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

/// Capstone (Phase 4 M3): two nodes that know *nothing* of each other's address
/// reach each other through a **public-key-keyed relay**. Each node connects out
/// to the relay and addresses its peer purely by public key via an opaque
/// endpoint handle (a non-routable loopback address that stands in for the peer).
/// The relay forwards by key; the mesh's crypto-demux routes the inbound payload.
/// This is the fallback path for peers with no working direct route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_connects_two_nodes_by_public_key() {
    let (a, b) = (KeyPair::generate(), KeyPair::generate());

    // The shared relay both nodes dial out to.
    let relay = Arc::new(
        RelayServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );
    let relay_addr = relay.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = relay.serve().await;
    });

    // Opaque endpoint handles: stable identities for each peer, not routable
    // (all traffic goes to the relay). Each node maps its peer's handle <-> key.
    let handle_a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let handle_b: SocketAddr = "127.0.0.1:9002".parse().unwrap();

    let trans_a = RelayMeshTransport::connect(
        relay_addr,
        a.public.to_bytes(),
        &[(handle_b, b.public.to_bytes())],
    )
    .await
    .unwrap();
    let trans_b = RelayMeshTransport::connect(
        relay_addr,
        b.public.to_bytes(),
        &[(handle_a, a.public.to_bytes())],
    )
    .await
    .unwrap();

    // A reaches B at handle_b; B reaches A at handle_a — both via the relay.
    let a_peers = vec![MeshPeer::new(
        Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
        handle_b,
        vec![cidr("10.8.0.2/32")],
    )];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        handle_a,
        vec![cidr("10.8.0.1/32")],
    )];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (_ua_tx, ua_rx) = tokio::sync::mpsc::channel(1);
    let (_ub_tx, ub_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh(tun_a, trans_a, a_peers, ua_rx, async {
            stop_a_rx.await.ok();
        })
        .await
    });
    let jb = tokio::spawn(async move {
        run_mesh(tun_b, trans_b, b_peers, ub_rx, async {
            stop_b_rx.await.ok();
        })
        .await
    });

    tokio::time::sleep(Duration::from_millis(500)).await; // handshake via relay

    let to_b = ipv4([10, 8, 0, 2]);
    inject_a.lock().unwrap().push_back(to_b.clone());

    let mut b_pkt = None;
    for _ in 0..80 {
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
        b_pkt.expect("B should receive A's packet relayed by public key"),
        to_b
    );
}

/// Automatic relay **fallback** (Phase 4): two nodes run the dual-underlay data
/// plane (`run_mesh_relayed`) with a working relay *and* a direct UDP transport,
/// but each node's direct endpoint for its peer is a blackhole — so the direct
/// path can never come up. The per-peer path machine must bring the tunnel up
/// over the relay instead: handshakes fan across both underlays, the relay
/// delivers, `on_relay_packet` confirms the relay path, and data then rides it.
/// Delivery here can *only* have come over the relay (direct is a sink), proving
/// the fallback is wired, not just modeled. The relay's `handle <-> key` table is
/// aligned from the peer set by `run_mesh_relayed` (connect with no peers).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_fallback_carries_traffic_when_direct_is_blocked() {
    let (a, b) = (KeyPair::generate(), KeyPair::generate());

    // Direct UDP sockets for each node's direct underlay.
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Blackhole sinks: each node's *direct* endpoint for its peer points here, so
    // the direct path never comes up (sends are silently drained — no ICMP reset
    // on Windows). The only working path is the relay.
    let sink_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_a_addr = sink_a.local_addr().unwrap();
    let sink_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_b_addr = sink_b.local_addr().unwrap();
    for sink in [sink_a, sink_b] {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while sink.recv_from(&mut buf).await.is_ok() {}
        });
    }

    // A working public-key-keyed relay both nodes dial out to.
    let relay = Arc::new(
        RelayServer::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );
    let relay_addr = relay.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = relay.serve().await;
    });

    // Relay transports connect with no peers; run_mesh_relayed aligns their tables
    // from the peer set (using each peer's blackhole endpoint as a stable handle).
    let relay_a = RelayMeshTransport::connect(relay_addr, a.public.to_bytes(), &[])
        .await
        .unwrap();
    let relay_b = RelayMeshTransport::connect(relay_addr, b.public.to_bytes(), &[])
        .await
        .unwrap();

    // Direct endpoints are blackholes; the tunnel can only come up over the relay.
    let a_peers = vec![MeshPeer::new(
        Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
        sink_b_addr,
        vec![cidr("10.8.0.2/32")],
    )];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        sink_a_addr,
        vec![cidr("10.8.0.1/32")],
    )];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (_ua_tx, ua_rx) = tokio::sync::mpsc::channel(1);
    let (_ub_tx, ub_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh_relayed(
            tun_a,
            UdpMeshTransport::from_socket(sock_a),
            relay_a,
            a_peers,
            ua_rx,
            async {
                stop_a_rx.await.ok();
            },
        )
        .await
    });
    let jb = tokio::spawn(async move {
        run_mesh_relayed(
            tun_b,
            UdpMeshTransport::from_socket(sock_b),
            relay_b,
            b_peers,
            ub_rx,
            async {
                stop_b_rx.await.ok();
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(700)).await; // handshake over the relay

    let to_b = ipv4([10, 8, 0, 2]);
    inject_a.lock().unwrap().push_back(to_b.clone());

    let mut b_pkt = None;
    for _ in 0..100 {
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
        b_pkt.expect("B should receive A's packet over the relay fallback when direct is blocked"),
        to_b
    );
}

/// Direct path is **preferred** over an available relay (Phase 4): the dual
/// underlay runs with a *non-forwarding* relay (a draining sink that registers
/// nothing and delivers nothing) but correct direct endpoints. The tunnel comes
/// up over the direct path and data rides it; since the relay forwards nothing,
/// delivery proves the traffic went direct — and that a dead relay underlay does
/// not break the direct path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_path_is_used_when_available_despite_a_relay() {
    let (a, b) = (KeyPair::generate(), KeyPair::generate());

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // A "relay" that never forwards: a draining sink. The relay underlay exists
    // (each node connects to it) but delivers nothing, so any delivery must be
    // direct.
    let dead_relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_relay_addr = dead_relay.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while dead_relay.recv_from(&mut buf).await.is_ok() {}
    });

    let relay_a = RelayMeshTransport::connect(dead_relay_addr, a.public.to_bytes(), &[])
        .await
        .unwrap();
    let relay_b = RelayMeshTransport::connect(dead_relay_addr, b.public.to_bytes(), &[])
        .await
        .unwrap();

    // Correct direct endpoints: the direct path comes up.
    let a_peers = vec![MeshPeer::new(
        Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap(),
        addr_b,
        vec![cidr("10.8.0.2/32")],
    )];
    let b_peers = vec![MeshPeer::new(
        Session::from_bytes(b.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
        addr_a,
        vec![cidr("10.8.0.1/32")],
    )];

    let tun_a = MockTun::default();
    let tun_b = MockTun::default();
    let inject_a = tun_a.to_runner.clone();
    let recv_b = tun_b.from_runner.clone();

    let (stop_a_tx, stop_a_rx) = oneshot::channel();
    let (stop_b_tx, stop_b_rx) = oneshot::channel();
    let (_ua_tx, ua_rx) = tokio::sync::mpsc::channel(1);
    let (_ub_tx, ub_rx) = tokio::sync::mpsc::channel(1);

    let ja = tokio::spawn(async move {
        run_mesh_relayed(
            tun_a,
            UdpMeshTransport::from_socket(sock_a),
            relay_a,
            a_peers,
            ua_rx,
            async {
                stop_a_rx.await.ok();
            },
        )
        .await
    });
    let jb = tokio::spawn(async move {
        run_mesh_relayed(
            tun_b,
            UdpMeshTransport::from_socket(sock_b),
            relay_b,
            b_peers,
            ub_rx,
            async {
                stop_b_rx.await.ok();
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(500)).await; // direct WG handshake

    let to_b = ipv4([10, 8, 0, 2]);
    inject_a.lock().unwrap().push_back(to_b.clone());

    let mut b_pkt = None;
    for _ in 0..80 {
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
        b_pkt.expect(
            "B should receive A's packet over the direct path (the relay forwards nothing)"
        ),
        to_b
    );
}
