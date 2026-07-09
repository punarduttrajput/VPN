//! Live-traffic harness for the relay, including its eBPF/XDP fast path
//! (PRD `phase-6-ebpf-xdp-relay.md`, M5 "live traffic" verification).
//!
//! Not a test: the XDP path doesn't fire on loopback, so this runs manually
//! as two processes against a `ferrum relay` reachable over a real
//! (veth/netns or physical) interface — see `relay-ebpf/README.md` "Verify".
//!
//! Two fixed roles, `a` and `b`, with well-known 32-byte test keys, so the
//! two processes need no key exchange:
//!
//! ```sh
//! relay_traffic <relay_addr> b recv 1000 [timeout_secs]     # start first
//! relay_traffic <relay_addr> a send 1000 [payload_bytes] [pps]
//! relay_traffic <relay_addr> b bench-recv [idle_cutoff_secs]
//! relay_traffic <relay_addr> a bench-send <secs> [payload_bytes]
//! ```
//!
//! Machine-readable result lines start with `RESULT` — the driver scripts
//! grep for them.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ferrum_transport::relay::{PublicKey, RelayMeshTransport};
use ferrum_transport::MeshTransport;

const KEY_A: PublicKey = [0xAA; 32];
const KEY_B: PublicKey = [0xBB; 32];

/// Opaque per-peer endpoint handles (never routed to — the relay addresses
/// peers by key; these only key the transport's internal peer map).
const HANDLE_A: &str = "10.255.255.1:1";
const HANDLE_B: &str = "10.255.255.2:1";

fn usage() -> ! {
    eprintln!(
        "usage: relay_traffic <relay_addr> <a|b> <mode> [args]\n\
         modes:\n\
         \x20 recv <expected> [timeout_secs=30]\n\
         \x20 send <count> [payload_bytes=1400] [pps=0 (unpaced)]\n\
         \x20 bench-recv [idle_cutoff_secs=3]\n\
         \x20 bench-send <secs> [payload_bytes=1400]"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        usage();
    }
    let relay: SocketAddr = args[1].parse().expect("bad relay addr");
    let (self_key, peer_handle, peer_key) = match args[2].as_str() {
        "a" => (KEY_A, HANDLE_B, KEY_B),
        "b" => (KEY_B, HANDLE_A, KEY_A),
        _ => usage(),
    };
    let peer: SocketAddr = peer_handle.parse().unwrap();

    let transport = RelayMeshTransport::connect(relay, self_key, &[(peer, peer_key)])
        .await
        .expect("connecting to relay");
    // Give the relay a beat to process our register frame before any send.
    tokio::time::sleep(Duration::from_millis(100)).await;

    match args[3].as_str() {
        "recv" => {
            let expected: u64 = args
                .get(4)
                .map(|s| s.parse().unwrap())
                .unwrap_or_else(|| usage());
            let timeout = Duration::from_secs(arg_or(&args, 5, 30));
            recv(&transport, expected, timeout).await;
        }
        "send" => {
            let count: u64 = args
                .get(4)
                .map(|s| s.parse().unwrap())
                .unwrap_or_else(|| usage());
            let size = arg_or(&args, 5, 1400) as usize;
            let pps = arg_or(&args, 6, 0);
            send(&transport, peer, count, size, pps).await;
        }
        "bench-recv" => {
            let idle = Duration::from_secs(arg_or(&args, 4, 3));
            bench_recv(&transport, idle).await;
        }
        "bench-send" => {
            let secs = args
                .get(4)
                .map(|s| s.parse().unwrap())
                .unwrap_or_else(|| usage());
            let size = arg_or(&args, 5, 1400) as usize;
            bench_send(&transport, peer, secs, size).await;
        }
        // Diagnostic: drop the RelayMeshTransport filtering entirely and dump
        // every raw datagram this role's socket sees (source + first bytes),
        // so a mis-rewritten fast-path packet is visible byte-for-byte.
        "rawdump" => {
            drop(transport); // its socket would steal nothing (distinct port), but be tidy
            let expected: u64 = arg_or(&args, 4, 10);
            let timeout = Duration::from_secs(arg_or(&args, 5, 20));
            rawdump(relay, self_key, expected, timeout).await;
        }
        _ => usage(),
    }
}

/// Register `self_key` from a plain socket, then print every datagram that
/// arrives (truncated hex) until `expected` datagrams or `timeout`.
async fn rawdump(relay: SocketAddr, self_key: [u8; 32], expected: u64, timeout: Duration) {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind");
    let mut reg = vec![0x01u8];
    reg.extend_from_slice(&self_key);
    sock.send_to(&reg, relay).await.expect("register");
    eprintln!("rawdump: registered from {}", sock.local_addr().unwrap());
    let mut buf = vec![0u8; 65_600];
    let deadline = Instant::now() + timeout;
    let mut n = 0u64;
    while n < expected {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                n += 1;
                let head = &buf[..len.min(48)];
                let hex: String = head.iter().map(|b| format!("{b:02x}")).collect();
                println!("RAW n={n} from={from} len={len} head={hex}");
            }
            Ok(Err(e)) => {
                eprintln!("raw recv error: {e}");
                break;
            }
            Err(_) => break,
        }
    }
    println!("RESULT rawdump datagrams={n} expected={expected}");
}

fn arg_or(args: &[String], i: usize, default: u64) -> u64 {
    args.get(i).map(|s| s.parse().unwrap()).unwrap_or(default)
}

/// Receive until `expected` frames arrive or `timeout` elapses; report both.
async fn recv(t: &RelayMeshTransport, expected: u64, timeout: Duration) {
    let mut buf = vec![0u8; 65_600];
    let (mut n, mut bytes) = (0u64, 0u64);
    let deadline = Instant::now() + timeout;
    let mut first: Option<Instant> = None;
    while n < expected {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, t.recv_from(&mut buf)).await {
            Ok(Ok((len, _from))) => {
                first.get_or_insert_with(Instant::now);
                n += 1;
                bytes += len as u64;
                if n.is_multiple_of(1000) {
                    eprintln!("recv: {n}/{expected}");
                }
            }
            Ok(Err(e)) => {
                eprintln!("recv error: {e}");
                break;
            }
            Err(_) => break, // timeout
        }
    }
    let elapsed = first.map(|f| f.elapsed().as_secs_f64()).unwrap_or(0.0);
    println!("RESULT recv frames={n} expected={expected} bytes={bytes} elapsed_s={elapsed:.3}");
}

/// Send `count` frames of `size` payload bytes; `pps == 0` means unpaced.
async fn send(t: &RelayMeshTransport, peer: SocketAddr, count: u64, size: usize, pps: u64) {
    let payload = vec![0x42u8; size];
    let interval = (pps > 0).then(|| Duration::from_secs_f64(1.0 / pps as f64));
    let start = Instant::now();
    for i in 0..count {
        t.send_to(peer, &payload).await.expect("send");
        if let Some(iv) = interval {
            tokio::time::sleep(iv).await;
        } else if i % 64 == 63 {
            // Unpaced: yield now and then so we don't starve the runtime.
            tokio::task::yield_now().await;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "RESULT send frames={count} bytes={} elapsed_s={elapsed:.3}",
        count * size as u64
    );
}

/// Count everything that arrives until traffic goes quiet for `idle`;
/// report throughput over first-frame..last-frame.
async fn bench_recv(t: &RelayMeshTransport, idle: Duration) {
    let mut buf = vec![0u8; 65_600];
    let (mut n, mut bytes) = (0u64, 0u64);
    let mut first: Option<Instant> = None;
    let mut last = Instant::now();
    loop {
        // Wait indefinitely for the first frame; apply the idle cutoff after.
        let wait = if first.is_some() {
            idle
        } else {
            Duration::from_secs(600)
        };
        match tokio::time::timeout(wait, t.recv_from(&mut buf)).await {
            Ok(Ok((len, _from))) => {
                first.get_or_insert_with(Instant::now);
                last = Instant::now();
                n += 1;
                bytes += len as u64;
            }
            Ok(Err(e)) => {
                eprintln!("recv error: {e}");
                break;
            }
            Err(_) => break, // idle / gave up waiting
        }
    }
    let elapsed = first
        .map(|f| last.duration_since(f).as_secs_f64())
        .unwrap_or(0.0);
    let mbps = if elapsed > 0.0 {
        bytes as f64 * 8.0 / elapsed / 1e6
    } else {
        0.0
    };
    let pps = if elapsed > 0.0 {
        n as f64 / elapsed
    } else {
        0.0
    };
    println!(
        "RESULT bench-recv frames={n} bytes={bytes} elapsed_s={elapsed:.3} mbps={mbps:.1} pps={pps:.0}"
    );
}

/// Flood frames of `size` payload bytes for `secs`; report the offered rate.
async fn bench_send(t: &RelayMeshTransport, peer: SocketAddr, secs: u64, size: usize) {
    let payload = vec![0x42u8; size];
    let start = Instant::now();
    let window = Duration::from_secs(secs);
    let mut n = 0u64;
    while start.elapsed() < window {
        t.send_to(peer, &payload).await.expect("send");
        n += 1;
        if n.is_multiple_of(64) {
            tokio::task::yield_now().await;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let bytes = n * size as u64;
    let mbps = bytes as f64 * 8.0 / elapsed / 1e6;
    println!(
        "RESULT bench-send frames={n} bytes={bytes} elapsed_s={elapsed:.3} offered_mbps={mbps:.1}"
    );
}
