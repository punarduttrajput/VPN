//! Data-plane glue (Phase 5): drive the OS mesh data plane from the facade.
//!
//! [`FerrumClient`](crate::FerrumClient) owns the *control* side — registration, state,
//! the peer view, the event stream. This module connects it to the *data* side
//! ([`ferrum_tunnel::run_mesh`]): a native shell (or the CLI) supplies an opened TUN
//! device and a bound [`MeshTransport`], and [`run_mesh_session`] registers with
//! the coordinator, keeps the live mesh converged from `WatchNetworkMap`, and
//! reflects every change back into the facade so the UI stays current.
//!
//! Split of responsibilities: the *shell* owns the OS integration (creating the
//! TUN — typically from a platform-provided fd — and choosing the transport);
//! this owns everything platform-independent (control sync + the mesh loop).
//!
//! Behind the `data-plane` feature, since it pulls in the tunnel/transport crates.

use std::future::Future;
use std::net::SocketAddr;

use tokio::sync::mpsc;
use tracing::warn;

use ferrum_core::config::Cidr;
use ferrum_transport::{MeshTransport, RelayMeshTransport};
use ferrum_tunnel::device::TunDevice;
use ferrum_tunnel::session::Session;
use ferrum_tunnel::{run_mesh, run_mesh_relayed, MeshPeer};

use crate::client::FerrumClient;
use crate::{ClientIdentity, ControlClient, Error, PeerSpec};

/// Turn the coordinator's peer list into mesh sessions keyed by our private key.
///
/// Each peer gets its own [`Session`] (distinct local index) so outbound packets
/// can be routed to it by `allowed_ips` over one shared transport. A malformed
/// key/endpoint/CIDR surfaces as [`Error::DataPlane`].
// `Error` is the crate's single shared error (large because it carries
// `tonic::Status`); the rest of the crate returns it from async fns, which don't
// trip `result_large_err`. This is the one sync fn that returns it — boxing only
// here would be inconsistent, so allow the lint.
#[allow(clippy::result_large_err)]
pub fn build_mesh_peers(private_key_b64: &str, peers: &[PeerSpec]) -> Result<Vec<MeshPeer>, Error> {
    let priv_bytes = ferrum_core::keys::decode_key(private_key_b64)
        .map_err(|e| Error::DataPlane(format!("decoding private key: {e}")))?;
    peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let pub_bytes = ferrum_core::keys::decode_key(&p.public_key)
                .map_err(|e| Error::DataPlane(format!("peer key '{}': {e}", p.public_key)))?;
            let endpoint: SocketAddr = p
                .endpoint
                .parse()
                .map_err(|e| Error::DataPlane(format!("peer endpoint '{}': {e}", p.endpoint)))?;
            let allowed_ips = p
                .allowed_ips
                .iter()
                .map(|c| c.parse::<Cidr>())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| {
                    Error::DataPlane(format!("allowed_ips for '{}': {e}", p.public_key))
                })?;
            // ICE candidates (host + STUN reflexive) to probe for a working path;
            // unparseable entries are skipped rather than failing the whole peer.
            let candidates = p
                .candidates
                .iter()
                .filter_map(|c| c.parse::<SocketAddr>().ok())
                .collect::<Vec<_>>();
            // Local session indices must be distinct per peer; +1 keeps them non-zero.
            let session = Session::from_bytes(priv_bytes, pub_bytes, (i as u32) + 1)
                .map_err(|e| Error::DataPlane(format!("session for '{}': {e}", p.public_key)))?;
            Ok(MeshPeer::with_candidates(
                session,
                endpoint,
                allowed_ips,
                candidates,
            ))
        })
        .collect()
}

/// Our own 32-byte WireGuard public key, derived from the base64 private key —
/// the relay underlay's routing identity for this node.
// `Error` carries `tonic::Status` (large); boxing only this sync helper would be
// inconsistent with the rest of the crate, so allow the lint.
#[allow(clippy::result_large_err)]
fn self_public_key(private_key_b64: &str) -> Result<[u8; 32], Error> {
    let pub_b64 = ferrum_core::keys::public_base64_from_private(private_key_b64)
        .map_err(|e| Error::DataPlane(e.to_string()))?;
    ferrum_core::keys::decode_key(&pub_b64).map_err(|e| Error::DataPlane(e.to_string()))
}

/// Connect a public-key-keyed relay underlay at `addr` for this node. The relay's
/// peer table is aligned from the network map by the mesh runner, so we connect
/// with no peers here.
async fn connect_relay(addr: &str, private_key_b64: &str) -> Result<RelayMeshTransport, Error> {
    let relay_addr: SocketAddr = addr
        .parse()
        .map_err(|e| Error::DataPlane(format!("relay '{addr}': {e}")))?;
    let self_key = self_public_key(private_key_b64)?;
    RelayMeshTransport::connect(relay_addr, self_key, &[])
        .await
        .map_err(|e| Error::DataPlane(e.to_string()))
}

/// Run the full client data plane until `shutdown` resolves.
///
/// Registers `identity` with the coordinator (driving `client` to `Connected`),
/// then runs [`run_mesh`] over the caller-supplied `device` and `transport`,
/// continuously reconverging the mesh — and the facade's peer view — from the
/// coordinator's `WatchNetworkMap` stream. On exit (clean shutdown or a
/// data-plane error) the client returns to `Disconnected`.
///
/// `device` is the opened TUN (a shell hands one built from its platform fd);
/// `transport` is a bound [`MeshTransport`] (`UdpMeshTransport`, or QUIC/MASQUE).
/// `relay` is an optional **local relay-address override** (`ip:port`); when
/// `None`, the coordinator's advertised relay (if any) is used instead. Whenever a
/// relay address is resolved, the mesh runs direct + relay at once
/// ([`run_mesh_relayed`]), preferring direct and falling back per peer (PRD Phase
/// 4). `private_key_b64` is this device's WireGuard private key, used to build the
/// per-peer sessions and the relay's routing identity (it is never sent to the
/// coordinator).
///
/// `candidates` are this device's gathered NAT-traversal candidates (host +
/// STUN server-reflexive `ip:port`, typically from
/// [`ferrum_transport::stun::gather_candidates`]); they are published to the
/// coordinator after registration so permitted peers can probe them (PRD Phase
/// 4). Pass an empty slice to skip publishing.
// Eight parameters: each is an independent input the shell must supply (control
// identity, keys, candidates, the OS device, the transport, shutdown). Grouping
// them into a struct would only move the noise, so allow the lint.
#[allow(clippy::too_many_arguments)]
pub async fn run_mesh_session<D, M, F>(
    client: &FerrumClient,
    coordinator: &str,
    identity: &ClientIdentity,
    private_key_b64: &str,
    candidates: &[String],
    device: D,
    transport: M,
    relay: Option<String>,
    shutdown: F,
) -> Result<(), Error>
where
    D: TunDevice + Send + 'static,
    M: MeshTransport + Send + 'static,
    F: Future<Output = ()> + Send,
{
    // Control-plane connect: registers, loads the initial peer view, and drives
    // the facade Connecting -> Connected (or -> Failed, returning the error).
    client.connect(coordinator, identity).await?;

    // A second channel carries live map updates into both the mesh and the facade.
    let mut control = ControlClient::connect(coordinator.to_string()).await?;

    // Publish our gathered candidates (gather-then-signal, after registration) so
    // peers learn the alternative paths to probe. Best-effort: a failure here
    // only loses NAT-traversal candidates, not the (already-registered) tunnel.
    if !candidates.is_empty() {
        if let Err(e) = control
            .publish_candidates(&identity.public_key, candidates)
            .await
        {
            warn!("publishing NAT-traversal candidates failed: {e}");
        }
    }

    // Resolve the relay underlay: a local override wins, else whatever the
    // coordinator advertises for this network. Connect it once; the mesh runner
    // aligns its peer table from the map. `None` => direct-only.
    let relay = match relay {
        Some(addr) => Some(addr),
        None => control
            .advertised_relay(&identity.public_key)
            .await
            .unwrap_or(None),
    };
    let relay = match relay {
        Some(addr) => Some(connect_relay(&addr, private_key_b64).await?),
        None => None,
    };

    let mut stream = control.watch(&identity.public_key).await?;
    let (tx, rx) = mpsc::channel::<Vec<MeshPeer>>(8);

    let watch_client = client.clone();
    let priv_b64 = private_key_b64.to_string();
    let watcher = tokio::spawn(async move {
        loop {
            match stream.next().await {
                Ok(Some(specs)) => {
                    // Keep the facade's peer view + event stream fresh regardless
                    // of whether the specs build into sessions.
                    watch_client.apply_peers(specs.clone());
                    match build_mesh_peers(&priv_b64, &specs) {
                        Ok(peers) => {
                            if tx.send(peers).await.is_err() {
                                break; // data plane stopped
                            }
                        }
                        Err(e) => warn!("ignoring unusable network map: {e}"),
                    }
                }
                Ok(None) => break, // stream ended
                Err(e) => {
                    warn!("network-map stream error: {e}");
                    break;
                }
            }
        }
    });

    // Start the mesh empty; the watch stream delivers the current peer set
    // immediately, then updates as the network changes. With a relay configured
    // the mesh runs both underlays and selects per peer; otherwise direct only.
    let result = match relay {
        Some(relay) => run_mesh_relayed(device, transport, relay, Vec::new(), rx, shutdown).await,
        None => run_mesh(device, transport, Vec::new(), rx, shutdown).await,
    }
    .map_err(|e| Error::DataPlane(e.to_string()));

    watcher.abort();
    client.disconnect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ConnectionState;
    use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use ferrum_coordinator::{CoordinatorService, Registry};
    use ferrum_transport::UdpMeshTransport;
    use ferrum_tunnel::device::mock::MockTun;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    async fn start_coordinator() -> String {
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinatorServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn build_mesh_peers_rejects_a_bad_endpoint() {
        let me = ferrum_core::keys::KeyPair::generate();
        let peer = ferrum_core::keys::KeyPair::generate();
        let specs = vec![PeerSpec {
            public_key: peer.public_base64(),
            endpoint: "not-an-addr".into(),
            allowed_ips: vec!["10.8.0.3/32".into()],
            candidates: vec![],
        }];
        let result = build_mesh_peers(&me.private_base64(), &specs);
        assert!(matches!(result, Err(Error::DataPlane(_))));
    }

    #[test]
    fn build_mesh_peers_builds_a_session_per_peer() {
        let me = ferrum_core::keys::KeyPair::generate();
        let p1 = ferrum_core::keys::KeyPair::generate();
        let p2 = ferrum_core::keys::KeyPair::generate();
        let specs = vec![
            PeerSpec {
                public_key: p1.public_base64(),
                endpoint: "127.0.0.1:51820".into(),
                allowed_ips: vec!["10.8.0.3/32".into()],
                candidates: vec![],
            },
            PeerSpec {
                public_key: p2.public_base64(),
                endpoint: "127.0.0.1:51821".into(),
                allowed_ips: vec!["10.8.0.4/32".into()],
                candidates: vec![],
            },
        ];
        let peers = build_mesh_peers(&me.private_base64(), &specs).unwrap();
        assert_eq!(peers.len(), 2);
    }

    /// The runner registers (driving the facade to `Connected`), reflects a peer
    /// that joins later into the facade's peer view via the watch stream, and
    /// returns to `Disconnected` on shutdown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_mesh_session_connects_then_tracks_live_peers() {
        let url = start_coordinator().await;

        let me = ferrum_core::keys::KeyPair::generate();
        let device = MockTun::default();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpMeshTransport::from_socket(sock);

        let client = FerrumClient::new();
        let identity = ClientIdentity {
            public_key: me.public_base64(),
            name: "node-a".into(),
            endpoint: "127.0.0.1:51820".into(),
            tags: vec![],
        };

        // Run the data plane in the background; a oneshot drives its shutdown.
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let runner_client = client.clone();
        let priv_b64 = me.private_base64();
        let url_runner = url.clone();
        let handle = tokio::spawn(async move {
            run_mesh_session(
                &runner_client,
                &url_runner,
                &identity,
                &priv_b64,
                &[],
                device,
                transport,
                None,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });

        // Facade reaches Connected with the coordinator-assigned address.
        wait_for(Duration::from_secs(5), || {
            client.status() == ConnectionState::Connected && client.address().is_some()
        })
        .await;
        assert_eq!(client.address().as_deref(), Some("10.8.0.2/32"));
        assert!(client.peers().is_empty(), "no peers yet");

        // A second device registers. Its endpoint is a real (drained) socket so
        // handshake sends don't hit a dead port — avoids the Windows
        // ICMP/WSAECONNRESET gotcha. `_sink` stays bound for the test's lifetime.
        let _sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = _sink.local_addr().unwrap();
        let peer = ferrum_core::keys::KeyPair::generate();
        let mut b = ControlClient::connect(url.clone()).await.unwrap();
        b.register(&peer.public_base64(), "node-b", &sink_addr.to_string(), &[])
            .await
            .unwrap();

        // The watch push reflects B into our facade peer view.
        wait_for(Duration::from_secs(5), || client.peers().len() == 1).await;
        assert_eq!(client.peers()[0].public_key, peer.public_base64());

        // Shutting down the data plane returns the facade to Disconnected.
        let _ = stop_tx.send(());
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("runner did not stop")
            .expect("runner task panicked");
        assert!(result.is_ok(), "runner returned error: {result:?}");
        assert_eq!(client.status(), ConnectionState::Disconnected);
    }

    /// Candidates handed to `run_mesh_session` are published to the coordinator
    /// and surface in a peer's view of this device (closing the Phase 4 M2 loop:
    /// gather -> publish -> peer learns the path to probe).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_mesh_session_publishes_candidates_to_peers() {
        let url = start_coordinator().await;

        let me = ferrum_core::keys::KeyPair::generate();
        let device = MockTun::default();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpMeshTransport::from_socket(sock);

        let client = FerrumClient::new();
        let identity = ClientIdentity {
            public_key: me.public_base64(),
            name: "node-a".into(),
            endpoint: "127.0.0.1:51820".into(),
            tags: vec![],
        };
        let candidates = vec!["203.0.113.5:51820".to_string()];

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let runner_client = client.clone();
        let priv_b64 = me.private_base64();
        let url_runner = url.clone();
        let cands = candidates.clone();
        let handle = tokio::spawn(async move {
            run_mesh_session(
                &runner_client,
                &url_runner,
                &identity,
                &priv_b64,
                &cands,
                device,
                transport,
                None,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });

        wait_for(Duration::from_secs(5), || {
            client.status() == ConnectionState::Connected
        })
        .await;

        // A peer B registers and reads the network map: A's published candidate
        // is visible on A's entry.
        let peer = ferrum_core::keys::KeyPair::generate();
        let mut b = ControlClient::connect(url.clone()).await.unwrap();
        b.register(&peer.public_base64(), "node-b", "127.0.0.1:51999", &[])
            .await
            .unwrap();

        // Poll the map until A's candidate appears (publish + broadcast are async).
        let mut seen = vec![];
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            let peers = b.network_map(&peer.public_base64()).await.unwrap();
            if let Some(a) = peers.iter().find(|p| p.public_key == me.public_base64()) {
                if !a.candidates.is_empty() {
                    seen = a.candidates.clone();
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(seen, candidates, "peer should see A's published candidate");

        let _ = stop_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    /// Poll `cond` until it holds or `timeout` elapses.
    async fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("condition not met within {timeout:?}");
    }
}
