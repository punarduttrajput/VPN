//! Data-plane glue (Phase 5): drive the OS mesh data plane from the facade.
//!
//! [`VpnClient`](crate::VpnClient) owns the *control* side — registration, state,
//! the peer view, the event stream. This module connects it to the *data* side
//! ([`vpn_tunnel::run_mesh`]): a native shell (or the CLI) supplies an opened TUN
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

use vpn_core::config::Cidr;
use vpn_transport::MeshTransport;
use vpn_tunnel::device::TunDevice;
use vpn_tunnel::session::Session;
use vpn_tunnel::{run_mesh, MeshPeer};

use crate::client::VpnClient;
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
    let priv_bytes = vpn_core::keys::decode_key(private_key_b64)
        .map_err(|e| Error::DataPlane(format!("decoding private key: {e}")))?;
    peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let pub_bytes = vpn_core::keys::decode_key(&p.public_key)
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
            // Local session indices must be distinct per peer; +1 keeps them non-zero.
            let session = Session::from_bytes(priv_bytes, pub_bytes, (i as u32) + 1)
                .map_err(|e| Error::DataPlane(format!("session for '{}': {e}", p.public_key)))?;
            Ok(MeshPeer {
                session,
                endpoint,
                allowed_ips,
            })
        })
        .collect()
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
/// `private_key_b64` is this device's WireGuard private key, used to build the
/// per-peer sessions (it is never sent to the coordinator).
pub async fn run_mesh_session<D, M, F>(
    client: &VpnClient,
    coordinator: &str,
    identity: &ClientIdentity,
    private_key_b64: &str,
    device: D,
    transport: M,
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
    // immediately, then updates as the network changes.
    let result = run_mesh(device, transport, Vec::new(), rx, shutdown)
        .await
        .map_err(|e| Error::DataPlane(e.to_string()));

    watcher.abort();
    client.disconnect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ConnectionState;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use vpn_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use vpn_coordinator::{CoordinatorService, Registry};
    use vpn_transport::UdpMeshTransport;
    use vpn_tunnel::device::mock::MockTun;

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
        let me = vpn_core::keys::KeyPair::generate();
        let peer = vpn_core::keys::KeyPair::generate();
        let specs = vec![PeerSpec {
            public_key: peer.public_base64(),
            endpoint: "not-an-addr".into(),
            allowed_ips: vec!["10.8.0.3/32".into()],
        }];
        let result = build_mesh_peers(&me.private_base64(), &specs);
        assert!(matches!(result, Err(Error::DataPlane(_))));
    }

    #[test]
    fn build_mesh_peers_builds_a_session_per_peer() {
        let me = vpn_core::keys::KeyPair::generate();
        let p1 = vpn_core::keys::KeyPair::generate();
        let p2 = vpn_core::keys::KeyPair::generate();
        let specs = vec![
            PeerSpec {
                public_key: p1.public_base64(),
                endpoint: "127.0.0.1:51820".into(),
                allowed_ips: vec!["10.8.0.3/32".into()],
            },
            PeerSpec {
                public_key: p2.public_base64(),
                endpoint: "127.0.0.1:51821".into(),
                allowed_ips: vec!["10.8.0.4/32".into()],
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

        let me = vpn_core::keys::KeyPair::generate();
        let device = MockTun::default();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpMeshTransport::from_socket(sock);

        let client = VpnClient::new();
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
                device,
                transport,
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
        let peer = vpn_core::keys::KeyPair::generate();
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
