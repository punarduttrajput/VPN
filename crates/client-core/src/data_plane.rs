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
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use ferrum_core::config::Cidr;
use ferrum_transport::fingerprint::parse_fingerprint;
use ferrum_transport::{MeshTransport, RelayMeshTransport};
use ferrum_tunnel::device::TunDevice;
use ferrum_tunnel::session::Session;
use ferrum_tunnel::{run_mesh, run_mesh_relayed, MeshPeer};

use crate::client::FerrumClient;
use crate::{ClientIdentity, Error, PeerSpec, ReconnectPolicy};

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
            // The peer's registered TLS cert pin (SEC-004), for a QUIC dial. A
            // malformed pin is dropped (that peer is dialed unpinned, with the
            // transport's warning) rather than failing the whole mesh.
            let tls_pins = match p.tls_cert_sha256.as_str() {
                "" => Vec::new(),
                pin => match parse_fingerprint(pin) {
                    Ok(fp) => vec![fp],
                    Err(e) => {
                        warn!(peer = %p.public_key, "ignoring peer's TLS pin: {e}");
                        Vec::new()
                    }
                },
            };
            Ok(
                MeshPeer::with_candidates(session, endpoint, allowed_ips, candidates)
                    .with_tls_pins(tls_pins),
            )
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
    // Publish the TLS pin of the transport actually carrying this session
    // (SEC-004) — derived from the key the shell bound it with — rather than
    // trusting a separately-set value that could lag a key rotation. Non-TLS
    // transports publish none.
    client.set_tls_fingerprint(
        transport
            .tls_fingerprint()
            .map(|fp| ferrum_transport::fingerprint::fingerprint_hex(&fp)),
    );
    // Control-plane connect: registers, loads the initial peer view, and drives
    // the facade Connecting -> Connected (or -> Failed, returning the error).
    client.connect(coordinator, identity).await?;

    // A second channel carries live map updates into both the mesh and the facade.
    // It authenticates with the same bearer token as the facade's own channel, so
    // an OIDC-protected coordinator accepts the watch/publish/relay-lookup RPCs.
    let mut control = client.control(coordinator.to_string()).await?;

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

    // Surface the coordinator-advertised DNS resolvers (PRD leak-protection.md
    // M1). Enforcement (pointing system DNS at them + the leak-guard firewall)
    // lands in M2/M3; until then this is observability so an operator can see
    // what the network advertises — and that DNS is unprotected either way.
    match control
        .advertised_dns(&identity.public_key)
        .await
        .unwrap_or(None)
    {
        Some(dns) => info!(
            ?dns,
            "coordinator advertises DNS resolvers (not yet enforced — leak-protection M2)"
        ),
        None => info!("coordinator advertises no DNS resolvers; DNS is unprotected"),
    }

    // Resolve the relay underlay: a local override wins, else whatever the
    // coordinator advertises for this network. Connect it once; the mesh runner
    // aligns its peer table from the map. `None` => direct-only.
    //
    // When the relay came from the coordinator's advertisement (no local
    // override), the session also *tracks* it: the coordinator can retarget
    // the advertisement live — a relay drains, dies, or a first one scales
    // out (PRD `phase-6-anycast-autoscaling.md` FR3) — and the watch stream
    // pushes the change. The session then ends with an error so the
    // supervisor rebuilds it against the newly-advertised relay.
    let local_override = relay.is_some();
    let relay = match relay {
        Some(addr) => Some(addr),
        None => control
            .advertised_relay(&identity.public_key)
            .await
            .unwrap_or(None),
    };
    let tracked_relay = (!local_override).then(|| relay.clone());
    let relay = match relay {
        Some(addr) => Some(connect_relay(&addr, private_key_b64).await?),
        None => None,
    };

    let mut stream = control.watch(&identity.public_key).await?;
    let (tx, rx) = mpsc::channel::<Vec<MeshPeer>>(8);
    // Fired by the watcher when the advertised relay no longer matches the one
    // this session connected to; ends the mesh loop below.
    let relay_changed = Arc::new(tokio::sync::Notify::new());

    let watch_client = client.clone();
    let priv_b64 = private_key_b64.to_string();
    let relay_changed_tx = relay_changed.clone();
    let watcher = tokio::spawn(async move {
        loop {
            match stream.next_update().await {
                Ok(Some(update)) => {
                    // Keep the facade's peer view + event stream fresh regardless
                    // of whether the specs build into sessions.
                    watch_client.apply_peers(update.peers.clone());
                    if let Some(connected) = &tracked_relay {
                        if update.relay != *connected {
                            info!(
                                had_relay = connected.is_some(),
                                has_relay = update.relay.is_some(),
                                "coordinator retargeted the advertised relay; session will restart"
                            );
                            relay_changed_tx.notify_one();
                            break;
                        }
                    }
                    match build_mesh_peers(&priv_b64, &update.peers) {
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

    // The mesh ends on the caller's shutdown *or* on a relay retarget; the two
    // are told apart afterwards so a retarget surfaces as a restartable error.
    let retarget = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mesh_shutdown = {
        let relay_changed = relay_changed.clone();
        let retarget = retarget.clone();
        async move {
            tokio::select! {
                _ = shutdown => {}
                _ = relay_changed.notified() => {
                    retarget.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    };

    // Start the mesh empty; the watch stream delivers the current peer set
    // immediately, then updates as the network changes. With a relay configured
    // the mesh runs both underlays and selects per peer; otherwise direct only.
    let result = match relay {
        Some(relay) => {
            run_mesh_relayed(device, transport, relay, Vec::new(), rx, mesh_shutdown).await
        }
        None => run_mesh(device, transport, Vec::new(), rx, mesh_shutdown).await,
    }
    .map_err(|e| Error::DataPlane(e.to_string()));

    watcher.abort();
    client.disconnect();
    if result.is_ok() && retarget.load(std::sync::atomic::Ordering::Relaxed) {
        // A clean end we caused ourselves: report it as an error so the
        // supervisor restarts the session against the new advertised relay
        // (rather than treating it as the caller's shutdown and exiting).
        return Err(Error::DataPlane(
            "advertised relay changed; restarting session to retarget".into(),
        ));
    }
    result
}

/// Run a **self-healing** mesh session (Phase 5 FR5): keep a working
/// [`run_mesh_session`] alive, automatically restarting it with exponential
/// backoff whenever it drops, until `shutdown` resolves.
///
/// This is the data-plane half of "always-on": where
/// [`FerrumClient::connect_with_retry`](crate::FerrumClient::connect_with_retry)
/// reconnects the *control plane*, this reruns the whole mesh session — control
/// sync **and** the OS data plane — so a coordinator outage, a dropped watch
/// stream, or a transport failure all recover on their own.
///
/// Because a session **consumes** its TUN device and transport (and an OS TUN fd
/// is closed when its [`TunDevice`] drops — see
/// [`ferrum_tunnel::device::from_fd`]), the caller supplies *factories* rather
/// than values: `make_device`/`make_transport` are invoked to build a fresh pair
/// for each attempt. A native shell's factory re-acquires its OS TUN (e.g. a new
/// `NEPacketTunnelProvider`/`VpnService` fd) and rebinds its socket; the CLI's
/// reopens `/dev/net/tun` and rebinds. A factory error is treated like a session
/// failure (it counts against the retry budget and backs off).
///
/// Backoff follows `policy` (see [`ReconnectPolicy`]): it escalates on consecutive
/// failures and resets after a session that had come up and then ended, so a long
/// healthy tunnel that briefly drops reconnects promptly rather than after a grown
/// delay. With `policy.max_retries == 0` it retries forever (the always-on case);
/// otherwise it returns the last error once the budget is exhausted. The backoff
/// wait and an in-flight session are both interrupted promptly by `shutdown`, and
/// the facade is moved to `Reconnecting` between attempts.
// Eleven parameters: the same independent inputs as `run_mesh_session` with the
// device/transport replaced by factories, plus the retry policy. Grouping them
// into a struct would only move the noise across the boundary, so allow the lint.
#[allow(clippy::too_many_arguments)]
pub async fn run_mesh_session_supervised<D, M, MkD, MkM, FutD, FutM, F>(
    client: &FerrumClient,
    coordinator: &str,
    identity: &ClientIdentity,
    private_key_b64: &str,
    candidates: &[String],
    mut make_device: MkD,
    mut make_transport: MkM,
    relay: Option<String>,
    policy: &ReconnectPolicy,
    shutdown: F,
) -> Result<(), Error>
where
    D: TunDevice + Send + 'static,
    M: MeshTransport + Send + 'static,
    MkD: FnMut() -> FutD + Send,
    MkM: FnMut() -> FutM + Send,
    FutD: Future<Output = Result<D, Error>> + Send,
    FutM: Future<Output = Result<M, Error>> + Send,
    F: Future<Output = ()> + Send,
{
    // `stop` is flipped true once `shutdown` resolves. Each session derives its
    // own shutdown future from a clone, so the same external signal tears down
    // whichever session is currently running — without spawning a task (which
    // would force a `'static` bound on `shutdown`).
    let (stop, watch_stop) = tokio::sync::watch::channel(false);
    tokio::pin!(shutdown);

    let mut attempt: u32 = 0;
    let mut backoff = policy.initial_backoff_ms.max(1);

    loop {
        if *watch_stop.borrow() {
            return Ok(());
        }

        // Build a fresh device + transport for this attempt.
        let built = async {
            let device = make_device().await?;
            let transport = make_transport().await?;
            Ok::<_, Error>((device, transport))
        }
        .await;

        let outcome: Result<(), Error> = match built {
            Ok((device, transport)) => {
                let mut session_stop = watch_stop.clone();
                let session_shutdown = async move {
                    let _ = session_stop.wait_for(|stop| *stop).await;
                };
                let session = run_mesh_session(
                    client,
                    coordinator,
                    identity,
                    private_key_b64,
                    candidates,
                    device,
                    transport,
                    relay.clone(),
                    session_shutdown,
                );
                tokio::pin!(session);
                tokio::select! {
                    // External shutdown: signal the running session, let it clean
                    // up (abort its watcher, return the facade to Disconnected),
                    // then we're done.
                    _ = &mut shutdown => {
                        let _ = stop.send(true);
                        let _ = (&mut session).await;
                        return Ok(());
                    }
                    // The session ended on its own (error, or the watch stream
                    // closed) — fall through to backoff + restart.
                    r = &mut session => r,
                }
            }
            Err(e) => {
                client.emit_error(e.to_string());
                Err(e)
            }
        };

        let failed = outcome.is_err();
        match outcome {
            // A session that came up and then ended: reconnect promptly with a
            // fresh budget rather than a backoff grown by earlier failures.
            Ok(()) => {
                attempt = 0;
                backoff = policy.initial_backoff_ms.max(1);
            }
            Err(e) => {
                attempt += 1;
                if policy.max_retries != 0 && attempt > policy.max_retries {
                    return Err(e);
                }
            }
        }

        client.mark_reconnecting();

        // Interruptible backoff before the next attempt.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(backoff)) => {}
            _ = &mut shutdown => {
                let _ = stop.send(true);
                return Ok(());
            }
        }

        // Escalate the delay only after a genuine failure.
        if failed {
            backoff = backoff.saturating_mul(2).min(policy.max_backoff_ms.max(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ConnectionState;
    use crate::ControlClient;
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
            tls_cert_sha256: String::new(),
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
                tls_cert_sha256: String::new(),
            },
            PeerSpec {
                public_key: p2.public_base64(),
                endpoint: "127.0.0.1:51821".into(),
                allowed_ips: vec!["10.8.0.4/32".into()],
                candidates: vec![],
                tls_cert_sha256: String::new(),
            },
        ];
        let peers = build_mesh_peers(&me.private_base64(), &specs).unwrap();
        assert_eq!(peers.len(), 2);
    }

    /// SEC-004: a peer's coordinator-advertised TLS pin becomes its mesh pin; a
    /// malformed one is dropped (dialed unpinned) rather than failing the mesh.
    #[test]
    fn build_mesh_peers_carries_tls_pins() {
        let me = ferrum_core::keys::KeyPair::generate();
        let spec = |pin: &str| PeerSpec {
            public_key: ferrum_core::keys::KeyPair::generate().public_base64(),
            endpoint: "127.0.0.1:51820".into(),
            allowed_ips: vec!["10.8.0.3/32".into()],
            candidates: vec![],
            tls_cert_sha256: pin.into(),
        };
        let specs = [spec(&"ab".repeat(32)), spec("garbage"), spec("")];
        let peers = build_mesh_peers(&me.private_base64(), &specs).unwrap();
        assert_eq!(peers[0].tls_pins, vec![[0xab; 32]]);
        assert!(peers[1].tls_pins.is_empty(), "malformed pin dropped");
        assert!(peers[2].tls_pins.is_empty());
    }

    /// SEC-004: a pin set on the facade is published at registration and
    /// reaches another device's peer view.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_fingerprint_is_published_to_peers() {
        let url = start_coordinator().await;
        let a = crate::FerrumClient::new();
        a.set_tls_fingerprint(Some("12".repeat(32)));
        let a_id = crate::ClientIdentity {
            public_key: ferrum_core::keys::KeyPair::generate().public_base64(),
            name: "a".into(),
            endpoint: "127.0.0.1:51820".into(),
            tags: vec![],
        };
        a.connect(url.clone(), &a_id).await.unwrap();

        let mut b = ControlClient::connect(url).await.unwrap();
        let b_key = ferrum_core::keys::KeyPair::generate().public_base64();
        b.register(&b_key, "b", "127.0.0.1:51821", &[])
            .await
            .unwrap();
        let peers = b.network_map(&b_key).await.unwrap();
        let seen = peers
            .iter()
            .find(|p| p.public_key == a_id.public_key)
            .unwrap();
        assert_eq!(seen.tls_cert_sha256, "12".repeat(32));
    }

    /// The runner registers (driving the facade to `Connected`), reflects a peer
    /// that joins later into the facade's peer view via the watch stream, and
    /// returns to `Disconnected` on shutdown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_publishes_its_transports_pin_not_a_stale_one() {
        // Review fix: the session publishes what its transport reports, so a
        // pin left over on the facade (e.g. from before a key rotation) can't
        // be advertised. A UDP transport has no TLS identity: it clears it.
        let url = start_coordinator().await;
        let me = ferrum_core::keys::KeyPair::generate();
        let client = FerrumClient::new();
        client.set_tls_fingerprint(Some("ab".repeat(32))); // stale
        let identity = ClientIdentity {
            public_key: me.public_base64(),
            name: "node-a".into(),
            endpoint: "127.0.0.1:51820".into(),
            tags: vec![],
        };
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (runner, url_runner, priv_b64) = (client.clone(), url.clone(), me.private_base64());
        let id = identity.clone();
        let handle = tokio::spawn(async move {
            run_mesh_session(
                &runner,
                &url_runner,
                &id,
                &priv_b64,
                &[],
                MockTun::default(),
                UdpMeshTransport::from_socket(sock),
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

        let mut b = ControlClient::connect(url).await.unwrap();
        let b_key = ferrum_core::keys::KeyPair::generate().public_base64();
        b.register(&b_key, "b", "127.0.0.1:51821", &[])
            .await
            .unwrap();
        let peers = b.network_map(&b_key).await.unwrap();
        let seen = peers
            .iter()
            .find(|p| p.public_key == identity.public_key)
            .unwrap();
        assert_eq!(seen.tls_cert_sha256, "", "stale pin must not be published");

        let _ = stop_tx.send(());
        let _ = handle.await;
    }

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

    fn node_identity(me: &ferrum_core::keys::KeyPair) -> ClientIdentity {
        ClientIdentity {
            public_key: me.public_base64(),
            name: "node-a".into(),
            endpoint: "127.0.0.1:51820".into(),
            tags: vec![],
        }
    }

    /// When the session's relay came from the coordinator's advertisement (no
    /// local override) and the advertisement changes — here: a first relay
    /// scales out and heartbeats — the session ends with a restartable error
    /// so the supervisor rebuilds it against the new relay (PRD
    /// `phase-6-anycast-autoscaling.md` FR3).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_mesh_session_restarts_when_advertised_relay_changes() {
        let url = start_coordinator().await;

        let me = ferrum_core::keys::KeyPair::generate();
        let device = MockTun::default();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpMeshTransport::from_socket(sock);

        let client = FerrumClient::new();
        let identity = node_identity(&me);

        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
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
                None, // no local override: the advertised relay is tracked
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

        // `Connected` fires before the session resolves the advertised relay
        // and opens its watch stream; a heartbeat landing in that window would
        // be resolved at startup (correct, but no retarget to observe). Prove
        // the watch stream is live first: a registering peer must show up in
        // the facade's peer view, which only the watch stream updates.
        let _sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = ferrum_core::keys::KeyPair::generate();
        let mut b = ControlClient::connect(url.clone()).await.unwrap();
        b.register(
            &peer.public_base64(),
            "node-b",
            &_sink.local_addr().unwrap().to_string(),
            &[],
        )
        .await
        .unwrap();
        wait_for(Duration::from_secs(5), || client.peers().len() == 1).await;

        // A relay announces itself: the advertisement goes (none) -> addr, the
        // watch push delivers it, and the session ends asking for a restart.
        let mut relay_ctl = ControlClient::connect(url.clone()).await.unwrap();
        relay_ctl
            .relay_heartbeat("127.0.0.1:51899", false)
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("session did not end on relay retarget")
            .expect("runner task panicked");
        let err = result.expect_err("session should end with a restartable error");
        assert!(
            err.to_string().contains("advertised relay changed"),
            "unexpected error: {err}"
        );
        assert_eq!(client.status(), ConnectionState::Disconnected);
    }

    /// The supervisor retries a failing data-plane build with backoff and reaches
    /// `Connected` once the build succeeds, then stops cleanly on shutdown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervised_retries_until_the_data_plane_builds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let url = start_coordinator().await;
        let me = ferrum_core::keys::KeyPair::generate();
        let identity = node_identity(&me);
        let policy = ReconnectPolicy {
            max_retries: 0, // forever
            initial_backoff_ms: 10,
            max_backoff_ms: 10,
        };

        // The transport factory fails its first two calls, then succeeds — so the
        // supervisor must retry before a session can come up.
        let tries = Arc::new(AtomicUsize::new(0));
        let tries_f = tries.clone();
        let make_transport = move || {
            let tries = tries_f.clone();
            async move {
                if tries.fetch_add(1, Ordering::SeqCst) < 2 {
                    Err(Error::DataPlane("transport not ready".into()))
                } else {
                    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    Ok(UdpMeshTransport::from_socket(sock))
                }
            }
        };
        let make_device = || async { Ok::<MockTun, Error>(MockTun::default()) };

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let client = FerrumClient::new();
        let runner_client = client.clone();
        let priv_b64 = me.private_base64();
        let url_runner = url.clone();
        let handle = tokio::spawn(async move {
            run_mesh_session_supervised(
                &runner_client,
                &url_runner,
                &identity,
                &priv_b64,
                &[],
                make_device,
                make_transport,
                None,
                &policy,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });

        // It eventually comes up despite the early build failures.
        wait_for(Duration::from_secs(5), || {
            client.status() == ConnectionState::Connected
        })
        .await;
        assert!(
            tries.load(Ordering::SeqCst) >= 3,
            "transport should have been retried before succeeding"
        );

        // Shutdown winds the supervisor down to Disconnected with an Ok result.
        let _ = stop_tx.send(());
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor did not stop")
            .expect("task panicked");
        assert!(
            result.is_ok(),
            "clean shutdown should return Ok: {result:?}"
        );
        assert_eq!(client.status(), ConnectionState::Disconnected);
    }

    /// With a bounded retry budget and a build that always fails, the supervisor
    /// gives up after `max_retries + 1` attempts and returns the last error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervised_gives_up_after_exhausting_retries() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let me = ferrum_core::keys::KeyPair::generate();
        let identity = node_identity(&me);
        let policy = ReconnectPolicy {
            max_retries: 2, // 3 attempts total
            initial_backoff_ms: 5,
            max_backoff_ms: 5,
        };

        let tries = Arc::new(AtomicUsize::new(0));
        let tries_f = tries.clone();
        let make_transport = move || {
            let tries = tries_f.clone();
            async move {
                tries.fetch_add(1, Ordering::SeqCst);
                Err::<UdpMeshTransport, Error>(Error::DataPlane("always down".into()))
            }
        };
        let make_device = || async { Ok::<MockTun, Error>(MockTun::default()) };

        let client = FerrumClient::new();
        // The coordinator is never reached — the transport build fails first.
        let result = run_mesh_session_supervised(
            &client,
            "http://127.0.0.1:1",
            &identity,
            &me.private_base64(),
            &[],
            make_device,
            make_transport,
            None,
            &policy,
            std::future::pending::<()>(),
        )
        .await;

        assert!(result.is_err(), "exhausted retries should return the error");
        assert_eq!(
            tries.load(Ordering::SeqCst),
            3,
            "should attempt max_retries + 1 times"
        );
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
