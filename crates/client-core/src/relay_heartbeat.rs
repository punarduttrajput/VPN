//! A relay's side of the coordinator relay registry (PRD
//! `phase-6-anycast-autoscaling.md` FR3) and, for a relay in a relay mesh,
//! its membership (PRD `relay-mesh.md` M2): heartbeat the coordinator and
//! adopt the sibling list each response carries.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum_transport::RelayServer;
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::ControlClient;

/// How long to wait before reconnecting after a failed heartbeat.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// What a relay announces to the coordinator.
pub struct Announce {
    /// Coordinator gRPC URL.
    pub coordinator: String,
    /// The relay's client-reachable address.
    pub advertise: String,
    /// OIDC bearer token for the RelayHeartbeat RPC, if the coordinator needs one.
    pub token: Option<String>,
    /// Mesh siblings configured statically (`--mesh-peer`); kept alongside the
    /// ones the coordinator lists.
    pub static_mesh_peers: Vec<SocketAddr>,
}

/// The mesh peers to use: the coordinator's list plus the static ones,
/// without this relay's own address and without duplicates.
fn merge_peers(listed: &[String], static_peers: &[SocketAddr], me: SocketAddr) -> Vec<SocketAddr> {
    let mut peers: Vec<SocketAddr> = static_peers.to_vec();
    for p in listed {
        match p.parse::<SocketAddr>() {
            Ok(addr) if addr != me && !peers.contains(&addr) => peers.push(addr),
            Ok(_) => {}
            Err(e) => warn!("relay heartbeat: ignoring a bad mesh peer from the coordinator: {e}"),
        }
    }
    peers.sort();
    peers
}

/// Keep `server` announced to the coordinator: heartbeat at the cadence the
/// coordinator directs, reconnecting with a flat backoff on any failure. A
/// relay in a mesh also sends its mesh address and adopts the sibling list
/// from every response. When `goodbye` fires (or the relay is seen draining),
/// send one `draining: true` heartbeat, which withdraws the relay from
/// advertisement at once, and return. If that can't be delivered, return
/// anyway: the coordinator withdraws the relay when its heartbeats lapse.
pub async fn run(announce: Announce, server: Arc<RelayServer>, goodbye: Arc<Notify>) {
    let mesh_addr = server.mesh_addr();
    let mesh_str = mesh_addr.map(|a| a.to_string()).unwrap_or_default();
    let mut interval = Duration::from_secs(15); // until the coordinator directs one

    loop {
        let mut control = match ControlClient::connect(announce.coordinator.clone()).await {
            Ok(c) => match &announce.token {
                Some(t) => c.with_token(t.clone()),
                None => c,
            },
            Err(e) => {
                if server.is_draining() {
                    warn!(
                        "relay heartbeat: coordinator unreachable for the draining goodbye ({e}); \
                         it will withdraw this relay on missed heartbeats"
                    );
                    return;
                }
                warn!("relay heartbeat: coordinator unreachable ({e}); retrying");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
                continue;
            }
        };
        loop {
            let draining = server.is_draining();
            match control
                .relay_heartbeat_mesh(&announce.advertise, &mesh_str, draining)
                .await
            {
                Ok(beat) => {
                    if draining {
                        info!("relay heartbeat: draining goodbye sent; coordinator withdrew us");
                        return;
                    }
                    if beat.interval_secs > 0 {
                        interval = Duration::from_secs(u64::from(beat.interval_secs));
                    }
                    if let Some(me) = mesh_addr {
                        let peers = merge_peers(&beat.mesh_peers, &announce.static_mesh_peers, me);
                        server.set_mesh_peers(peers).await;
                    }
                }
                Err(e) => {
                    warn!("relay heartbeat failed ({e}); reconnecting");
                    break; // reconnect via the outer loop
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = goodbye.notified() => {} // send the goodbye now
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use ferrum_coordinator::{CoordinatorService, Registry};
    use ferrum_core::keys::{decode_key, private_from_base64, KeyPair};
    use ferrum_transport::{MeshConfig, MeshTransport, RelayMeshTransport};
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    #[test]
    fn merged_peers_drop_self_and_duplicates() {
        let me: SocketAddr = "10.0.0.1:51822".parse().unwrap();
        let s: SocketAddr = "10.0.0.9:51822".parse().unwrap();
        let listed = [
            "10.0.0.3:51822".to_string(),
            "10.0.0.1:51822".into(),
            "10.0.0.9:51822".into(),
            "junk".into(),
            "10.0.0.2:51822".into(),
        ];
        let got = merge_peers(&listed, &[s], me);
        let want: Vec<SocketAddr> = ["10.0.0.2:51822", "10.0.0.3:51822", "10.0.0.9:51822"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(got, want);
    }

    async fn start_coordinator() -> String {
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry).with_relay_heartbeat_interval(1);
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

    /// A meshed relay that announces itself to `coordinator`.
    async fn start_relay(coordinator: &str) -> Arc<RelayServer> {
        let server = Arc::new(
            RelayServer::bind_with_mesh(
                "127.0.0.1:0".parse().unwrap(),
                MeshConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    peers: Vec::new(),
                    key: [5; 32],
                },
            )
            .await
            .unwrap(),
        );
        tokio::spawn({
            let server = server.clone();
            async move {
                let _ = server.serve().await;
            }
        });
        let advertise = server.local_addr().unwrap().to_string();
        tokio::spawn(run(
            Announce {
                coordinator: coordinator.to_string(),
                advertise,
                token: None,
                static_mesh_peers: Vec::new(),
            },
            server.clone(),
            Arc::new(Notify::new()),
        ));
        server
    }

    fn mesh_peers(server: &RelayServer) -> u64 {
        let text = server.metrics().render();
        text.lines()
            .find_map(|l| l.strip_prefix("ferrum_relay_mesh_peers "))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// PRD `relay-mesh.md` M2: two relays with no `--mesh-peer` learn each
    /// other from the coordinator, and then carry traffic between their
    /// clients.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relays_join_the_mesh_through_the_coordinator() {
        let coordinator = start_coordinator().await;
        let a = start_relay(&coordinator).await;
        let b = start_relay(&coordinator).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while mesh_peers(&a) != 1 || mesh_peers(&b) != 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "relays never learned each other"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let (px, py) = (KeyPair::generate(), KeyPair::generate());
        let sx = private_from_base64(&px.private_base64()).unwrap();
        let sy = private_from_base64(&py.private_base64()).unwrap();
        let kx = decode_key(&px.public_base64()).unwrap();
        let ky = decode_key(&py.public_base64()).unwrap();
        let hx: SocketAddr = "10.9.0.1:1".parse().unwrap();
        let hy: SocketAddr = "10.9.0.2:1".parse().unwrap();
        let x = RelayMeshTransport::connect(a.local_addr().unwrap(), &sx, &[(hy, ky)])
            .await
            .unwrap();
        let y = RelayMeshTransport::connect(b.local_addr().unwrap(), &sy, &[(hx, kx)])
            .await
            .unwrap();
        // Until A has heard of Y, X's frames are dropped: retry until one lands.
        let mut buf = [0u8; 256];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            x.send_to(hy, b"across the mesh").await.unwrap();
            if let Ok(Ok((n, from))) =
                tokio::time::timeout(Duration::from_millis(200), y.recv_from(&mut buf)).await
            {
                assert_eq!((&buf[..n], from), (&b"across the mesh"[..], hx));
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "nothing crossed the mesh"
            );
        }
    }
}
