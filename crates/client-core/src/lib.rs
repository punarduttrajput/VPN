//! Client-side control-plane integration (PRD Phase 3, FR6 / Phase 5 client-core).
//!
//! [`ControlClient`] talks to the coordinator over gRPC: it registers the device
//! (receiving an assigned tunnel address) and fetches the network map of peers it
//! may reach, turning that into a [`TunnelPlan`] the data plane can apply.
//!
//! This is the bridge from the control plane (Phase 3) to the data plane
//! (Phases 1–2): a `TunnelPlan` lists the peers, their endpoints, and allowed IPs
//! that a `vpn-tunnel` session would be configured from. Applying a multi-peer
//! plan to the running tunnel (mesh) is a later increment; today the data plane
//! is point-to-point.
#![forbid(unsafe_code)]

use thiserror::Error;
use tonic::transport::Channel;
use vpn_control_proto::coordinator::coordinator_client::CoordinatorClient;
use vpn_control_proto::coordinator::{NetworkMapRequest, RegisterDeviceRequest};

/// Errors talking to the coordinator.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to establish the gRPC channel.
    #[error("control transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// The coordinator returned an RPC error.
    #[error("control rpc error: {0}")]
    Rpc(#[from] tonic::Status),
}

/// One peer the device may reach, as derived from the network map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpec {
    /// Peer's base64 public key.
    pub public_key: String,
    /// Peer's reachable endpoint `ip:port`.
    pub endpoint: String,
    /// CIDRs routed to this peer.
    pub allowed_ips: Vec<String>,
}

/// The tunnel configuration derived from the control plane for this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPlan {
    /// Assigned tunnel address (e.g. `10.8.0.2/32`).
    pub address: String,
    /// Peers this device may reach.
    pub peers: Vec<PeerSpec>,
}

/// A client connection to the coordinator.
pub struct ControlClient {
    inner: CoordinatorClient<Channel>,
}

impl ControlClient {
    /// Connect to the coordinator at `endpoint` (e.g. `http://10.0.0.1:50051`).
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, Error> {
        let inner = CoordinatorClient::connect(endpoint.into()).await?;
        Ok(Self { inner })
    }

    /// Connect over mutual TLS: trust `ca_pem`, present the client identity
    /// (`client_cert_pem` / `client_key_pem`), and verify the server against
    /// `domain` (its certificate SAN). Endpoint should be `https://…`.
    #[cfg(feature = "mtls")]
    pub async fn connect_mtls(
        endpoint: impl Into<String>,
        ca_pem: &str,
        client_cert_pem: &str,
        client_key_pem: &str,
        domain: &str,
    ) -> Result<Self, Error> {
        use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
        // tonic builds rustls configs that need a process-default provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca_pem))
            .identity(Identity::from_pem(client_cert_pem, client_key_pem))
            .domain_name(domain.to_string());
        let channel = Channel::from_shared(endpoint.into())
            .map_err(|e| Error::Rpc(tonic::Status::invalid_argument(e.to_string())))?
            .tls_config(tls)?
            .connect()
            .await?;
        Ok(Self {
            inner: CoordinatorClient::new(channel),
        })
    }

    /// Register (or re-register) this device; returns the assigned tunnel CIDR.
    pub async fn register(
        &mut self,
        public_key: &str,
        name: &str,
        endpoint: &str,
        tags: &[String],
    ) -> Result<String, Error> {
        let resp = self
            .inner
            .register_device(RegisterDeviceRequest {
                public_key: public_key.to_string(),
                name: name.to_string(),
                endpoint: endpoint.to_string(),
                tags: tags.to_vec(),
            })
            .await?
            .into_inner();
        Ok(resp.assigned_cidr)
    }

    /// Fetch the peers this device may currently reach.
    pub async fn network_map(&mut self, public_key: &str) -> Result<Vec<PeerSpec>, Error> {
        let resp = self
            .inner
            .get_network_map(NetworkMapRequest {
                public_key: public_key.to_string(),
            })
            .await?
            .into_inner();
        Ok(resp
            .peers
            .into_iter()
            .map(|p| PeerSpec {
                public_key: p.public_key,
                endpoint: p.endpoint,
                allowed_ips: p.allowed_ips,
            })
            .collect())
    }

    /// Register then fetch the map, returning a ready-to-apply [`TunnelPlan`].
    pub async fn plan(
        &mut self,
        public_key: &str,
        name: &str,
        endpoint: &str,
        tags: &[String],
    ) -> Result<TunnelPlan, Error> {
        let address = self.register(public_key, name, endpoint, tags).await?;
        let peers = self.network_map(public_key).await?;
        Ok(TunnelPlan { address, peers })
    }

    /// Subscribe to live network-map updates: the current map immediately, then
    /// a fresh peer set whenever the network changes.
    pub async fn watch(&mut self, public_key: &str) -> Result<NetworkMapStream, Error> {
        let stream = self
            .inner
            .watch_network_map(NetworkMapRequest {
                public_key: public_key.to_string(),
            })
            .await?
            .into_inner();
        Ok(NetworkMapStream { inner: stream })
    }
}

/// A live stream of network-map updates from the coordinator.
pub struct NetworkMapStream {
    inner: tonic::Streaming<vpn_control_proto::coordinator::NetworkMapResponse>,
}

impl NetworkMapStream {
    /// Await the next peer set, or `None` when the stream ends.
    pub async fn next(&mut self) -> Result<Option<Vec<PeerSpec>>, Error> {
        match self.inner.message().await? {
            Some(resp) => Ok(Some(
                resp.peers
                    .into_iter()
                    .map(|p| PeerSpec {
                        public_key: p.public_key,
                        endpoint: p.endpoint,
                        allowed_ips: p.allowed_ips,
                    })
                    .collect(),
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use vpn_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use vpn_coordinator::{CoordinatorService, Registry};

    /// Start an in-process coordinator and return its `http://addr` URL.
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_registers_and_builds_plan_from_map() {
        let url = start_coordinator().await;
        let mut a = ControlClient::connect(url.clone()).await.unwrap();
        let mut b = ControlClient::connect(url).await.unwrap();

        // First device: assigned .2, no peers yet.
        let plan_a = a.plan("AAA", "laptop", "1.1.1.1:51820", &[]).await.unwrap();
        assert_eq!(plan_a.address, "10.8.0.2/32");
        assert!(plan_a.peers.is_empty());

        // Second device: assigned .3, sees A.
        let plan_b = b
            .plan("BBB", "gateway", "2.2.2.2:51820", &[])
            .await
            .unwrap();
        assert_eq!(plan_b.address, "10.8.0.3/32");
        assert_eq!(plan_b.peers.len(), 1);
        assert_eq!(plan_b.peers[0].public_key, "AAA");

        // A re-fetches its map and now sees B with its endpoint + allowed IPs.
        let peers_a = a.network_map("AAA").await.unwrap();
        assert_eq!(peers_a.len(), 1);
        assert_eq!(peers_a[0].public_key, "BBB");
        assert_eq!(peers_a[0].endpoint, "2.2.2.2:51820");
        assert_eq!(peers_a[0].allowed_ips, vec!["10.8.0.3/32".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch_pushes_live_updates_when_peer_joins() {
        use std::time::Duration;

        let url = start_coordinator().await;
        let mut a = ControlClient::connect(url.clone()).await.unwrap();
        let mut b = ControlClient::connect(url).await.unwrap();

        // A registers and starts watching; the initial map has no peers.
        a.register("AAA", "laptop", "1.1.1.1:51820", &[])
            .await
            .unwrap();
        let mut stream = a.watch("AAA").await.unwrap();
        let initial = stream.next().await.unwrap().unwrap();
        assert!(initial.is_empty(), "initial map has no peers");

        // B registers -> the coordinator pushes a fresh map to A's stream.
        b.register("BBB", "gateway", "2.2.2.2:51820", &[])
            .await
            .unwrap();
        let update = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("watch update timed out")
            .unwrap()
            .unwrap();
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].public_key, "BBB");
        assert_eq!(update[0].endpoint, "2.2.2.2:51820");
    }

    #[cfg(feature = "mtls")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_accepts_valid_client_and_rejects_wrong_ca() {
        use vpn_coordinator::pki;

        let pki = pki::generate().unwrap();

        // Coordinator requiring client certs signed by the CA.
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = pki::server_tls_config(&pki);
        tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(CoordinatorServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let url = format!("https://{addr}");

        // Correct CA + client identity: registration succeeds.
        let mut ok = ControlClient::connect_mtls(
            url.clone(),
            &pki.ca_pem,
            &pki.client_cert_pem,
            &pki.client_key_pem,
            "localhost",
        )
        .await
        .unwrap();
        assert_eq!(
            ok.register("AAA", "a", "1.1.1.1:51820", &[]).await.unwrap(),
            "10.8.0.2/32"
        );

        // Trusting the wrong CA: the server cert can't be verified -> failure
        // (whether at connect or on the first RPC).
        let other = pki::generate().unwrap();
        let bad_ok = match ControlClient::connect_mtls(
            url,
            &other.ca_pem,
            &pki.client_cert_pem,
            &pki.client_key_pem,
            "localhost",
        )
        .await
        {
            Ok(mut c) => c.register("BBB", "b", "2.2.2.2:51820", &[]).await.is_ok(),
            Err(_) => false,
        };
        assert!(!bad_ok, "client trusting the wrong CA must not succeed");
    }
}
