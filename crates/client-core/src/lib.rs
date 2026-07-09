//! Client-side core (PRD Phase 3 FR6 + Phase 5 FR1).
//!
//! Two layers:
//! - [`ControlClient`] — the gRPC control-plane client: registers the device
//!   (receiving an assigned tunnel address) and fetches/streams the network map
//!   of peers it may reach, as a [`TunnelPlan`].
//! - [`FerrumClient`] — the high-level, FFI-ready facade the native shells drive
//!   (Phase 5): a connection state machine over [`ControlClient`] with a peer
//!   view and an event subscription. The OS data-plane bring-up (TUN +
//!   `run_mesh`) is supplied by each platform shell.
//!
//! The `uniffi` feature adds an FFI layer ([`ffi`]) that exposes the facade to
//! Swift/Kotlin; uniffi's generated scaffolding is `extern "C"` glue, so the
//! crate-wide `unsafe` ban is lifted only for that build (normal builds keep
//! `#![forbid(unsafe_code)]`).
#![cfg_attr(not(feature = "uniffi"), forbid(unsafe_code))]

pub mod client;
pub use client::{
    ClientEvent, ClientIdentity, ConnectionState, FerrumClient, PeerPath, PeerStatus,
    ReconnectPolicy,
};

#[cfg(feature = "uniffi")]
pub mod ffi;

#[cfg(feature = "data-plane")]
pub mod data_plane;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

use ferrum_control_proto::coordinator::coordinator_client::CoordinatorClient;
use ferrum_control_proto::coordinator::{
    NetworkMapRequest, PeerInfo, PublishCandidatesRequest, RegisterDeviceRequest, RotateKeyRequest,
};
use thiserror::Error;
use tonic::transport::Channel;

/// Convert a coordinator [`PeerInfo`] into the crate's [`PeerSpec`].
fn peer_spec_from_info(p: PeerInfo) -> PeerSpec {
    PeerSpec {
        public_key: p.public_key,
        endpoint: p.endpoint,
        allowed_ips: p.allowed_ips,
        candidates: p.candidates,
    }
}

/// Errors talking to the coordinator.
///
/// Exposed to FFI as a flat error (variant name + `Display` message), since the
/// wrapped tonic types aren't themselves FFI-representable.
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum Error {
    /// Failed to establish the gRPC channel.
    #[error("control transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// The coordinator returned an RPC error.
    #[error("control rpc error: {0}")]
    Rpc(#[from] tonic::Status),
    /// A data-plane / mesh-runner failure (peer build, TUN device, or transport).
    /// Only produced with the `data-plane` feature.
    #[error("data plane: {0}")]
    DataPlane(String),
}

/// One peer the device may reach, as derived from the network map.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PeerSpec {
    /// Peer's base64 public key.
    pub public_key: String,
    /// Peer's reachable endpoint `ip:port`.
    pub endpoint: String,
    /// CIDRs routed to this peer.
    pub allowed_ips: Vec<String>,
    /// Peer's published ICE candidates (host + STUN reflexive `ip:port`), for
    /// NAT traversal (PRD Phase 4). Empty until the peer publishes them.
    pub candidates: Vec<String>,
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
    /// Optional OIDC bearer token attached to every RPC (`authorization` header).
    token: Option<String>,
}

impl ControlClient {
    /// Connect to the coordinator at `endpoint` (e.g. `http://10.0.0.1:50051`).
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, Error> {
        let inner = CoordinatorClient::connect(endpoint.into()).await?;
        Ok(Self { inner, token: None })
    }

    /// Attach an OIDC bearer token sent as `authorization: Bearer <token>` on
    /// every request (required when the coordinator runs with OIDC auth on).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Wrap a message in a request, attaching the bearer token if one is set.
    fn request<T>(&self, message: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(message);
        if let Some(token) = &self.token {
            // A valid token is ASCII; a malformed one simply isn't attached and
            // the server will reject the unauthenticated call with a clear error.
            if let Ok(value) = format!("Bearer {token}").parse() {
                req.metadata_mut().insert("authorization", value);
            }
        }
        req
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
            token: None,
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
        let req = self.request(RegisterDeviceRequest {
            public_key: public_key.to_string(),
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            tags: tags.to_vec(),
        });
        let resp = self.inner.register_device(req).await?.into_inner();
        Ok(resp.assigned_cidr)
    }

    /// Fetch the peers this device may currently reach.
    pub async fn network_map(&mut self, public_key: &str) -> Result<Vec<PeerSpec>, Error> {
        let req = self.request(NetworkMapRequest {
            public_key: public_key.to_string(),
        });
        let resp = self.inner.get_network_map(req).await?.into_inner();
        Ok(resp.peers.into_iter().map(peer_spec_from_info).collect())
    }

    /// The relay fallback address (`ip:port`) the coordinator advertises to this
    /// network, or `None` if it advertises no relay (PRD Phase 4 NAT traversal).
    /// A device uses this as its relay underlay unless it has a local override.
    pub async fn advertised_relay(&mut self, public_key: &str) -> Result<Option<String>, Error> {
        let req = self.request(NetworkMapRequest {
            public_key: public_key.to_string(),
        });
        let resp = self.inner.get_network_map(req).await?.into_inner();
        Ok(Some(resp.relay).filter(|r| !r.is_empty()))
    }

    /// The DNS resolvers (bare IPs, reachable through the tunnel) the
    /// coordinator advertises to this network, or `None` if it advertises none
    /// (PRD leak-protection.md). A device points its system DNS at them while
    /// connected unless it has a local `[dns]` override — see
    /// [`resolve_dns_servers`].
    pub async fn advertised_dns(&mut self, public_key: &str) -> Result<Option<Vec<String>>, Error> {
        let req = self.request(NetworkMapRequest {
            public_key: public_key.to_string(),
        });
        let resp = self.inner.get_network_map(req).await?.into_inner();
        Ok(Some(resp.dns_servers).filter(|d| !d.is_empty()))
    }

    /// Publish this device's ICE candidates (host + STUN server-reflexive
    /// `ip:port` strings) so permitted peers can learn how to reach it for NAT
    /// traversal (PRD Phase 4). The device must already be registered;
    /// republishing replaces the previously published set.
    pub async fn publish_candidates(
        &mut self,
        public_key: &str,
        candidates: &[String],
    ) -> Result<(), Error> {
        let req = self.request(PublishCandidatesRequest {
            public_key: public_key.to_string(),
            candidates: candidates.to_vec(),
        });
        self.inner.publish_candidates(req).await?;
        Ok(())
    }

    /// Rotate this device's static public key (PRD Phase 3, FR3): tell the
    /// coordinator to move the device's registration from `old_public_key` to
    /// `new_public_key`, keeping its assigned tunnel IP, name, endpoint, tags, and
    /// candidates. Returns the (unchanged) assigned CIDR. The caller generates the
    /// new keypair locally and rebuilds its data plane with the new private key;
    /// peers learn the new key over their watch stream and re-handshake to it.
    pub async fn rotate_key(
        &mut self,
        old_public_key: &str,
        new_public_key: &str,
    ) -> Result<String, Error> {
        let req = self.request(RotateKeyRequest {
            old_public_key: old_public_key.to_string(),
            new_public_key: new_public_key.to_string(),
        });
        let resp = self.inner.rotate_key(req).await?.into_inner();
        Ok(resp.assigned_cidr)
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
        let req = self.request(NetworkMapRequest {
            public_key: public_key.to_string(),
        });
        let stream = self.inner.watch_network_map(req).await?.into_inner();
        Ok(NetworkMapStream { inner: stream })
    }
}

/// Resolve the DNS servers to use while connected (PRD leak-protection.md):
/// a non-empty local `[dns] servers` override wins, else the
/// coordinator-advertised list, else none — the same local-else-advertised
/// order as relay selection. An empty result means DNS is unprotected; callers
/// should surface that visibly.
pub fn resolve_dns_servers(
    local_override: &[String],
    advertised: Option<Vec<String>>,
) -> Vec<String> {
    if local_override.is_empty() {
        advertised.unwrap_or_default()
    } else {
        local_override.to_vec()
    }
}

/// A live stream of network-map updates from the coordinator.
pub struct NetworkMapStream {
    inner: tonic::Streaming<ferrum_control_proto::coordinator::NetworkMapResponse>,
}

impl NetworkMapStream {
    /// Await the next peer set, or `None` when the stream ends.
    pub async fn next(&mut self) -> Result<Option<Vec<PeerSpec>>, Error> {
        match self.inner.message().await? {
            Some(resp) => Ok(Some(
                resp.peers.into_iter().map(peer_spec_from_info).collect(),
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use ferrum_coordinator::{CoordinatorService, Registry};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    /// Start an in-process coordinator and return its `http://addr` URL.
    async fn start_coordinator() -> String {
        start_coordinator_with_relay("").await
    }

    /// Start an in-process coordinator advertising `relay` (empty for none).
    async fn start_coordinator_with_relay(relay: &str) -> String {
        start_coordinator_configured(relay, Vec::new()).await
    }

    /// Start an in-process coordinator advertising `relay` (empty for none)
    /// and `dns_servers` (empty for none).
    async fn start_coordinator_configured(relay: &str, dns_servers: Vec<String>) -> String {
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry)
            .with_relay(relay)
            .with_dns_servers(dns_servers);
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
    async fn advertised_relay_is_surfaced_to_clients() {
        let url = start_coordinator_with_relay("198.51.100.9:3478").await;
        let mut a = ControlClient::connect(url).await.unwrap();
        a.register("AAA", "laptop", "1.1.1.1:51820", &[])
            .await
            .unwrap();
        assert_eq!(
            a.advertised_relay("AAA").await.unwrap(),
            Some("198.51.100.9:3478".to_string())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn advertised_relay_is_none_when_coordinator_has_no_relay() {
        let url = start_coordinator().await; // no relay configured
        let mut a = ControlClient::connect(url).await.unwrap();
        a.register("AAA", "laptop", "1.1.1.1:51820", &[])
            .await
            .unwrap();
        assert_eq!(a.advertised_relay("AAA").await.unwrap(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn advertised_dns_is_surfaced_to_clients() {
        let url =
            start_coordinator_configured("", vec!["10.99.0.53".into(), "fd00::53".into()]).await;
        let mut a = ControlClient::connect(url).await.unwrap();
        a.register("AAA", "laptop", "1.1.1.1:51820", &[])
            .await
            .unwrap();
        assert_eq!(
            a.advertised_dns("AAA").await.unwrap(),
            Some(vec!["10.99.0.53".to_string(), "fd00::53".to_string()])
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn advertised_dns_is_none_when_coordinator_has_no_dns() {
        let url = start_coordinator().await; // no DNS configured
        let mut a = ControlClient::connect(url).await.unwrap();
        a.register("AAA", "laptop", "1.1.1.1:51820", &[])
            .await
            .unwrap();
        assert_eq!(a.advertised_dns("AAA").await.unwrap(), None);
    }

    #[test]
    fn dns_resolution_prefers_local_override_then_advertised() {
        let local = vec!["10.8.0.2".to_string()];
        let advertised = Some(vec!["10.99.0.53".to_string()]);
        assert_eq!(resolve_dns_servers(&local, advertised.clone()), local);
        assert_eq!(
            resolve_dns_servers(&[], advertised),
            vec!["10.99.0.53".to_string()]
        );
        assert_eq!(resolve_dns_servers(&[], None), Vec::<String>::new());
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

    /// A device's published ICE candidates reach a peer through the network map,
    /// and a live `watch` stream is pushed when they are published.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn published_candidates_reach_a_peer() {
        use std::time::Duration;

        let url = start_coordinator().await;
        let mut a = ControlClient::connect(url.clone()).await.unwrap();
        let mut b = ControlClient::connect(url).await.unwrap();

        a.register("AAA", "laptop", "1.1.1.1:51820", &[])
            .await
            .unwrap();
        b.register("BBB", "gateway", "2.2.2.2:51820", &[])
            .await
            .unwrap();

        // B watches; the initial map shows A with no candidates yet.
        let mut stream = b.watch("BBB").await.unwrap();
        let initial = stream.next().await.unwrap().unwrap();
        assert_eq!(initial.len(), 1);
        assert!(initial[0].candidates.is_empty());

        // A publishes its host + reflexive candidates.
        let cands = vec!["1.1.1.1:51820".to_string(), "203.0.113.5:7777".to_string()];
        a.publish_candidates("AAA", &cands).await.unwrap();

        // The publish pushes a fresh map to B; A now carries the candidates.
        let update = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("watch update timed out")
            .unwrap()
            .unwrap();
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].public_key, "AAA");
        assert_eq!(update[0].candidates, cands);

        // A one-shot map fetch reflects them too.
        let map = b.network_map("BBB").await.unwrap();
        assert_eq!(map[0].candidates, cands);
    }

    /// A device rotates its static key; a peer's network map reflects the new
    /// key while the tunnel IP is preserved (PRD Phase 3 FR3).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotate_key_moves_the_device_to_a_new_key() {
        let url = start_coordinator().await;
        let mut a = ControlClient::connect(url.clone()).await.unwrap();
        let mut b = ControlClient::connect(url).await.unwrap();

        let addr = a
            .register("OLD", "laptop", "1.1.1.1:51820", &[])
            .await
            .unwrap();
        b.register("BBB", "gateway", "2.2.2.2:51820", &[])
            .await
            .unwrap();

        // Rotate OLD -> NEW; the assigned CIDR is unchanged.
        let after = a.rotate_key("OLD", "NEW").await.unwrap();
        assert_eq!(after, addr);

        // B's map now shows the device under its NEW key with the same allowed IP.
        let peers = b.network_map("BBB").await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, "NEW");
        assert_eq!(peers[0].allowed_ips, vec!["10.8.0.2/32".to_string()]);

        // Rotating an unregistered key is rejected.
        assert!(b.rotate_key("ghost", "x").await.is_err());
    }

    /// Publishing candidates for a device that never registered is rejected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publish_candidates_for_unknown_device_is_rejected() {
        let url = start_coordinator().await;
        let mut c = ControlClient::connect(url).await.unwrap();
        let err = c.publish_candidates("ghost", &["1.1.1.1:1".into()]).await;
        assert!(err.is_err(), "unregistered device must be rejected");
    }

    #[cfg(feature = "mtls")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_accepts_valid_client_and_rejects_wrong_ca() {
        use ferrum_coordinator::pki;

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
