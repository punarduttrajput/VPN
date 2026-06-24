//! The gRPC [`Coordinator`] service implementation over the [`Registry`].

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use ferrum_control_proto::coordinator::coordinator_server::Coordinator;
use ferrum_control_proto::coordinator::{
    NetworkMapRequest, NetworkMapResponse, PeerInfo, PublishCandidatesRequest,
    PublishCandidatesResponse, RegisterDeviceRequest, RegisterDeviceResponse,
};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::registry::Registry;

/// Compute the current network-map response for a device, advertising `relay`
/// (the coordinator's configured relay address, or empty for none).
fn current_map(
    registry: &Arc<Mutex<Registry>>,
    public_key: &str,
    relay: &str,
) -> NetworkMapResponse {
    let reg = registry.lock().expect("registry mutex poisoned");
    let peers = reg
        .network_map(public_key)
        .into_iter()
        .map(|d| PeerInfo {
            public_key: d.public_key,
            endpoint: d.endpoint,
            allowed_ips: vec![format!("{}/32", d.tunnel_ip)],
            candidates: d.candidates,
        })
        .collect();
    NetworkMapResponse {
        peers,
        relay: relay.to_string(),
    }
}

/// An authenticated caller identity derived from a verified bearer token.
///
/// Produced by the OIDC verifier (the `oidc` feature). `tags` here are
/// *authorized* tags — sourced from a signed claim, not self-declared in the
/// request — so the policy engine can treat them as an authorization boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    /// The token subject (`sub`) — the authenticated principal.
    pub subject: String,
    /// Tags the principal is authorized to carry.
    pub tags: Vec<String>,
}

/// Coordinator gRPC service backed by a shared [`Registry`].
pub struct CoordinatorService {
    registry: Arc<Mutex<Registry>>,
    /// Fires after any registry change so watchers can push a fresh map.
    changes: broadcast::Sender<()>,
    /// A network-wide relay address (`ip:port`) advertised to every device in the
    /// network map (PRD Phase 4 NAT traversal), or empty for none.
    relay: String,
    /// When set (the `oidc` feature + a configured verifier), every RPC requires
    /// a valid bearer token and registration tags come from the token.
    #[cfg(feature = "oidc")]
    verifier: Option<std::sync::Arc<crate::auth::OidcVerifier>>,
}

impl CoordinatorService {
    /// Build a service over a shared registry (no authentication).
    pub fn new(registry: Arc<Mutex<Registry>>) -> Self {
        let (changes, _) = broadcast::channel(16);
        Self {
            registry,
            changes,
            relay: String::new(),
            #[cfg(feature = "oidc")]
            verifier: None,
        }
    }

    /// Advertise a network-wide relay address (`ip:port`) to every device in the
    /// network map. Devices use it as their relay fallback unless locally
    /// overridden. An empty string (the default) advertises no relay.
    pub fn with_relay(mut self, relay: impl Into<String>) -> Self {
        self.relay = relay.into();
        self
    }

    /// Build a service that requires OIDC bearer tokens on every RPC.
    #[cfg(feature = "oidc")]
    pub fn with_auth(
        registry: Arc<Mutex<Registry>>,
        verifier: std::sync::Arc<crate::auth::OidcVerifier>,
    ) -> Self {
        let (changes, _) = broadcast::channel(16);
        Self {
            registry,
            changes,
            relay: String::new(),
            verifier: Some(verifier),
        }
    }

    /// Authenticate a request. Returns the verified claims when auth is enabled,
    /// or `None` when it is not (open mode / feature off). Errors map to
    /// `unauthenticated` so the client sees a clear rejection.
    #[cfg(feature = "oidc")]
    #[allow(clippy::result_large_err)] // tonic::Status is the trait-wide error type
    fn authenticate<T>(&self, request: &Request<T>) -> Result<Option<VerifiedClaims>, Status> {
        let Some(verifier) = &self.verifier else {
            return Ok(None);
        };
        let token = bearer_token(request.metadata())?;
        let claims = verifier
            .verify(token)
            .map_err(|e| Status::unauthenticated(format!("token rejected: {e}")))?;
        Ok(Some(claims))
    }

    /// No-auth build: every request passes with no verified identity.
    #[cfg(not(feature = "oidc"))]
    #[allow(clippy::result_large_err)] // tonic::Status is the trait-wide error type
    fn authenticate<T>(&self, _request: &Request<T>) -> Result<Option<VerifiedClaims>, Status> {
        Ok(None)
    }
}

/// Extract the `authorization: Bearer <token>` value from request metadata.
#[cfg(feature = "oidc")]
#[allow(clippy::result_large_err)] // tonic::Status is the trait-wide error type
fn bearer_token(meta: &tonic::metadata::MetadataMap) -> Result<&str, Status> {
    let header = meta
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("authorization metadata is not valid ASCII"))?;
    header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or_else(|| Status::unauthenticated("authorization must be a Bearer token"))
}

#[tonic::async_trait]
impl Coordinator for CoordinatorService {
    async fn register_device(
        &self,
        request: Request<RegisterDeviceRequest>,
    ) -> Result<Response<RegisterDeviceResponse>, Status> {
        let claims = self.authenticate(&request)?;
        let req = request.into_inner();
        // When authenticated, tags come from the verified token (an authorization
        // boundary); otherwise they are the self-declared request tags.
        let tags: &[String] = match &claims {
            Some(c) => &c.tags,
            None => &req.tags,
        };
        let ip = {
            let mut reg = self.registry.lock().expect("registry mutex poisoned");
            reg.register(&req.public_key, &req.name, &req.endpoint, tags)
                .map_err(|e| Status::invalid_argument(e.to_string()))?
        };
        // Notify watchers that the network changed (ignored if none are connected).
        let _ = self.changes.send(());
        Ok(Response::new(RegisterDeviceResponse {
            assigned_cidr: format!("{ip}/32"),
        }))
    }

    async fn get_network_map(
        &self,
        request: Request<NetworkMapRequest>,
    ) -> Result<Response<NetworkMapResponse>, Status> {
        self.authenticate(&request)?;
        let req = request.into_inner();
        Ok(Response::new(current_map(
            &self.registry,
            &req.public_key,
            &self.relay,
        )))
    }

    type WatchNetworkMapStream =
        Pin<Box<dyn Stream<Item = Result<NetworkMapResponse, Status>> + Send>>;

    async fn watch_network_map(
        &self,
        request: Request<NetworkMapRequest>,
    ) -> Result<Response<Self::WatchNetworkMapStream>, Status> {
        self.authenticate(&request)?;
        let public_key = request.into_inner().public_key;
        let registry = self.registry.clone();
        let relay = self.relay.clone();
        let mut changes = self.changes.subscribe();
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            // Push the current map immediately, then on every change.
            if tx
                .send(Ok(current_map(&registry, &public_key, &relay)))
                .await
                .is_err()
            {
                return;
            }
            // On each change (or a missed burst) recompute and push; the loop
            // ends when the broadcast closes (pattern stops matching) or the
            // client disconnects.
            while let Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) = changes.recv().await {
                if tx
                    .send(Ok(current_map(&registry, &public_key, &relay)))
                    .await
                    .is_err()
                {
                    break; // client disconnected
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn publish_candidates(
        &self,
        request: Request<PublishCandidatesRequest>,
    ) -> Result<Response<PublishCandidatesResponse>, Status> {
        self.authenticate(&request)?;
        let req = request.into_inner();
        {
            let mut reg = self.registry.lock().expect("registry mutex poisoned");
            reg.set_candidates(&req.public_key, &req.candidates)
                .map_err(|e| Status::failed_precondition(e.to_string()))?;
        }
        // New candidates change the map; push a fresh one to all watchers so
        // peers learn how to reach this device (PRD Phase 4 FR5).
        let _ = self.changes.send(());
        Ok(Response::new(PublishCandidatesResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_control_proto::coordinator::coordinator_client::CoordinatorClient;
    use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use std::net::Ipv4Addr;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    /// End-to-end over real gRPC on localhost: register two devices, then a
    /// network-map request returns the other peer with its assigned address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_and_get_map_over_grpc() {
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry);

        // Bind first so the listening socket accepts into its backlog (no race
        // with the client connecting before the server task starts serving).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinatorServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let mut client = CoordinatorClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let a = client
            .register_device(RegisterDeviceRequest {
                public_key: "AAA".into(),
                name: "a".into(),
                endpoint: "1.1.1.1:51820".into(),
                tags: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(a.assigned_cidr, "10.8.0.2/32");

        let b = client
            .register_device(RegisterDeviceRequest {
                public_key: "BBB".into(),
                name: "b".into(),
                endpoint: "2.2.2.2:51820".into(),
                tags: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(b.assigned_cidr, "10.8.0.3/32");

        let map = client
            .get_network_map(NetworkMapRequest {
                public_key: "AAA".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(map.peers.len(), 1);
        assert_eq!(map.peers[0].public_key, "BBB");
        assert_eq!(map.peers[0].endpoint, "2.2.2.2:51820");
        assert_eq!(map.peers[0].allowed_ips, vec!["10.8.0.3/32".to_string()]);
    }

    /// End-to-end with OIDC on: an unauthenticated register is rejected, a
    /// register with a valid token succeeds, and the device's tags come from the
    /// verified token claim (not the self-declared request field).
    #[cfg(feature = "oidc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oidc_rejects_unauthenticated_and_uses_token_tags() {
        use crate::auth::testsign::TestSigner;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tonic::Request;

        let signer = TestSigner::new("k1");
        let verifier =
            std::sync::Arc::new(signer.verifier("https://idp.example", "ferrum-coordinator"));
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::with_auth(registry.clone(), verifier);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinatorServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let mut client = CoordinatorClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        // No token -> unauthenticated.
        let no_token = client
            .register_device(RegisterDeviceRequest {
                public_key: "AAA".into(),
                name: "a".into(),
                endpoint: "1.1.1.1:51820".into(),
                tags: vec!["admin".into()],
            })
            .await;
        assert_eq!(no_token.unwrap_err().code(), tonic::Code::Unauthenticated);

        // Valid token whose claim grants tag "dev"; the request *claims* "admin"
        // (self-declared) but that must be ignored in favor of the token.
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = signer.sign(&format!(
            r#"{{"iss":"https://idp.example","aud":"ferrum-coordinator","sub":"alice","exp":{exp},"tags":["dev"]}}"#
        ));
        let mut req = Request::new(RegisterDeviceRequest {
            public_key: "AAA".into(),
            name: "a".into(),
            endpoint: "1.1.1.1:51820".into(),
            tags: vec!["admin".into()],
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let resp = client.register_device(req).await.unwrap().into_inner();
        assert_eq!(resp.assigned_cidr, "10.8.0.2/32");

        // The persisted device carries the *token* tags, not the request tags.
        let tags = registry.lock().unwrap().network_map("other")[0]
            .tags
            .clone();
        assert_eq!(tags, vec!["dev".to_string()]);
    }
}
