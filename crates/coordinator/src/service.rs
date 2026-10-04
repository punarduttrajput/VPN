//! The gRPC [`Coordinator`] service implementation over the [`Registry`].

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrum_control_proto::coordinator::coordinator_server::Coordinator;
use ferrum_control_proto::coordinator::{
    NetworkMapRequest, NetworkMapResponse, PeerInfo, PublishCandidatesRequest,
    PublishCandidatesResponse, RegisterDeviceRequest, RegisterDeviceResponse,
    RelayHeartbeatRequest, RelayHeartbeatResponse, RotateKeyRequest, RotateKeyResponse,
};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::limits::{source_key, KeyedLimiter, Limits, LimitsConfig};
use crate::metrics::Metrics;
use crate::registry::{Registry, RegistryError, TlsPins};

/// How often a relay should heartbeat, directed to it in every
/// [`RelayHeartbeatResponse`] (PRD `phase-6-anycast-autoscaling.md` FR3).
const RELAY_HEARTBEAT_INTERVAL_SECS: u32 = 15;

/// How long a registered relay stays advertised without a heartbeat — three
/// missed beats. Comfortably inside the parent PRD's < 90 s scale-out/withdraw
/// reaction target (NFR4).
const DEFAULT_RELAY_TTL: Duration = Duration::from_secs(45);

/// The verified tag that grants the relay role (SEC-013): only a caller whose
/// token carries it (or an identity in `--relay-identity`) may announce a relay.
/// Any other authenticated device is refused, since the announced relay is
/// advertised to the whole mesh.
pub const RELAY_TAG: &str = "relay";

/// A live, heartbeating relay known to the coordinator.
struct RelayEntry {
    last_beat: Instant,
    /// Registration order: selection prefers the earliest still-live relay, so
    /// the advertised relay is stable (a newly scaled-out relay doesn't steal
    /// clients from a healthy one; it takes over only when the current one
    /// drains or dies).
    joined: u64,
}

/// The registry of self-announced relays (PRD `phase-6-anycast-autoscaling.md`
/// FR3): populated by [`Coordinator::relay_heartbeat`], consulted for the
/// network map's `relay` field whenever no static `--relay` override is set.
pub(crate) struct RelayRegistry {
    entries: HashMap<String, RelayEntry>,
    next_seq: u64,
    ttl: Duration,
}

impl RelayRegistry {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            next_seq: 0,
            ttl,
        }
    }

    /// Record a heartbeat from `addr`. A draining relay is withdrawn on the
    /// spot (its goodbye); a new relay joins at the back of the selection
    /// order; a known one just refreshes its deadline.
    fn heartbeat(&mut self, addr: &str, draining: bool) {
        if draining {
            self.entries.remove(addr);
            return;
        }
        match self.entries.get_mut(addr) {
            Some(e) => e.last_beat = Instant::now(),
            None => {
                let joined = self.next_seq;
                self.next_seq += 1;
                self.entries.insert(
                    addr.to_string(),
                    RelayEntry {
                        last_beat: Instant::now(),
                        joined,
                    },
                );
            }
        }
    }

    /// The relay this registry currently advertises: the earliest-joined entry
    /// whose heartbeat is still fresh, or `None` when none are live.
    fn advertised(&self) -> Option<String> {
        self.entries
            .iter()
            .filter(|(_, e)| e.last_beat.elapsed() <= self.ttl)
            .min_by_key(|(_, e)| e.joined)
            .map(|(addr, _)| addr.clone())
    }

    /// Drop entries whose heartbeat lapsed (the sweeper's cleanup half; the
    /// *advertisement* change is what the sweeper actually watches for).
    fn sweep(&mut self) {
        let ttl = self.ttl;
        self.entries.retain(|_, e| e.last_beat.elapsed() <= ttl);
    }
}

/// The relay address to advertise in a network map right now: the static
/// `--relay` override when configured, else whatever the registry holds, else
/// empty for none.
fn effective_relay(static_relay: &str, relays: &RelayRegistry) -> String {
    if !static_relay.is_empty() {
        return static_relay.to_string();
    }
    relays.advertised().unwrap_or_default()
}

/// Compute the current network-map response for a device, advertising `relay`
/// (the coordinator's currently-advertised relay address, or empty for none)
/// and `dns_servers` (the coordinator's configured resolvers, or empty for
/// none).
fn current_map(
    registry: &Arc<Mutex<Registry>>,
    public_key: &str,
    relay: &str,
    dns_servers: &[String],
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
            tls_cert_sha256: d.tls_cert_sha256,
            tls_next_pins: d.tls_next_pins,
        })
        .collect();
    NetworkMapResponse {
        peers,
        relay: relay.to_string(),
        dns_servers: dns_servers.to_vec(),
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
    /// network map (PRD Phase 4 NAT traversal), or empty for none. When set it
    /// is a **static override**: the relay registry below is ignored.
    relay: String,
    /// Self-announced, heartbeating relays (PRD `phase-6-anycast-autoscaling.md`
    /// FR3). Advertised when no static `relay` override is configured.
    relays: Arc<Mutex<RelayRegistry>>,
    /// DNS resolvers (bare IPs, reachable through the tunnel) advertised to
    /// every device in the network map (PRD leak-protection.md), or empty for
    /// none.
    dns_servers: Vec<String>,
    /// Aggregate, privacy-preserving control-plane metrics (PRD Phase 6 FR4).
    metrics: Arc<Metrics>,
    /// Authenticated identities (`oidc:<sub>` / `mtls:<fp>`) allowed to act as
    /// relays in addition to tokens carrying the [`RELAY_TAG`] (SEC-013). For
    /// mTLS-only deployments, whose client certs carry no tags.
    relay_identities: Vec<String>,
    /// Per-source / per-identity rate limits and the watch-stream quota
    /// (SEC-006). Always on; tune with [`Self::with_limits`].
    limits: Arc<Limits>,
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
            relays: Arc::new(Mutex::new(RelayRegistry::new(DEFAULT_RELAY_TTL))),
            dns_servers: Vec::new(),
            metrics: Metrics::new(),
            relay_identities: Vec::new(),
            limits: Arc::new(Limits::new(&LimitsConfig::default())),
            #[cfg(feature = "oidc")]
            verifier: None,
        }
    }

    /// Replace the default rate limits and watch-stream quota (SEC-006).
    pub fn with_limits(mut self, cfg: &LimitsConfig) -> Self {
        self.limits = Arc::new(Limits::new(cfg));
        self
    }

    /// A handle to this service's metrics, for the `/metrics` exporter to render.
    /// Clone it before moving the service into the gRPC server.
    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    /// A handle to the change-notification channel this service fires after
    /// every registry mutation, so an external surface (the admin API) can
    /// trigger the same "push a fresh network map to watchers" behavior after
    /// its own mutations (revoke, policy edit). Clone it before moving the
    /// service into the gRPC server.
    pub fn changes(&self) -> broadcast::Sender<()> {
        self.changes.clone()
    }

    /// Advertise a **static** network-wide relay address (`ip:port`) to every
    /// device in the network map. Devices use it as their relay fallback unless
    /// locally overridden. An empty string (the default) advertises no static
    /// relay — the map then advertises whatever live relay has announced itself
    /// via [`Coordinator::relay_heartbeat`] (PRD `phase-6-anycast-autoscaling.md`
    /// FR3), if any. When set, this overrides the relay registry entirely.
    pub fn with_relay(mut self, relay: impl Into<String>) -> Self {
        self.relay = relay.into();
        self
    }

    /// Shrink the relay-registry liveness TTL (how long a relay stays
    /// advertised without a heartbeat) — for tests that need fast expiry.
    pub fn with_relay_ttl(self, ttl: Duration) -> Self {
        self.relays.lock().expect("relay registry poisoned").ttl = ttl;
        self
    }

    /// Spawn the relay-registry sweeper (PRD `phase-6-anycast-autoscaling.md`
    /// FR3): every `period`, drop relays whose heartbeat lapsed and — the part
    /// a lazy check can't do — push a fresh map to watchers when the passage
    /// of time alone changed which relay is advertised (an expired relay with
    /// no other registry activity would otherwise stay in clients' maps until
    /// the next unrelated change). Call from within a tokio runtime; abort the
    /// returned handle to stop. Not needed when a static `--relay` override is
    /// configured (the advertisement can never change).
    pub fn spawn_relay_sweeper(&self, period: Duration) -> tokio::task::JoinHandle<()> {
        let relays = self.relays.clone();
        let static_relay = self.relay.clone();
        let changes = self.changes.clone();
        tokio::spawn(async move {
            let mut last = {
                let reg = relays.lock().expect("relay registry poisoned");
                effective_relay(&static_relay, &reg)
            };
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                let now_advertised = {
                    let mut reg = relays.lock().expect("relay registry poisoned");
                    reg.sweep();
                    effective_relay(&static_relay, &reg)
                };
                if now_advertised != last {
                    tracing::info!(
                        withdrawn = now_advertised.is_empty(),
                        "advertised relay changed (liveness); pushing fresh map to watchers"
                    );
                    last = now_advertised;
                    let _ = changes.send(());
                }
            }
        })
    }

    /// Allow these authenticated identities (`oidc:<sub>` or `mtls:<sha256 hex>`)
    /// to announce relays, in addition to tokens carrying [`RELAY_TAG`]
    /// (SEC-013). Needed for mTLS-only deployments, whose client certs carry
    /// no tags.
    pub fn with_relay_identities(mut self, identities: Vec<String>) -> Self {
        self.relay_identities = identities;
        self
    }

    /// Advertise DNS resolvers (bare IPs, reachable through the tunnel) to
    /// every device in the network map (PRD leak-protection.md). Devices point
    /// their system DNS at them while connected unless locally overridden.
    /// An empty list (the default) advertises none.
    pub fn with_dns_servers(mut self, dns_servers: Vec<String>) -> Self {
        self.dns_servers = dns_servers;
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
            relays: Arc::new(Mutex::new(RelayRegistry::new(DEFAULT_RELAY_TTL))),
            dns_servers: Vec::new(),
            metrics: Metrics::new(),
            relay_identities: Vec::new(),
            limits: Arc::new(Limits::new(&LimitsConfig::default())),
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

    /// [`authenticate`](Self::authenticate), counting a rejected request in the
    /// `unauthenticated` metric. Used by every RPC so the count covers them all.
    #[allow(clippy::result_large_err)] // tonic::Status is the trait-wide error type
    fn authenticate_metered<T>(
        &self,
        request: &Request<T>,
    ) -> Result<Option<VerifiedClaims>, Status> {
        self.authenticate(request)
            .inspect_err(|_| self.metrics.inc_unauthenticated())
    }

    /// The authenticated identity to enforce SEC-002 key binding against, or
    /// `None` when the request carries no verified identity at all (open
    /// mode). Namespaced so an OIDC subject and an mTLS fingerprint can never
    /// collide:
    /// - a verified OIDC token -> `oidc:<sub>` (also the source of `tags`);
    /// - otherwise, a client certificate presented over mTLS -> its
    ///   fingerprint as `mtls:<sha256 hex>`. mTLS carries no tags claim, so
    ///   tags stay self-declared in this case — only the key binding is
    ///   enforced.
    fn bound_identity<T>(
        &self,
        #[cfg_attr(not(feature = "mtls"), allow(unused_variables))] request: &Request<T>,
        claims: &Option<VerifiedClaims>,
    ) -> Option<String> {
        if let Some(c) = claims {
            return Some(format!("oidc:{}", c.subject));
        }
        #[cfg(feature = "mtls")]
        {
            mtls_identity(request)
        }
        #[cfg(not(feature = "mtls"))]
        {
            None
        }
    }
}

impl CoordinatorService {
    /// SEC-013: may this caller act for `public_key`? A revoked key is refused
    /// in every mode. An authenticated caller must additionally be the identity
    /// bound to that key (SEC-002). Open mode (no identity) has no binding to
    /// check.
    #[allow(clippy::result_large_err)] // tonic::Status is the trait-wide error type
    fn authorize_key<T>(
        &self,
        request: &Request<T>,
        claims: &Option<VerifiedClaims>,
        public_key: &str,
    ) -> Result<(), Status> {
        let reg = self.registry.lock().expect("registry mutex poisoned");
        if reg.is_key_revoked(public_key) {
            return Err(Status::permission_denied("device has been revoked"));
        }
        if let Some(identity) = self.bound_identity(request, claims) {
            if reg.key_for_identity(&identity) != Some(public_key) {
                return Err(Status::permission_denied(
                    "public_key is not bound to the caller's identity (register it first)",
                ));
            }
        }
        Ok(())
    }

    /// SEC-013: may this caller announce a relay? The announcement is pushed to
    /// every device, so an authenticated caller needs the relay role: a
    /// [`RELAY_TAG`] in its verified token, or an identity listed via
    /// [`with_relay_identities`](Self::with_relay_identities). Open mode is
    /// unchanged.
    #[allow(clippy::result_large_err)] // tonic::Status is the trait-wide error type
    fn authorize_relay<T>(
        &self,
        request: &Request<T>,
        claims: &Option<VerifiedClaims>,
    ) -> Result<(), Status> {
        let Some(identity) = self.bound_identity(request, claims) else {
            return Ok(());
        };
        let tagged = claims
            .as_ref()
            .is_some_and(|c| c.tags.iter().any(|t| t == RELAY_TAG));
        if tagged || self.relay_identities.contains(&identity) {
            Ok(())
        } else {
            Err(Status::permission_denied(
                "RelayHeartbeat requires the relay role",
            ))
        }
    }
}

/// Map a registry error to a gRPC status: a revocation is always
/// `permission_denied` (SEC-013); anything else goes through `other`.
fn registry_status(e: RegistryError, other: impl FnOnce(String) -> Status) -> Status {
    match e {
        RegistryError::Revoked => Status::permission_denied(e.to_string()),
        e => other(e.to_string()),
    }
}

/// Derive a stable identity from the mTLS client leaf certificate presented on
/// this connection, if any: the SHA-256 fingerprint of its DER encoding,
/// hex-encoded (PRD security-hardening.md SEC-002). `None` when the
/// connection isn't mTLS (no client certificate) or presented none.
#[cfg(feature = "mtls")]
fn mtls_identity<T>(request: &Request<T>) -> Option<String> {
    use std::fmt::Write;

    let certs = request.peer_certs()?;
    let leaf = certs.first()?;
    let fp = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    let mut hex = String::with_capacity(fp.as_ref().len() * 2);
    for b in fp.as_ref() {
        let _ = write!(hex, "{b:02x}");
    }
    Some(format!("mtls:{hex}"))
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

/// Charge one request for `key` against `limiter` (SEC-006), mapping a refusal
/// to `resource_exhausted`. Neither the key nor the caller is logged (NFR5).
#[allow(clippy::result_large_err)] // tonic::Status is the trait-wide error type
fn rate_limit(limiter: &KeyedLimiter, key: &str, rpc: &'static str) -> Result<(), Status> {
    if limiter.check(key, Instant::now()) {
        return Ok(());
    }
    tracing::debug!(rpc, "request rate limited");
    Err(Status::resource_exhausted(format!(
        "{rpc} rate limit exceeded; retry later"
    )))
}

#[tonic::async_trait]
impl Coordinator for CoordinatorService {
    // `skip_all`: the request carries the device public key/name/endpoint; none of
    // it enters the span (NFR5 — no per-user identity in traces). The span records
    // only the operation and a safe outcome.
    #[tracing::instrument(skip_all, name = "register_device")]
    async fn register_device(
        &self,
        request: Request<RegisterDeviceRequest>,
    ) -> Result<Response<RegisterDeviceResponse>, Status> {
        let _timer = self.metrics.start_request();
        // SEC-006: the per-source limit runs before authentication so a flood
        // can't make the coordinator do token verification at an unbounded
        // rate; the per-identity limit needs the verified identity.
        let throttled = |_: &Status| self.metrics.inc_register_throttled();
        let source = source_key(request.remote_addr());
        rate_limit(&self.limits.register_source, &source, "RegisterDevice")
            .inspect_err(throttled)?;
        let claims = self.authenticate_metered(&request)?;
        let bound_identity = self.bound_identity(&request, &claims);
        if let Some(identity) = &bound_identity {
            rate_limit(&self.limits.register_identity, identity, "RegisterDevice")
                .inspect_err(throttled)?;
        }
        self.metrics.inc_register();
        let req = request.into_inner();
        // When authenticated, tags come from the verified token (an authorization
        // boundary); otherwise they are the self-declared request tags.
        let tags: &[String] = match &claims {
            Some(c) => &c.tags,
            None => &req.tags,
        };
        // SEC-004: the device's TLS cert pin, plus (SEC-007) any next pins it
        // pre-announces for a rotation, distributed to peers that dial it over
        // QUIC. Bound to this (authenticated, SEC-002) registration.
        let tls_pins = TlsPins::normalize(&req.tls_cert_sha256, &req.tls_next_pins)
            .map_err(Status::invalid_argument)?;
        let ip = {
            let mut reg = self.registry.lock().expect("registry mutex poisoned");
            // SEC-002: an authenticated caller (OIDC token or mTLS client cert)
            // may only ever register the public key it first claimed.
            if let Some(identity) = &bound_identity {
                reg.bind_identity(identity, &req.public_key)
                    .map_err(|e| registry_status(e, Status::failed_precondition))?;
            }
            // One store write carries the device and its pins.
            reg.register_with_pins(
                &req.public_key,
                &req.name,
                &req.endpoint,
                tags,
                Some(&tls_pins),
            )
            .map_err(|e| registry_status(e, Status::invalid_argument))?
        };
        // Notify watchers that the network changed (ignored if none are connected).
        let _ = self.changes.send(());
        tracing::info!(authenticated = claims.is_some(), "registered device");
        Ok(Response::new(RegisterDeviceResponse {
            assigned_cidr: format!("{ip}/32"),
        }))
    }

    #[tracing::instrument(skip_all, name = "get_network_map")]
    async fn get_network_map(
        &self,
        request: Request<NetworkMapRequest>,
    ) -> Result<Response<NetworkMapResponse>, Status> {
        let _timer = self.metrics.start_request();
        let claims = self.authenticate_metered(&request)?;
        self.authorize_key(&request, &claims, &request.get_ref().public_key)?;
        self.metrics.inc_network_map_request();
        let req = request.into_inner();
        let relay = {
            let reg = self.relays.lock().expect("relay registry poisoned");
            effective_relay(&self.relay, &reg)
        };
        let map = current_map(&self.registry, &req.public_key, &relay, &self.dns_servers);
        tracing::debug!(peers = map.peers.len(), "served network map");
        Ok(Response::new(map))
    }

    type WatchNetworkMapStream =
        Pin<Box<dyn Stream<Item = Result<NetworkMapResponse, Status>> + Send>>;

    #[tracing::instrument(skip_all, name = "watch_network_map")]
    async fn watch_network_map(
        &self,
        request: Request<NetworkMapRequest>,
    ) -> Result<Response<Self::WatchNetworkMapStream>, Status> {
        let _timer = self.metrics.start_request();
        let source = source_key(request.remote_addr());
        let claims = self.authenticate_metered(&request)?;
        self.authorize_key(&request, &claims, &request.get_ref().public_key)?;
        // SEC-006: cap concurrent streams per source, per identity (when
        // authenticated) and overall. The permit rides into the serving task
        // and frees the slot when the stream ends.
        let mut quota_keys = vec![(source, self.limits.watch_per_source)];
        if let Some(identity) = self.bound_identity(&request, &claims) {
            quota_keys.push((identity, self.limits.watch_per_identity));
        }
        let Some(permit) = self.limits.watch.try_acquire(quota_keys) else {
            self.metrics.inc_watch_stream_rejected();
            tracing::debug!("watch stream refused: concurrent-stream quota");
            return Err(Status::resource_exhausted(
                "too many concurrent WatchNetworkMap streams; close one and retry",
            ));
        };
        let public_key = request.into_inner().public_key;
        let registry = self.registry.clone();
        let static_relay = self.relay.clone();
        let relays = self.relays.clone();
        let dns_servers = self.dns_servers.clone();
        let mut changes = self.changes.subscribe();
        // Track this stream in the active-streams gauge; the guard rides into the
        // serving task and decrements when it ends (disconnect / close / error).
        let guard = self.metrics.watch_started();
        tracing::info!("watch stream opened");
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let _guard = guard;
            let _permit = permit;
            // The advertised relay is recomputed per push (the registry is
            // live state — a heartbeat, goodbye, or sweep can change it
            // between pushes; each such change fires `changes`).
            let advertised = |static_relay: &str| {
                let reg = relays.lock().expect("relay registry poisoned");
                effective_relay(static_relay, &reg)
            };
            // SEC-013: a device revoked mid-stream gets no further maps. The
            // revocation fires `changes`, so this is checked promptly.
            let revoked = || {
                registry
                    .lock()
                    .expect("registry mutex poisoned")
                    .is_key_revoked(&public_key)
            };
            // Push the current map immediately, then on every change.
            if tx
                .send(Ok(current_map(
                    &registry,
                    &public_key,
                    &advertised(&static_relay),
                    &dns_servers,
                )))
                .await
                .is_err()
            {
                return;
            }
            // On each change (or a missed burst) recompute and push; the loop
            // ends when the broadcast closes or the client disconnects. The
            // `closed()` arm notices a disconnect right away rather than at
            // the next push, so the stream's quota slot (SEC-006) and gauge
            // entry are released promptly.
            loop {
                let changed = tokio::select! {
                    _ = tx.closed() => break,
                    changed = changes.recv() => changed,
                };
                if let Err(broadcast::error::RecvError::Closed) = changed {
                    break;
                }
                if revoked() {
                    let _ = tx
                        .send(Err(Status::permission_denied("device has been revoked")))
                        .await;
                    break;
                }
                if tx
                    .send(Ok(current_map(
                        &registry,
                        &public_key,
                        &advertised(&static_relay),
                        &dns_servers,
                    )))
                    .await
                    .is_err()
                {
                    break; // client disconnected
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    #[tracing::instrument(skip_all, name = "publish_candidates")]
    async fn publish_candidates(
        &self,
        request: Request<PublishCandidatesRequest>,
    ) -> Result<Response<PublishCandidatesResponse>, Status> {
        let _timer = self.metrics.start_request();
        let claims = self.authenticate_metered(&request)?;
        self.authorize_key(&request, &claims, &request.get_ref().public_key)?;
        self.metrics.inc_publish_candidates();
        let req = request.into_inner();
        tracing::debug!(candidates = req.candidates.len(), "published candidates");
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

    // `skip_all`: the relay address is infrastructure, not user identity, but the
    // span still records only the operation + outcome for consistency (NFR5).
    #[tracing::instrument(skip_all, name = "relay_heartbeat")]
    async fn relay_heartbeat(
        &self,
        request: Request<RelayHeartbeatRequest>,
    ) -> Result<Response<RelayHeartbeatResponse>, Status> {
        let _timer = self.metrics.start_request();
        // SEC-006: per-source before authentication, per-identity after.
        let throttled = |_: &Status| self.metrics.inc_relay_heartbeat_throttled();
        let source = source_key(request.remote_addr());
        rate_limit(&self.limits.heartbeat_source, &source, "RelayHeartbeat")
            .inspect_err(throttled)?;
        let claims = self.authenticate_metered(&request)?;
        if let Some(identity) = self.bound_identity(&request, &claims) {
            rate_limit(&self.limits.heartbeat_identity, &identity, "RelayHeartbeat")
                .inspect_err(throttled)?;
        }
        self.authorize_relay(&request, &claims)?;
        let req = request.into_inner();
        req.addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| Status::invalid_argument(format!("relay addr '{}': {e}", req.addr)))?;
        let changed = {
            let mut reg = self.relays.lock().expect("relay registry poisoned");
            let before = effective_relay(&self.relay, &reg);
            reg.heartbeat(&req.addr, req.draining);
            let after = effective_relay(&self.relay, &reg);
            before != after
        };
        if changed {
            // The advertised relay changed (a first relay came up, the current
            // one said goodbye, …) — push a fresh map so clients retarget.
            let _ = self.changes.send(());
            tracing::info!(draining = req.draining, "advertised relay changed");
        }
        Ok(Response::new(RelayHeartbeatResponse {
            interval_secs: RELAY_HEARTBEAT_INTERVAL_SECS,
        }))
    }

    #[tracing::instrument(skip_all, name = "rotate_key")]
    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let _timer = self.metrics.start_request();
        let claims = self.authenticate_metered(&request)?;
        let bound_identity = self.bound_identity(&request, &claims);
        self.metrics.inc_rotate_key();
        let req = request.into_inner();
        // The device's TLS cert is derived from its WireGuard key, so a rotation
        // carries the new pin set (or clears it) — never keep the stale one.
        let tls_pins = TlsPins::normalize(&req.new_tls_cert_sha256, &req.new_tls_next_pins)
            .map_err(Status::invalid_argument)?;
        let ip = {
            let mut reg = self.registry.lock().expect("registry mutex poisoned");
            // SEC-002: the authorized rotation path — an authenticated caller
            // may only rotate a key it already owns, and may not rotate onto a
            // key another identity already owns.
            if let Some(identity) = &bound_identity {
                reg.rebind_identity(identity, &req.old_public_key, &req.new_public_key)
                    .map_err(|e| registry_status(e, Status::failed_precondition))?;
            }
            let ip = reg
                .rotate_key(&req.old_public_key, &req.new_public_key)
                .map_err(|e| match e {
                    RegistryError::UnknownDevice => Status::not_found(e.to_string()),
                    RegistryError::Revoked => Status::permission_denied(e.to_string()),
                    RegistryError::InvalidKey | RegistryError::KeyInUse => {
                        Status::invalid_argument(e.to_string())
                    }
                    other => Status::internal(other.to_string()),
                })?;
            reg.set_tls_pins(&req.new_public_key, &tls_pins)
                .map_err(|e| Status::internal(e.to_string()))?;
            ip
        };
        // The device now answers under a new key; push a fresh map so peers
        // re-handshake to it (PRD Phase 3 FR3 graceful re-handshake).
        let _ = self.changes.send(());
        tracing::info!("rotated device key");
        Ok(Response::new(RotateKeyResponse {
            assigned_cidr: format!("{ip}/32"),
        }))
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
                ..Default::default()
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
                ..Default::default()
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

    /// Configured DNS resolvers are advertised in every network map (and an
    /// unconfigured service advertises none) — PRD leak-protection.md M1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn advertised_dns_servers_land_in_map() {
        use ferrum_control_proto::coordinator::coordinator_server::Coordinator;

        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry)
            .with_dns_servers(vec!["10.99.0.53".into(), "fd00::53".into()]);
        svc.register_device(Request::new(RegisterDeviceRequest {
            public_key: "AAA".into(),
            name: "a".into(),
            endpoint: "1.1.1.1:51820".into(),
            tags: vec![],
            ..Default::default()
        }))
        .await
        .unwrap();

        let map = svc
            .get_network_map(Request::new(NetworkMapRequest {
                public_key: "AAA".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(map.dns_servers, vec!["10.99.0.53", "fd00::53"]);

        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let bare = CoordinatorService::new(registry);
        bare.register_device(Request::new(RegisterDeviceRequest {
            public_key: "AAA".into(),
            name: "a".into(),
            endpoint: "1.1.1.1:51820".into(),
            tags: vec![],
            ..Default::default()
        }))
        .await
        .unwrap();
        let map = bare
            .get_network_map(Request::new(NetworkMapRequest {
                public_key: "AAA".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(map.dns_servers.is_empty());
    }

    /// Calling the RPC handlers directly bumps the matching metrics, and `render`
    /// reports them (with the device gauge sampled from the registry) (PRD Phase 6).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn metrics_count_handled_rpcs() {
        use ferrum_control_proto::coordinator::coordinator_server::Coordinator;

        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry.clone());
        let metrics = svc.metrics();

        for (pk, ep) in [("AAA", "1.1.1.1:51820"), ("BBB", "2.2.2.2:51820")] {
            svc.register_device(Request::new(RegisterDeviceRequest {
                public_key: pk.into(),
                name: pk.into(),
                endpoint: ep.into(),
                tags: vec![],
                ..Default::default()
            }))
            .await
            .unwrap();
        }
        svc.get_network_map(Request::new(NetworkMapRequest {
            public_key: "AAA".into(),
        }))
        .await
        .unwrap();
        svc.rotate_key(Request::new(RotateKeyRequest {
            old_public_key: "AAA".into(),
            new_public_key: "CCC".into(),
            ..Default::default()
        }))
        .await
        .unwrap();

        let text = metrics.render(registry.lock().unwrap().device_count());
        assert!(text.contains("ferrum_register_total 2\n"), "{text}");
        assert!(
            text.contains("ferrum_network_map_requests_total 1\n"),
            "{text}"
        );
        assert!(text.contains("ferrum_rotate_key_total 1\n"), "{text}");
        assert!(text.contains("ferrum_devices_registered 2\n"), "{text}");
        assert!(text.contains("ferrum_unauthenticated_total 0\n"), "{text}");
    }

    /// SEC-004: a device's registered TLS cert pin reaches its peers' maps
    /// (normalized), a malformed pin is rejected, a re-registration replaces the
    /// pin, and a key rotation carries the new one (never the stale pin).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_pin_is_distributed_to_peers() {
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
        let mut client = CoordinatorClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        let register = |pk: &str, pin: &str| RegisterDeviceRequest {
            public_key: pk.into(),
            name: pk.into(),
            endpoint: "1.1.1.1:51820".into(),
            tls_cert_sha256: pin.into(),
            ..Default::default()
        };
        let pin_of = |map: NetworkMapResponse, pk: &str| {
            map.peers
                .into_iter()
                .find(|p| p.public_key == pk)
                .map(|p| p.tls_cert_sha256)
                .expect("peer in map")
        };

        // openssl-style (uppercase, colon-separated) is accepted and normalized.
        let openssl = vec!["AB"; 32].join(":");
        client
            .register_device(register("A", &openssl))
            .await
            .unwrap();
        client.register_device(register("B", "")).await.unwrap();
        let map = client
            .get_network_map(NetworkMapRequest {
                public_key: "B".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(pin_of(map, "A"), "ab".repeat(32));

        // Malformed pins are refused outright.
        let err = client
            .register_device(register("C", "not-a-pin"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // Re-registering replaces the pin.
        client
            .register_device(register("A", &"cd".repeat(32)))
            .await
            .unwrap();
        let map = client
            .get_network_map(NetworkMapRequest {
                public_key: "B".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(pin_of(map, "A"), "cd".repeat(32));

        // Rotation carries the new key's pin — or clears it — never the old one.
        client
            .rotate_key(RotateKeyRequest {
                old_public_key: "A".into(),
                new_public_key: "A2".into(),
                new_tls_cert_sha256: "ef".repeat(32),
                ..Default::default()
            })
            .await
            .unwrap();
        let map = client
            .get_network_map(NetworkMapRequest {
                public_key: "B".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(pin_of(map, "A2"), "ef".repeat(32));
        client
            .rotate_key(RotateKeyRequest {
                old_public_key: "A2".into(),
                new_public_key: "A3".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let map = client
            .get_network_map(NetworkMapRequest {
                public_key: "B".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(pin_of(map, "A3"), "");
    }

    /// End-to-end over gRPC: a device rotates its key and a peer's network map
    /// reflects the new key while the tunnel IP stays the same (PRD Phase 3 FR3).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotate_key_updates_the_map_and_keeps_the_ip() {
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
        let mut client = CoordinatorClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        client
            .register_device(RegisterDeviceRequest {
                public_key: "OLD".into(),
                name: "a".into(),
                endpoint: "1.1.1.1:51820".into(),
                tags: vec![],
                ..Default::default()
            })
            .await
            .unwrap();
        client
            .register_device(RegisterDeviceRequest {
                public_key: "PEER".into(),
                name: "b".into(),
                endpoint: "2.2.2.2:51820".into(),
                tags: vec![],
                ..Default::default()
            })
            .await
            .unwrap();

        // Rotate OLD -> NEW; the assignment (10.8.0.2/32) is echoed back unchanged.
        let resp = client
            .rotate_key(RotateKeyRequest {
                old_public_key: "OLD".into(),
                new_public_key: "NEW".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.assigned_cidr, "10.8.0.2/32");

        // The peer's map now lists the rotated device under its NEW key, same IP.
        let map = client
            .get_network_map(NetworkMapRequest {
                public_key: "PEER".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(map.peers.len(), 1);
        assert_eq!(map.peers[0].public_key, "NEW");
        assert_eq!(map.peers[0].allowed_ips, vec!["10.8.0.2/32".to_string()]);

        // Rotating a key that doesn't exist is a not-found error.
        let err = client
            .rotate_key(RotateKeyRequest {
                old_public_key: "GHOST".into(),
                new_public_key: "X".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// Relay registry (PRD `phase-6-anycast-autoscaling.md` FR3): a heartbeat
    /// advertises the relay; selection is stable while the first relay lives;
    /// a draining goodbye hands over to the next; the last goodbye withdraws.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_heartbeat_advertises_and_goodbye_hands_over() {
        use ferrum_control_proto::coordinator::coordinator_server::Coordinator;

        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry);
        svc.register_device(Request::new(RegisterDeviceRequest {
            public_key: "AAA".into(),
            name: "a".into(),
            endpoint: "1.1.1.1:51820".into(),
            tags: vec![],
            ..Default::default()
        }))
        .await
        .unwrap();

        async fn advertised(svc: &CoordinatorService) -> String {
            svc.get_network_map(Request::new(NetworkMapRequest {
                public_key: "AAA".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .relay
        }

        // No relays yet: nothing advertised.
        assert_eq!(advertised(&svc).await, "");

        // First relay announces itself and is advertised; the response directs
        // the heartbeat cadence.
        let resp = svc
            .relay_heartbeat(Request::new(RelayHeartbeatRequest {
                addr: "9.9.9.1:51821".into(),
                draining: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.interval_secs, RELAY_HEARTBEAT_INTERVAL_SECS);
        assert_eq!(advertised(&svc).await, "9.9.9.1:51821");

        // A second relay joining does NOT steal the advertisement (stable
        // selection: earliest live relay wins).
        svc.relay_heartbeat(Request::new(RelayHeartbeatRequest {
            addr: "9.9.9.2:51821".into(),
            draining: false,
        }))
        .await
        .unwrap();
        assert_eq!(advertised(&svc).await, "9.9.9.1:51821");

        // The first relay drains (goodbye): the second takes over immediately.
        svc.relay_heartbeat(Request::new(RelayHeartbeatRequest {
            addr: "9.9.9.1:51821".into(),
            draining: true,
        }))
        .await
        .unwrap();
        assert_eq!(advertised(&svc).await, "9.9.9.2:51821");

        // The last relay drains: nothing advertised again.
        svc.relay_heartbeat(Request::new(RelayHeartbeatRequest {
            addr: "9.9.9.2:51821".into(),
            draining: true,
        }))
        .await
        .unwrap();
        assert_eq!(advertised(&svc).await, "");

        // A malformed relay address is rejected.
        let err = svc
            .relay_heartbeat(Request::new(RelayHeartbeatRequest {
                addr: "not-an-addr".into(),
                draining: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// A static `--relay` override wins over the relay registry, unchanged
    /// semantics for single-relay deployments.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn static_relay_override_beats_registry() {
        use ferrum_control_proto::coordinator::coordinator_server::Coordinator;

        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry).with_relay("5.5.5.5:51821");
        svc.register_device(Request::new(RegisterDeviceRequest {
            public_key: "AAA".into(),
            name: "a".into(),
            endpoint: "1.1.1.1:51820".into(),
            tags: vec![],
            ..Default::default()
        }))
        .await
        .unwrap();
        svc.relay_heartbeat(Request::new(RelayHeartbeatRequest {
            addr: "9.9.9.1:51821".into(),
            draining: false,
        }))
        .await
        .unwrap();

        let map = svc
            .get_network_map(Request::new(NetworkMapRequest {
                public_key: "AAA".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(map.relay, "5.5.5.5:51821");
    }

    /// Scale-out + withdrawal end-to-end through the watch stream (PRD
    /// `phase-6-anycast-autoscaling.md` FR3 / NFR-A3): a watcher is pushed a
    /// fresh map when a relay announces itself (well under the parent PRD's
    /// 90 s target — asserted at seconds here), and pushed again with the
    /// relay withdrawn when its heartbeats lapse (sweeper + short TTL).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchers_learn_relay_arrival_and_liveness_withdrawal() {
        use ferrum_control_proto::coordinator::coordinator_server::Coordinator;
        use tokio_stream::StreamExt;

        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry).with_relay_ttl(Duration::from_millis(100));
        let _sweeper = svc.spawn_relay_sweeper(Duration::from_millis(25));
        svc.register_device(Request::new(RegisterDeviceRequest {
            public_key: "AAA".into(),
            name: "a".into(),
            endpoint: "1.1.1.1:51820".into(),
            tags: vec![],
            ..Default::default()
        }))
        .await
        .unwrap();

        let mut stream = svc
            .watch_network_map(Request::new(NetworkMapRequest {
                public_key: "AAA".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        // Initial push: no relay yet.
        let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("no initial push")
            .unwrap()
            .unwrap();
        assert_eq!(first.relay, "");

        // Read pushes until one advertises `relay` (the heartbeat handler and
        // the sweeper may each push — an identical map twice is harmless to
        // real watchers, so the test just waits for the expected state).
        async fn next_push_with_relay(
            stream: &mut (impl Stream<Item = Result<NetworkMapResponse, Status>> + Unpin),
            relay: &str,
        ) {
            loop {
                let map = tokio::time::timeout(Duration::from_secs(5), stream.next())
                    .await
                    .unwrap_or_else(|_| panic!("no push advertising relay '{relay}'"))
                    .unwrap()
                    .unwrap();
                if map.relay == relay {
                    return;
                }
            }
        }

        // A relay scales out and heartbeats: the watcher is pushed the new map
        // (well under the 90 s NFR-A3 target — the timeout above is 5 s).
        svc.relay_heartbeat(Request::new(RelayHeartbeatRequest {
            addr: "9.9.9.1:51821".into(),
            draining: false,
        }))
        .await
        .unwrap();
        next_push_with_relay(&mut stream, "9.9.9.1:51821").await;

        // The relay goes silent: the sweeper withdraws it and pushes again.
        next_push_with_relay(&mut stream, "").await;
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
                ..Default::default()
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
            ..Default::default()
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

    /// SEC-007: pre-announced next pins reach peers alongside the current pin
    /// (normalized, deduplicated), bad ones are refused, a registration
    /// replaces them, and the rotation that completes the roll promotes the
    /// next pin to current and clears the announcement.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn next_tls_pins_are_distributed_and_completed_by_rotation() {
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
        let mut client = CoordinatorClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let (p1, p2) = ("11".repeat(32), "22".repeat(32));
        let register = |pk: &str, current: &str, next: Vec<String>| RegisterDeviceRequest {
            public_key: pk.into(),
            name: pk.into(),
            endpoint: "1.1.1.1:51820".into(),
            tls_cert_sha256: current.into(),
            tls_next_pins: next,
            ..Default::default()
        };
        async fn pins_of(
            client: &mut CoordinatorClient<tonic::transport::Channel>,
            pk: &str,
        ) -> (String, Vec<String>) {
            let map = client
                .get_network_map(NetworkMapRequest {
                    public_key: "B".into(),
                })
                .await
                .unwrap()
                .into_inner();
            let p = map
                .peers
                .into_iter()
                .find(|p| p.public_key == pk)
                .expect("peer in map");
            (p.tls_cert_sha256, p.tls_next_pins)
        }

        client
            .register_device(register("B", "", vec![]))
            .await
            .unwrap();
        // The openssl form is normalized; a duplicate and a copy of the
        // current pin are dropped.
        let p2_openssl = vec!["22"; 32].join(":");
        client
            .register_device(register("A", &p1, vec![p2_openssl, p2.clone(), p1.clone()]))
            .await
            .unwrap();
        assert_eq!(
            pins_of(&mut client, "A").await,
            (p1.clone(), vec![p2.clone()])
        );

        for bad in [
            vec!["not-a-pin".to_string()],
            vec![String::new()],
            (1..=5).map(|i| format!("{i:02}").repeat(32)).collect(),
        ] {
            let err = client
                .register_device(register("A", &p1, bad.clone()))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{bad:?}");
        }
        assert_eq!(
            pins_of(&mut client, "A").await,
            (p1.clone(), vec![p2.clone()]),
            "a refused registration changes nothing"
        );

        // Registration replaces the whole set, so an old client that
        // re-registers without next pins withdraws them.
        client
            .register_device(register("A", &p1, vec![]))
            .await
            .unwrap();
        assert_eq!(pins_of(&mut client, "A").await, (p1.clone(), vec![]));

        // Announce, then complete the roll: the next pin becomes current.
        client
            .register_device(register("A", &p1, vec![p2.clone()]))
            .await
            .unwrap();
        client
            .rotate_key(RotateKeyRequest {
                old_public_key: "A".into(),
                new_public_key: "A2".into(),
                new_tls_cert_sha256: p2.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(pins_of(&mut client, "A2").await, (p2, vec![]));
    }

    /// SEC-002: a verified token cannot register a second/unbound public key —
    /// a leaked or replayed token can't be used to swap in an attacker-chosen
    /// key — but the same identity's own `rotate_key` call (the authorized
    /// rotation path) succeeds and moves the binding.
    #[cfg(feature = "oidc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oidc_token_is_bound_to_its_first_registered_key() {
        use crate::auth::testsign::TestSigner;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tonic::Request;

        let signer = TestSigner::new("k1");
        let verifier =
            std::sync::Arc::new(signer.verifier("https://idp.example", "ferrum-coordinator"));
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::with_auth(registry, verifier);

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

        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = signer.sign(&format!(
            r#"{{"iss":"https://idp.example","aud":"ferrum-coordinator","sub":"alice","exp":{exp}}}"#
        ));
        fn authed<T>(req: T, token: &str) -> Request<T> {
            let mut r = Request::new(req);
            r.metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            r
        }

        // First registration binds alice's token to "AAA".
        client
            .register_device(authed(
                RegisterDeviceRequest {
                    public_key: "AAA".into(),
                    name: "a".into(),
                    endpoint: "1.1.1.1:51820".into(),
                    tags: vec![],
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap();

        // Re-registering the same key is idempotent.
        client
            .register_device(authed(
                RegisterDeviceRequest {
                    public_key: "AAA".into(),
                    name: "a".into(),
                    endpoint: "2.2.2.2:51820".into(),
                    tags: vec![],
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap();

        // The same (still-valid) token cannot register a *different* key.
        let swap = client
            .register_device(authed(
                RegisterDeviceRequest {
                    public_key: "BBB".into(),
                    name: "a".into(),
                    endpoint: "1.1.1.1:51820".into(),
                    tags: vec![],
                    ..Default::default()
                },
                &token,
            ))
            .await;
        assert_eq!(
            swap.unwrap_err().code(),
            tonic::Code::FailedPrecondition,
            "a key swap must be rejected"
        );

        // The authorized rotation path (rotate_key, same token) succeeds and
        // moves the binding.
        client
            .rotate_key(authed(
                RotateKeyRequest {
                    old_public_key: "AAA".into(),
                    new_public_key: "CCC".into(),
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap();

        // The old key is no longer alice's; registering it again is now a
        // key swap and is rejected.
        let stale = client
            .register_device(authed(
                RegisterDeviceRequest {
                    public_key: "AAA".into(),
                    name: "a".into(),
                    endpoint: "1.1.1.1:51820".into(),
                    tags: vec![],
                    ..Default::default()
                },
                &token,
            ))
            .await;
        assert_eq!(stale.unwrap_err().code(), tonic::Code::FailedPrecondition);

        // The rotated-to key is now alice's; re-registering it works.
        client
            .register_device(authed(
                RegisterDeviceRequest {
                    public_key: "CCC".into(),
                    name: "a".into(),
                    endpoint: "1.1.1.1:51820".into(),
                    tags: vec![],
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap();
    }

    // ---- SEC-013: per-RPC key binding, relay role, durable revocation ----

    /// Serve `svc` on loopback and return a connected client.
    async fn start(svc: CoordinatorService) -> CoordinatorClient<tonic::transport::Channel> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinatorServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        CoordinatorClient::connect(format!("http://{addr}"))
            .await
            .unwrap()
    }

    fn device(key: &str) -> RegisterDeviceRequest {
        RegisterDeviceRequest {
            public_key: key.into(),
            name: key.into(),
            endpoint: "1.1.1.1:51820".into(),
            ..Default::default()
        }
    }

    /// A limiter shape that never refills within a test's lifetime.
    fn no_refill(burst: u32) -> crate::limits::RateSpec {
        crate::limits::RateSpec::new(burst, 1e-9)
    }

    fn register_req(key: &str) -> RegisterDeviceRequest {
        RegisterDeviceRequest {
            public_key: key.into(),
            name: "d".into(),
            endpoint: "1.1.1.1:51820".into(),
            ..Default::default()
        }
    }

    fn map_req(key: &str) -> NetworkMapRequest {
        NetworkMapRequest {
            public_key: key.into(),
        }
    }

    #[cfg(feature = "oidc")]
    fn candidates(key: &str) -> PublishCandidatesRequest {
        PublishCandidatesRequest {
            public_key: key.into(),
            candidates: vec!["203.0.113.66:4444".into()],
        }
    }

    /// An OIDC-protected service plus a token minter.
    #[cfg(feature = "oidc")]
    struct Oidc {
        signer: crate::auth::testsign::TestSigner,
    }

    #[cfg(feature = "oidc")]
    impl Oidc {
        fn new() -> Self {
            Self {
                signer: crate::auth::testsign::TestSigner::new("k1"),
            }
        }

        fn service(&self, registry: Arc<Mutex<Registry>>) -> CoordinatorService {
            let verifier = std::sync::Arc::new(
                self.signer
                    .verifier("https://idp.example", "ferrum-coordinator"),
            );
            CoordinatorService::with_auth(registry, verifier)
        }

        /// A token for `sub` carrying `tags`.
        fn token(&self, sub: &str, tags: &[&str]) -> String {
            let exp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600;
            let tags: Vec<String> = tags.iter().map(|t| format!("\"{t}\"")).collect();
            self.signer.sign(&format!(
                r#"{{"iss":"https://idp.example","aud":"ferrum-coordinator","sub":"{sub}","exp":{exp},"tags":[{}]}}"#,
                tags.join(",")
            ))
        }
    }

    #[cfg(feature = "oidc")]
    fn authed<T>(msg: T, token: &str) -> Request<T> {
        let mut r = Request::new(msg);
        r.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        r
    }

    /// SEC-013: with auth on, a device may publish candidates for, fetch, or
    /// watch only the key bound to its own identity. Another device (or an
    /// authenticated caller that never registered) is refused.
    #[cfg(feature = "oidc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rpcs_are_bound_to_the_callers_own_key() {
        let oidc = Oidc::new();
        let mut client = start(oidc.service(test_registry())).await;
        let (alice, bob, carol) = (
            oidc.token("alice", &[]),
            oidc.token("bob", &[]),
            oidc.token("carol", &[]),
        );
        client
            .register_device(authed(device("AAA"), &alice))
            .await
            .unwrap();
        client
            .register_device(authed(device("BBB"), &bob))
            .await
            .unwrap();

        fn denied<T>(r: Result<tonic::Response<T>, Status>) {
            assert_eq!(
                r.map(|_| ()).unwrap_err().code(),
                tonic::Code::PermissionDenied
            );
        }
        // Bob acting as Alice: refused on every key-taking RPC.
        denied(
            client
                .publish_candidates(authed(candidates("AAA"), &bob))
                .await,
        );
        denied(client.get_network_map(authed(map_req("AAA"), &bob)).await);
        denied(client.watch_network_map(authed(map_req("AAA"), &bob)).await);
        // An authenticated identity with no registration at all: refused too.
        denied(client.get_network_map(authed(map_req("AAA"), &carol)).await);

        // Each acting for its own key: fine, and Bob's attempt changed nothing.
        client
            .publish_candidates(authed(candidates("BBB"), &bob))
            .await
            .unwrap();
        let map = client
            .get_network_map(authed(map_req("AAA"), &alice))
            .await
            .unwrap()
            .into_inner();
        let bob_seen = map.peers.iter().find(|p| p.public_key == "BBB").unwrap();
        assert_eq!(bob_seen.candidates, vec!["203.0.113.66:4444".to_string()]);
        let map = client
            .get_network_map(authed(map_req("BBB"), &bob))
            .await
            .unwrap()
            .into_inner();
        let alice_seen = map.peers.iter().find(|p| p.public_key == "AAA").unwrap();
        assert!(
            alice_seen.candidates.is_empty(),
            "bob must not have set alice's"
        );
    }

    /// SEC-013: announcing a relay (advertised to every device) needs the relay
    /// role: the `relay` tag, or an identity on the operator's allowlist.
    #[cfg(feature = "oidc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_heartbeat_requires_the_relay_role() {
        let oidc = Oidc::new();
        let svc = oidc
            .service(test_registry())
            .with_relay_identities(vec!["oidc:ops-relay".into()]);
        let mut client = start(svc).await;
        let beat = || RelayHeartbeatRequest {
            addr: "198.51.100.7:3478".into(),
            draining: false,
        };

        let err = client
            .relay_heartbeat(authed(beat(), &oidc.token("alice", &["dev"])))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        client
            .relay_heartbeat(authed(beat(), &oidc.token("relay-1", &[RELAY_TAG])))
            .await
            .unwrap();
        client
            .relay_heartbeat(authed(beat(), &oidc.token("ops-relay", &[])))
            .await
            .unwrap();
    }

    /// SEC-013: a revocation is durable. The same token can't re-register the
    /// key or bind a fresh one; other identities are unaffected; unrevoke
    /// restores both.
    #[cfg(feature = "oidc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoked_device_cannot_re_register_until_unrevoked() {
        let oidc = Oidc::new();
        let registry = test_registry();
        let mut client = start(oidc.service(registry.clone())).await;
        let (alice, bob) = (oidc.token("alice", &[]), oidc.token("bob", &[]));
        client
            .register_device(authed(device("AAA"), &alice))
            .await
            .unwrap();

        registry.lock().unwrap().revoke("AAA").unwrap();
        for key in ["AAA", "ZZZ"] {
            let err = client
                .register_device(authed(device(key), &alice))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied, "{key}");
        }
        client
            .register_device(authed(device("BBB"), &bob))
            .await
            .unwrap();

        assert!(registry.lock().unwrap().unrevoke("AAA").unwrap());
        client
            .register_device(authed(device("AAA"), &alice))
            .await
            .unwrap();
    }

    fn test_registry() -> Arc<Mutex<Registry>> {
        Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)))
    }

    /// SEC-013 in open mode: a revoked key can't re-register or fetch its map,
    /// and its already-open watch stream is closed with `permission_denied`
    /// instead of receiving the mesh map.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revocation_closes_the_watch_stream_and_blocks_the_key() {
        let registry = test_registry();
        let svc = CoordinatorService::new(registry.clone());
        let changes = svc.changes();
        let mut client = start(svc).await;
        client.register_device(device("AAA")).await.unwrap();
        client.register_device(device("BBB")).await.unwrap();
        let mut stream = client
            .watch_network_map(map_req("AAA"))
            .await
            .unwrap()
            .into_inner();
        assert!(stream.message().await.unwrap().is_some(), "initial map");

        registry.lock().unwrap().revoke("AAA").unwrap();
        let _ = changes.send(()); // what the admin API does after a revoke
        let err = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("stream must react to the revocation")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = client.register_device(device("AAA")).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let err = client.get_network_map(map_req("AAA")).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    /// SEC-006: a registration flood from one source is throttled with
    /// `resource_exhausted` once its burst is spent, and counted in the
    /// aggregate metric; admitted registrations still count as handled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registration_flood_is_throttled_per_source() {
        let limits = LimitsConfig {
            register_per_source: no_refill(3),
            ..LimitsConfig::default()
        };
        let svc = CoordinatorService::new(test_registry()).with_limits(&limits);
        let metrics = svc.metrics();
        let mut client = start(svc).await;

        for i in 0..3 {
            client
                .register_device(register_req(&format!("K{i}")))
                .await
                .unwrap();
        }
        for i in 3..6 {
            let err = client
                .register_device(register_req(&format!("K{i}")))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err:?}");
        }
        let text = metrics.render(3);
        assert!(
            text.contains("ferrum_register_throttled_total 3\n"),
            "{text}"
        );
        assert!(text.contains("ferrum_register_total 3\n"), "{text}");
    }

    /// SEC-006: a heartbeat flood is throttled the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_heartbeat_flood_is_throttled_per_source() {
        let limits = LimitsConfig {
            heartbeat_per_source: no_refill(2),
            ..LimitsConfig::default()
        };
        let svc = CoordinatorService::new(test_registry()).with_limits(&limits);
        let metrics = svc.metrics();
        let mut client = start(svc).await;
        let beat = || RelayHeartbeatRequest {
            addr: "198.51.100.1:3478".into(),
            draining: false,
        };

        client.relay_heartbeat(beat()).await.unwrap();
        client.relay_heartbeat(beat()).await.unwrap();
        let err = client.relay_heartbeat(beat()).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err:?}");
        assert!(metrics
            .render(0)
            .contains("ferrum_relay_heartbeat_throttled_total 1\n"));
    }

    /// SEC-006: concurrent watch streams past the per-source cap are refused,
    /// and closing one frees its slot promptly (not only at the next map push).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn excess_watch_streams_are_refused_and_slots_are_released() {
        let limits = LimitsConfig {
            watch_streams_per_source: 2,
            ..LimitsConfig::default()
        };
        let svc = CoordinatorService::new(test_registry()).with_limits(&limits);
        let metrics = svc.metrics();
        let mut client = start(svc).await;
        let watch_req = || NetworkMapRequest {
            public_key: "AAA".into(),
        };

        let mut first = client
            .watch_network_map(watch_req())
            .await
            .unwrap()
            .into_inner();
        first.message().await.unwrap().expect("initial map");
        let mut second = client
            .watch_network_map(watch_req())
            .await
            .unwrap()
            .into_inner();
        second.message().await.unwrap().expect("initial map");

        let err = client.watch_network_map(watch_req()).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err:?}");
        assert!(metrics
            .render(0)
            .contains("ferrum_watch_streams_rejected_total 1\n"));

        // Close one stream with no registry change afterwards: the slot must
        // still come back.
        drop(first);
        let mut reopened = None;
        for _ in 0..100 {
            match client.watch_network_map(watch_req()).await {
                Ok(s) => {
                    reopened = Some(s.into_inner());
                    break;
                }
                Err(e) => {
                    assert_eq!(e.code(), tonic::Code::ResourceExhausted);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
        let mut reopened = reopened.expect("closing a stream must release its slot");
        reopened.message().await.unwrap().expect("initial map");
        drop(second);
    }

    /// SEC-006: with OIDC on, the per-identity limit applies independently of
    /// the source: one subject's flood doesn't throttle another subject behind
    /// the same address.
    #[cfg(feature = "oidc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registration_limit_is_per_identity_when_authenticated() {
        use crate::auth::testsign::TestSigner;
        use std::time::{SystemTime, UNIX_EPOCH};

        let signer = TestSigner::new("k1");
        let verifier =
            std::sync::Arc::new(signer.verifier("https://idp.example", "ferrum-coordinator"));
        let limits = LimitsConfig {
            register_per_identity: no_refill(2),
            ..LimitsConfig::default()
        };
        let svc = CoordinatorService::with_auth(test_registry(), verifier).with_limits(&limits);
        let mut client = start(svc).await;

        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token_for = |sub: &str| {
            signer.sign(&format!(
                r#"{{"iss":"https://idp.example","aud":"ferrum-coordinator","sub":"{sub}","exp":{exp}}}"#
            ))
        };
        let authed = |key: &str, token: &str| {
            let mut r = Request::new(register_req(key));
            r.metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            r
        };
        let (alice, bob) = (token_for("alice"), token_for("bob"));

        client.register_device(authed("AAA", &alice)).await.unwrap();
        client.register_device(authed("AAA", &alice)).await.unwrap();
        let err = client
            .register_device(authed("AAA", &alice))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err:?}");
        // Same source, different identity: unaffected.
        client.register_device(authed("BBB", &bob)).await.unwrap();
    }
}
