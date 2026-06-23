//! High-level VPN client facade (PRD Phase 5, FR1 / M1).
//!
//! [`FerrumClient`] is the single shared entry point every native shell (iOS,
//! Android, desktop) drives — the box labelled "connection state machine" in the
//! Phase 5 architecture. It owns the connection lifecycle, talks to the
//! coordinator through [`ControlClient`](crate::ControlClient), surfaces the peer
//! set, and emits state-change events over a subscription channel.
//!
//! The types here are deliberately FFI-friendly (plain enums and records of
//! strings/vecs, no generics across the boundary) so a thin `uniffi` annotation
//! layer can wrap them into Swift/Kotlin bindings later. The data-plane bring-up
//! (TUN device + `run_mesh`) is supplied by each platform shell, which owns the
//! OS VPN integration; this facade owns everything platform-independent: control
//! sync, the state machine, and the peer view.

use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::{ControlClient, Error, PeerSpec};

/// Capacity of the event broadcast buffer (events are small and consumers are
/// expected to keep up; a lagging consumer simply misses intermediate events).
const EVENT_CAPACITY: usize = 64;

/// The connection lifecycle as shown to the UI (FR1/FR5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ConnectionState {
    /// No tunnel; idle.
    #[default]
    Disconnected,
    /// Registering with the coordinator and building the peer set.
    Connecting,
    /// Tunnel is up and the peer set is loaded.
    Connected,
    /// Lost the tunnel and re-establishing (network change, peer restart).
    Reconnecting,
    /// The last connect attempt failed; see the accompanying event reason.
    Failed,
}

/// How this client currently reaches a peer (Phase 4 mesh state, surfaced in the
/// connection-detail UI per FR5). Until live path probing lands this is
/// best-effort: a coordinator-provided endpoint is reported as `Direct`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PeerPath {
    /// A direct peer-to-peer path.
    Direct,
    /// Traffic is relayed (e.g. through a MASQUE proxy).
    Relay,
    /// Path not yet determined.
    Unknown,
}

/// One peer as presented to the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PeerStatus {
    /// Peer's base64 public key (its identity).
    pub public_key: String,
    /// Peer's reachable endpoint `ip:port`.
    pub endpoint: String,
    /// CIDRs routed to this peer.
    pub allowed_ips: Vec<String>,
    /// Direct vs relayed path (FR5).
    pub path: PeerPath,
}

impl PeerStatus {
    fn from_spec(spec: PeerSpec) -> Self {
        // Without live probing, treat a coordinator-listed endpoint as direct.
        let path = if spec.endpoint.is_empty() {
            PeerPath::Unknown
        } else {
            PeerPath::Direct
        };
        Self {
            public_key: spec.public_key,
            endpoint: spec.endpoint,
            allowed_ips: spec.allowed_ips,
            path,
        }
    }
}

/// An event emitted to subscribers when the client's observable state changes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ClientEvent {
    /// The connection state transitioned.
    StateChanged(ConnectionState),
    /// The peer set changed; carries the new peer count. (`u32`, not `usize`, so
    /// the type crosses the FFI boundary.)
    PeersUpdated(u32),
    /// A non-fatal or fatal error occurred; carries a human-readable reason.
    Error(String),
}

/// Identity + registration details a client presents to the coordinator.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ClientIdentity {
    /// This device's base64 public key.
    pub public_key: String,
    /// Human-friendly device name.
    pub name: String,
    /// This device's reachable endpoint advertised to peers (`ip:port`).
    pub endpoint: String,
    /// Policy tags (ignored by the coordinator when OIDC auth derives them).
    pub tags: Vec<String>,
}

#[derive(Default)]
struct Inner {
    state: ConnectionState,
    address: Option<String>,
    peers: Vec<PeerStatus>,
}

/// The shared client core: connection state machine + control-plane sync.
///
/// Cheap to clone (`Arc`-backed); clones share the same state and event stream.
#[derive(Clone)]
pub struct FerrumClient {
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<ClientEvent>,
}

impl Default for FerrumClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FerrumClient {
    /// Create a fresh, disconnected client.
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            events,
        }
    }

    /// Subscribe to state-change events. The returned receiver yields every
    /// [`ClientEvent`] emitted after this call (the UI typically calls `status`
    /// once for the current value, then drives off this stream).
    pub fn subscribe(&self) -> broadcast::Receiver<ClientEvent> {
        self.events.subscribe()
    }

    /// The current connection state.
    pub fn status(&self) -> ConnectionState {
        self.inner.lock().expect("client mutex poisoned").state
    }

    /// The assigned tunnel address, once connected (e.g. `10.8.0.2/32`).
    pub fn address(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("client mutex poisoned")
            .address
            .clone()
    }

    /// The current peer list (FR1 `peer_list`).
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.inner
            .lock()
            .expect("client mutex poisoned")
            .peers
            .clone()
    }

    /// Connect: register with the coordinator at `coordinator` and load the peer
    /// set. Drives the state machine Disconnected/Failed → Connecting → Connected
    /// (or → Failed), emitting an event on each transition.
    ///
    /// The OS data-plane bring-up (TUN + `run_mesh`) is the platform shell's job;
    /// this establishes the control-plane session and the peer view it needs.
    pub async fn connect(
        &self,
        coordinator: impl Into<String>,
        identity: &ClientIdentity,
    ) -> Result<(), Error> {
        self.set_state(ConnectionState::Connecting);

        let result = self.do_connect(coordinator.into(), identity).await;
        match result {
            Ok(()) => {
                self.set_state(ConnectionState::Connected);
                Ok(())
            }
            Err(e) => {
                self.emit(ClientEvent::Error(e.to_string()));
                self.set_state(ConnectionState::Failed);
                Err(e)
            }
        }
    }

    async fn do_connect(
        &self,
        coordinator: String,
        identity: &ClientIdentity,
    ) -> Result<(), Error> {
        let mut control = ControlClient::connect(coordinator).await?;
        let plan = control
            .plan(
                &identity.public_key,
                &identity.name,
                &identity.endpoint,
                &identity.tags,
            )
            .await?;

        let peers: Vec<PeerStatus> = plan.peers.into_iter().map(PeerStatus::from_spec).collect();
        let count = peers.len();
        {
            let mut inner = self.inner.lock().expect("client mutex poisoned");
            inner.address = Some(plan.address);
            inner.peers = peers;
        }
        self.emit(ClientEvent::PeersUpdated(count as u32));
        Ok(())
    }

    /// Disconnect: tear down the session view and return to `Disconnected`.
    pub fn disconnect(&self) {
        {
            let mut inner = self.inner.lock().expect("client mutex poisoned");
            inner.peers.clear();
            inner.address = None;
        }
        self.emit(ClientEvent::PeersUpdated(0));
        self.set_state(ConnectionState::Disconnected);
    }

    /// Replace the peer set (e.g. from a live `WatchNetworkMap` push) and notify
    /// subscribers. Used by the platform shell's watch loop to keep the UI fresh.
    pub fn apply_peers(&self, specs: Vec<PeerSpec>) {
        let peers: Vec<PeerStatus> = specs.into_iter().map(PeerStatus::from_spec).collect();
        let count = peers.len();
        self.inner.lock().expect("client mutex poisoned").peers = peers;
        self.emit(ClientEvent::PeersUpdated(count as u32));
    }

    /// Set the connection state and broadcast the transition (idempotent: a
    /// no-op state set emits nothing).
    fn set_state(&self, next: ConnectionState) {
        {
            let mut inner = self.inner.lock().expect("client mutex poisoned");
            if inner.state == next {
                return;
            }
            inner.state = next;
        }
        self.emit(ClientEvent::StateChanged(next));
    }

    fn emit(&self, event: ClientEvent) {
        // Ignore the "no subscribers" error — events are best-effort.
        let _ = self.events.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use ferrum_coordinator::{CoordinatorService, Registry};
    use std::net::Ipv4Addr;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    async fn start_coordinator() -> String {
        let registry = StdArc::new(StdMutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
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

    fn identity(pk: &str, name: &str, endpoint: &str) -> ClientIdentity {
        ClientIdentity {
            public_key: pk.into(),
            name: name.into(),
            endpoint: endpoint.into(),
            tags: vec![],
        }
    }

    #[test]
    fn new_client_starts_disconnected() {
        let c = FerrumClient::new();
        assert_eq!(c.status(), ConnectionState::Disconnected);
        assert!(c.peers().is_empty());
        assert!(c.address().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_drives_state_and_loads_peers() {
        let url = start_coordinator().await;
        let a = FerrumClient::new();
        let b = FerrumClient::new();

        // A connects first: assigned .2, no peers yet.
        a.connect(url.clone(), &identity("AAA", "laptop", "1.1.1.1:51820"))
            .await
            .unwrap();
        assert_eq!(a.status(), ConnectionState::Connected);
        assert_eq!(a.address().as_deref(), Some("10.8.0.2/32"));
        assert!(a.peers().is_empty());

        // B connects: assigned .3, sees A as a peer.
        b.connect(url, &identity("BBB", "gateway", "2.2.2.2:51820"))
            .await
            .unwrap();
        assert_eq!(b.status(), ConnectionState::Connected);
        let peers = b.peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, "AAA");
        assert_eq!(peers[0].endpoint, "1.1.1.1:51820");
        assert_eq!(peers[0].path, PeerPath::Direct);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribers_observe_state_transitions() {
        let url = start_coordinator().await;
        let c = FerrumClient::new();
        let mut events = c.subscribe();

        c.connect(url, &identity("AAA", "laptop", "1.1.1.1:51820"))
            .await
            .unwrap();

        // Expect: Connecting, PeersUpdated(0), Connected (in order).
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::StateChanged(ConnectionState::Connecting)
        );
        assert_eq!(events.recv().await.unwrap(), ClientEvent::PeersUpdated(0));
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::StateChanged(ConnectionState::Connected)
        );

        c.disconnect();
        assert_eq!(events.recv().await.unwrap(), ClientEvent::PeersUpdated(0));
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::StateChanged(ConnectionState::Disconnected)
        );
        assert_eq!(c.status(), ConnectionState::Disconnected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_failure_transitions_to_failed() {
        let c = FerrumClient::new();
        // Nothing listening on this port -> connect fails.
        let err = c
            .connect(
                "http://127.0.0.1:1",
                &identity("AAA", "laptop", "1.1.1.1:51820"),
            )
            .await;
        assert!(err.is_err());
        assert_eq!(c.status(), ConnectionState::Failed);
    }
}
