//! uniffi FFI layer for the Phase 5 client facade (FR1).
//!
//! [`FfiFerrumClient`] is a thin, FFI-safe wrapper around [`FerrumClient`](crate::FerrumClient):
//! the native shells (iOS/Android/desktop) drive *this* object through the
//! generated Swift/Kotlin bindings. It is intentionally minimal — the same
//! connection lifecycle, peer view, and event stream as the core facade, with a
//! shape uniffi can export:
//!
//! - the core's `Clone` + `broadcast::Sender` don't map onto a uniffi `Object`,
//!   so we wrap rather than annotate `FerrumClient` directly;
//! - events are delivered **pull-style** via [`FfiFerrumClient::next_event`] (the
//!   wrapper holds a dedicated `broadcast::Receiver`) rather than a callback
//!   interface — a foreign caller loops on it from a `Task`/coroutine. A
//!   push/callback variant can be added later if a shell wants it.
//!
//! The OS data-plane bring-up (TUN + `run_mesh`) remains each platform shell's
//! job; this exposes only the platform-independent control surface.

use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};

use crate::{
    ClientEvent, ClientIdentity, ConnectionState, Error, FerrumClient, PeerSpec, PeerStatus,
    ReconnectPolicy,
};

/// FFI handle to a VPN client. Construct with [`FfiFerrumClient::new`], then drive
/// the connection and observe state through the exported methods.
#[derive(uniffi::Object)]
pub struct FfiFerrumClient {
    inner: FerrumClient,
    /// Dedicated receiver backing `next_event`; a `Mutex` because uniffi methods
    /// take `&self` and `broadcast::Receiver::recv` needs `&mut`.
    events: Mutex<broadcast::Receiver<ClientEvent>>,
    /// Shutdown trigger for a running [`run`](FfiFerrumClient::run); `stop` takes and
    /// fires it. `std::sync::Mutex` (never held across an await).
    #[cfg(feature = "data-plane")]
    shutdown: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiFerrumClient {
    /// Create a fresh, disconnected client.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let inner = FerrumClient::new();
        let events = Mutex::new(inner.subscribe());
        Arc::new(Self {
            inner,
            events,
            #[cfg(feature = "data-plane")]
            shutdown: std::sync::Mutex::new(None),
        })
    }

    /// Connect: register with the coordinator at `coordinator` (e.g.
    /// `http://10.0.0.1:50051`) and load the peer set, driving the state machine
    /// and emitting events. Errors leave the client in `Failed`.
    pub async fn connect(
        &self,
        coordinator: String,
        identity: ClientIdentity,
    ) -> Result<(), Error> {
        self.inner.connect(coordinator, &identity).await
    }

    /// Connect with automatic reconnect (FR5): on failure, transition to
    /// `Reconnecting` and retry with exponential backoff per `policy` rather than
    /// failing at the first error. Resolves once connected, or errors once the
    /// retries are exhausted. A `disconnect` cancels an in-flight loop.
    pub async fn connect_with_retry(
        &self,
        coordinator: String,
        identity: ClientIdentity,
        policy: ReconnectPolicy,
    ) -> Result<(), Error> {
        self.inner
            .connect_with_retry(coordinator, &identity, &policy)
            .await
    }

    /// Tear down the session view and return to `Disconnected`. Also cancels any
    /// in-flight `connect_with_retry` loop.
    pub fn disconnect(&self) {
        self.inner.disconnect()
    }

    /// Rotate this device's static key with the coordinator (FR3): move the
    /// registration from `old_public_key` to `new_public_key`, keeping the tunnel
    /// IP and metadata, and return the unchanged assigned CIDR. The shell
    /// generates the new keypair locally, calls this, then re-runs its data plane
    /// with the new private key so peers re-handshake to it.
    pub async fn rotate_key(
        &self,
        coordinator: String,
        old_public_key: String,
        new_public_key: String,
    ) -> Result<String, Error> {
        self.inner
            .rotate_key(coordinator, &old_public_key, &new_public_key)
            .await
    }

    /// Attach (or clear) an OIDC bearer token applied to every coordinator RPC —
    /// required when the coordinator runs with OIDC auth. Set it before
    /// `connect`/`run`; it is re-read on every reconnect.
    pub fn set_token(&self, token: Option<String>) {
        self.inner.set_token(token)
    }

    /// Arm or disarm the kill-switch (FR5). When armed, non-tunnel traffic should
    /// be blocked whenever the tunnel is not `Connected`; observe the live intent
    /// via [`traffic_blocked`](FfiFerrumClient::traffic_blocked) and the
    /// `TrafficBlocked` event, and enforce it in the platform shell's firewall.
    pub fn set_kill_switch(&self, enabled: bool) {
        self.inner.set_kill_switch(enabled)
    }

    /// Whether the kill-switch is armed (the policy choice).
    pub fn kill_switch_enabled(&self) -> bool {
        self.inner.kill_switch_enabled()
    }

    /// Whether non-tunnel traffic should be blocked right now (kill-switch armed
    /// and tunnel not `Connected`).
    pub fn traffic_blocked(&self) -> bool {
        self.inner.traffic_blocked()
    }

    /// The current connection state.
    pub fn status(&self) -> ConnectionState {
        self.inner.status()
    }

    /// The assigned tunnel address, once connected (e.g. `10.8.0.2/32`).
    pub fn address(&self) -> Option<String> {
        self.inner.address()
    }

    /// The current peer list.
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.inner.peers()
    }

    /// Replace the peer set (e.g. driven from a live watch loop) and notify.
    pub fn apply_peers(&self, peers: Vec<PeerSpec>) {
        self.inner.apply_peers(peers)
    }

    /// Await the next event, or `None` once the client is dropped. A foreign
    /// caller loops on this to track state/peer changes. If the consumer falls
    /// behind and misses events, those are skipped (only the latest matter).
    pub async fn next_event(&self) -> Option<ClientEvent> {
        let mut rx = self.events.lock().await;
        loop {
            match rx.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// Data-plane entry points (the `data-plane` feature): a native shell hands in
/// the OS TUN file descriptor and this runs the full mesh data plane on it.
#[cfg(feature = "data-plane")]
#[uniffi::export(async_runtime = "tokio")]
impl FfiFerrumClient {
    /// Run the VPN on a platform-provided TUN `tun_fd`: register with the
    /// `coordinator`, bring up the mesh over a UDP underlay bound to
    /// `listen_port`, and keep it converged until [`stop`](FfiFerrumClient::stop).
    ///
    /// Blocks (as an async call) for the lifetime of the tunnel; the foreign
    /// caller runs it on a background task and calls `stop` to end it.
    /// `private_key` is this device's WireGuard key (used to build peer sessions;
    /// never sent to the coordinator). `stun_server` (`ip:port`), when given,
    /// enables NAT-traversal candidate gathering (host + server-reflexive) which
    /// is published to the coordinator for peers to probe (PRD Phase 4). `relay`
    /// (`ip:port`) is a local relay-fallback override; when `None`, the
    /// coordinator's advertised relay (if any) is used. With a relay the mesh
    /// runs direct + relay at once, preferring direct per peer. Returns when the
    /// tunnel is torn down.
    // Each parameter is an independent input the foreign shell must supply; a
    // params struct would only move the noise across the FFI boundary.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        tun_fd: i32,
        coordinator: String,
        identity: ClientIdentity,
        private_key: String,
        listen_port: u16,
        stun_server: Option<String>,
        relay: Option<String>,
    ) -> Result<(), Error> {
        let device =
            ferrum_tunnel::device::from_fd(tun_fd).map_err(|e| Error::DataPlane(e.to_string()))?;
        let bind: std::net::SocketAddr = format!("0.0.0.0:{listen_port}")
            .parse()
            .map_err(|e| Error::DataPlane(format!("bind address: {e}")))?;

        // Gather NAT-traversal candidates *before* binding the data-plane socket
        // (STUN briefly binds the same port). A malformed STUN address is an
        // error; a missing one simply skips gathering.
        let stun = match stun_server {
            Some(s) => Some(
                s.parse::<std::net::SocketAddr>()
                    .map_err(|e| Error::DataPlane(format!("stun_server '{s}': {e}")))?,
            ),
            None => None,
        };
        let candidates: Vec<String> = ferrum_transport::stun::gather_candidates(listen_port, stun)
            .await
            .iter()
            .map(|a| a.to_string())
            .collect();

        let transport = ferrum_transport::UdpMeshTransport::bind(bind)
            .await
            .map_err(|e| Error::DataPlane(e.to_string()))?;

        // Install a fresh shutdown trigger; `stop` fires it.
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        *self.shutdown.lock().expect("shutdown mutex poisoned") = Some(stop_tx);

        crate::data_plane::run_mesh_session(
            &self.inner,
            &coordinator,
            &identity,
            &private_key,
            &candidates,
            device,
            transport,
            relay,
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
    }

    /// Signal a running [`run`](FfiFerrumClient::run) to tear down; the client
    /// returns to `Disconnected`. A no-op if nothing is running.
    pub fn stop(&self) {
        if let Some(tx) = self
            .shutdown
            .lock()
            .expect("shutdown mutex poisoned")
            .take()
        {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_client_starts_disconnected() {
        let c = FfiFerrumClient::new();
        assert_eq!(c.status(), ConnectionState::Disconnected);
        assert!(c.peers().is_empty());
        assert!(c.address().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ffi_next_event_observes_disconnect() {
        let c = FfiFerrumClient::new();
        // A local-only transition we can drive without a coordinator.
        c.apply_peers(vec![]);
        assert_eq!(c.next_event().await, Some(ClientEvent::PeersUpdated(0)));
    }
}
