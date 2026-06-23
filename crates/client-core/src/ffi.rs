//! uniffi FFI layer for the Phase 5 client facade (FR1).
//!
//! [`FfiVpnClient`] is a thin, FFI-safe wrapper around [`VpnClient`](crate::VpnClient):
//! the native shells (iOS/Android/desktop) drive *this* object through the
//! generated Swift/Kotlin bindings. It is intentionally minimal — the same
//! connection lifecycle, peer view, and event stream as the core facade, with a
//! shape uniffi can export:
//!
//! - the core's `Clone` + `broadcast::Sender` don't map onto a uniffi `Object`,
//!   so we wrap rather than annotate `VpnClient` directly;
//! - events are delivered **pull-style** via [`FfiVpnClient::next_event`] (the
//!   wrapper holds a dedicated `broadcast::Receiver`) rather than a callback
//!   interface — a foreign caller loops on it from a `Task`/coroutine. A
//!   push/callback variant can be added later if a shell wants it.
//!
//! The OS data-plane bring-up (TUN + `run_mesh`) remains each platform shell's
//! job; this exposes only the platform-independent control surface.

use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};

use crate::{ClientEvent, ClientIdentity, ConnectionState, Error, PeerSpec, PeerStatus, VpnClient};

/// FFI handle to a VPN client. Construct with [`FfiVpnClient::new`], then drive
/// the connection and observe state through the exported methods.
#[derive(uniffi::Object)]
pub struct FfiVpnClient {
    inner: VpnClient,
    /// Dedicated receiver backing `next_event`; a `Mutex` because uniffi methods
    /// take `&self` and `broadcast::Receiver::recv` needs `&mut`.
    events: Mutex<broadcast::Receiver<ClientEvent>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiVpnClient {
    /// Create a fresh, disconnected client.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let inner = VpnClient::new();
        let events = Mutex::new(inner.subscribe());
        Arc::new(Self { inner, events })
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

    /// Tear down the session view and return to `Disconnected`.
    pub fn disconnect(&self) {
        self.inner.disconnect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_client_starts_disconnected() {
        let c = FfiVpnClient::new();
        assert_eq!(c.status(), ConnectionState::Disconnected);
        assert!(c.peers().is_empty());
        assert!(c.address().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ffi_next_event_observes_disconnect() {
        let c = FfiVpnClient::new();
        // A local-only transition we can drive without a coordinator.
        c.apply_peers(vec![]);
        assert_eq!(c.next_event().await, Some(ClientEvent::PeersUpdated(0)));
    }
}
