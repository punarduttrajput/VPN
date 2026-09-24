//! Helper-service IPC protocol (Phase 5 — privileged-helper, FR5).
//!
//! The Windows desktop runs its data plane in a separate **privileged service**
//! (`ferrum-helper.exe`, see [`crate::service`]) so the GUI itself need not be
//! elevated: only the service touches the wintun adapter and the Windows
//! Filtering Platform. The GUI is an ordinary unprivileged process that talks to
//! the service over a local **named pipe**. This module is the wire contract
//! between them.
//!
//! Shape of a session: the GUI opens one pipe connection and sends a
//! [`Request::Connect`] carrying a [`ConnectConfig`] (the connect-form fields).
//! The service acknowledges with [`ServerMessage::Ack`] (or
//! [`ServerMessage::Error`] if the config is rejected up front) and then streams
//! [`ServerMessage::Event`] frames — the same state/peers/kill-switch signals the
//! in-process core emits — for the life of the connection. The GUI can send
//! further [`Request`]s (e.g. [`Request::SetKillSwitch`]) on the same connection;
//! closing the pipe (or [`Request::Disconnect`]) winds the data plane down. So the
//! **pipe-connection lifetime is the session lifetime** — if the GUI dies, the
//! service sees EOF and tears the tunnel down, and the kill-switch with it.
//!
//! Framing is length-prefixed JSON: a 4-byte big-endian length followed by that
//! many bytes of UTF-8 JSON. JSON keeps the contract debuggable and matches the
//! types the rest of the shell already (de)serializes; the protocol is local-only
//! (a named pipe / Unix socket), never on the network. Frames are size-capped so a
//! corrupt or hostile length can't trigger an unbounded allocation.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The named-pipe path the service listens on / the GUI connects to (Windows).
/// A fixed, app-specific name under the local pipe namespace.
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\ferrum-helper";

/// Largest frame we will read, as a guard against a corrupt/hostile length prefix
/// driving an unbounded allocation. A `ConnectConfig` is well under 64 KiB.
const MAX_FRAME_LEN: u32 = 1 << 20; // 1 MiB

/// Everything the service needs to bring up the data plane, sent by the GUI in a
/// [`Request::Connect`]. Mirrors the connect-form fields the in-process path used
/// to consume directly — the privileged service now performs the registration,
/// candidate gathering, TUN open, and supervised mesh run on the GUI's behalf.
///
/// The WireGuard **private** key travels over the local pipe only (never to the
/// coordinator, never over the network); the advertised public key is derived
/// from it in the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectConfig {
    /// Coordinator URL, e.g. `http://10.0.0.1:50051`.
    pub coordinator: String,
    /// WireGuard private key (base64). Used to build per-peer sessions; not sent
    /// to the coordinator.
    pub private_key: String,
    /// Device name advertised to the coordinator.
    pub name: String,
    /// Advertised endpoint (`ip:port`) for other peers to reach this node.
    pub endpoint: String,
    /// ACL tags advertised to the coordinator.
    pub tags: Vec<String>,
    /// Local UDP port the data plane binds (and STUN reuses to gather candidates).
    pub listen_port: u16,
    /// Wire transport: `"udp"` | `"quic"` | `"masque"` (case-insensitive).
    pub transport_mode: String,
    /// MASQUE proxy `ip:port` (required for `transport_mode == "masque"`).
    #[serde(default)]
    pub masque_proxy: Option<String>,
    /// TLS / HTTP-3 `:authority` for QUIC/MASQUE (defaults to `ferrum` when unset).
    #[serde(default)]
    pub server_name: Option<String>,
    /// Expected SHA-256 fingerprint(s) of the MASQUE proxy's TLS certificate
    /// (SEC-004; hex, `:`-separated or not). Empty connects with an "outer
    /// transport unauthenticated" warning. No GUI field yet.
    #[serde(default)]
    pub cert_pins: Vec<String>,
    /// STUN server `ip:port`; when set, the service gathers + publishes candidates.
    #[serde(default)]
    pub stun_server: Option<String>,
    /// Local relay `ip:port` override of the coordinator-advertised relay.
    #[serde(default)]
    pub relay: Option<String>,
    /// Optional OIDC bearer token for an authenticated coordinator.
    #[serde(default)]
    pub token: Option<String>,
    /// Whether the kill-switch is armed for this session (the service enforces it
    /// in the OS firewall as the tunnel goes up/down).
    #[serde(default)]
    pub kill_switch: bool,
    /// DNS resolvers (bare IPs) to enforce while connected — a local override
    /// of the coordinator-advertised list (PRD leak-protection.md; empty means
    /// use whatever the coordinator advertises). A GUI field lands in M5.
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// IPv6 leak policy: `"auto"` (default when empty) | `"block"` | `"tunnel"`
    /// | `"off"` — see `ferrum_core::config::Ipv6LeakPolicy`.
    #[serde(default)]
    pub ipv6_policy: String,
}

/// A message from the GUI to the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Bring up the data plane with this configuration. The service replies
    /// [`ServerMessage::Ack`] then streams events for the connection's lifetime.
    Connect(Box<ConnectConfig>),
    /// Wind the data plane down (equivalent to closing the connection).
    Disconnect,
    /// Arm/disarm the kill-switch mid-session.
    SetKillSwitch(bool),
    /// Ask for the current state (answered by [`ServerMessage::Status`]).
    GetStatus,
    /// Liveness probe (answered by [`ServerMessage::Ack`]); used by the GUI to
    /// detect whether the service is installed and running.
    Ping,
}

/// A message from the service to the GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// A request was accepted (e.g. a valid `Connect`, or a `Ping`).
    Ack,
    /// A request was rejected, or the data plane failed to start, with a reason.
    Error(String),
    /// Answer to [`Request::GetStatus`].
    Status { state: String, peers: u32 },
    /// An asynchronous data-plane event (the service's view of the core's stream).
    Event(Event),
}

/// An asynchronous event the service pushes as the data plane runs — the
/// pipe-side mirror of `ferrum_client_core::ClientEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// Connection state changed (`Disconnected`/`Connecting`/`Connected`/…).
    State(String),
    /// The peer count changed.
    Peers(u32),
    /// A non-fatal data-plane error occurred.
    Error(String),
    /// The kill-switch block/release signal flipped (the service has already
    /// enforced it in the firewall; the GUI reflects it).
    TrafficBlocked(bool),
}

/// Write one length-prefixed JSON frame.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if bytes.len() as u64 > MAX_FRAME_LEN as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds maximum length",
        ));
    }
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed JSON frame. Returns `Ok(None)` on a clean EOF at a
/// frame boundary (the peer closed the connection) — the caller treats that as a
/// graceful end of session.
pub async fn read_frame<R, T>(r: &mut R) -> std::io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        // EOF exactly at a frame boundary: the peer hung up. Anything else
        // (a truncated length prefix) is a real error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length exceeds maximum",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    let msg = serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> ConnectConfig {
        ConnectConfig {
            coordinator: "http://10.0.0.1:50051".into(),
            private_key: "cHJpdmtleQ==".into(),
            name: "node-a".into(),
            endpoint: "203.0.113.1:51820".into(),
            tags: vec!["work".into(), "laptop".into()],
            listen_port: 51820,
            transport_mode: "udp".into(),
            masque_proxy: None,
            server_name: None,
            cert_pins: Vec::new(),
            stun_server: Some("198.51.100.1:3478".into()),
            relay: None,
            token: None,
            kill_switch: true,
            dns_servers: vec!["10.99.0.53".into()],
            ipv6_policy: "auto".into(),
        }
    }

    #[test]
    fn connect_config_json_roundtrips() {
        let cfg = sample_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ConnectConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn connect_config_tolerates_missing_optionals() {
        // Older/leaner GUIs may omit the `#[serde(default)]` fields entirely.
        let json = r#"{
            "coordinator": "http://c",
            "private_key": "k",
            "name": "n",
            "endpoint": "1.2.3.4:5",
            "tags": [],
            "listen_port": 51820,
            "transport_mode": "udp"
        }"#;
        let cfg: ConnectConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.masque_proxy, None);
        assert!(!cfg.kill_switch);
    }

    #[tokio::test]
    async fn frame_roundtrips_over_a_pipe_buffer() {
        // A request out, a server message back — through an in-memory duplex so the
        // codec is exercised exactly as it is over a real pipe.
        let (mut a, mut b) = tokio::io::duplex(4096);

        let req = Request::Connect(Box::new(sample_config()));
        write_frame(&mut a, &req).await.unwrap();
        let got: Request = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got, req);

        let msg = ServerMessage::Event(Event::TrafficBlocked(true));
        write_frame(&mut b, &msg).await.unwrap();
        let got: ServerMessage = read_frame(&mut a).await.unwrap().unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn multiple_frames_stream_in_order() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let msgs = [
            ServerMessage::Ack,
            ServerMessage::Event(Event::State("Connecting".into())),
            ServerMessage::Event(Event::State("Connected".into())),
            ServerMessage::Event(Event::Peers(2)),
        ];
        for m in &msgs {
            write_frame(&mut a, m).await.unwrap();
        }
        drop(a); // half-close so the reader sees EOF after the last frame
        for expected in &msgs {
            let got: ServerMessage = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(&got, expected);
        }
        // Clean EOF at the frame boundary → None, not an error.
        assert!(read_frame::<_, ServerMessage>(&mut b)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn an_oversized_length_prefix_is_rejected() {
        // Hand-craft a frame whose declared length exceeds the cap; the reader must
        // refuse it rather than try to allocate it.
        let (mut a, mut b) = tokio::io::duplex(16);
        let writer = tokio::spawn(async move {
            let _ = a.write_all(&(MAX_FRAME_LEN + 1).to_be_bytes()).await;
        });
        let err = read_frame::<_, ServerMessage>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let _ = writer.await;
    }
}
