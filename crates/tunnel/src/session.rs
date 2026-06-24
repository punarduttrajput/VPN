//! A thin, safe wrapper over a boringtun WireGuard session (PRD FR2).
//!
//! Owns a single [`Tunn`] and exposes the three operations the event loop needs:
//! encapsulate (plaintext -> encrypted), decapsulate (encrypted -> plaintext),
//! and timer servicing (handshake / keepalive). The wrapper never logs key
//! material or packet payloads (NFR3 / PRD §5 FR5).

use std::net::IpAddr;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::{Result, TunnelError};

/// Maximum datagram we will ever need to hold (WireGuard transport overhead is
/// 32 bytes on top of the inner packet; 65535 + headroom covers any IP packet).
pub const MAX_PACKET: usize = 65_535 + 64;

/// The outcome of feeding data into the session.
#[derive(Debug)]
pub enum Action<'a> {
    /// Nothing to do.
    Done,
    /// Send these bytes to the peer over UDP.
    SendToPeer(&'a [u8]),
    /// Write this decrypted IP packet to the TUN device.
    WriteToTun(&'a [u8], IpAddr),
}

/// A WireGuard session bound to one local key and one peer key.
pub struct Session {
    tunn: Tunn,
    /// The peer's static public key (WireGuard identity), kept for routing the
    /// session over a public-key-keyed relay underlay.
    peer_public: [u8; 32],
}

impl Session {
    /// Build a session from base64 keys (as they appear in config).
    pub fn from_base64(private_key_b64: &str, peer_public_b64: &str) -> Result<Self> {
        let priv_bytes =
            ferrum_core::keys::decode_key(private_key_b64).map_err(TunnelError::Core)?;
        let pub_bytes =
            ferrum_core::keys::decode_key(peer_public_b64).map_err(TunnelError::Core)?;
        Self::from_bytes(priv_bytes, pub_bytes, 0)
    }

    /// Build a session from raw 32-byte keys and a session index.
    pub fn from_bytes(private: [u8; 32], peer_public: [u8; 32], index: u32) -> Result<Self> {
        let peer_public_bytes = peer_public;
        let static_private = StaticSecret::from(private);
        let peer_public = PublicKey::from(peer_public);
        let tunn = Tunn::new(
            static_private,
            peer_public,
            None, // no preshared key in Phase 1
            None, // no persistent keepalive in Phase 1
            index,
            None, // no rate limiter (single peer)
        )
        .map_err(|e| TunnelError::Session(e.to_string()))?;
        Ok(Self {
            tunn,
            peer_public: peer_public_bytes,
        })
    }

    /// The peer's static public key (its WireGuard identity), as raw bytes — the
    /// routing key for a public-key-keyed relay underlay.
    pub fn peer_public_key(&self) -> [u8; 32] {
        self.peer_public
    }

    /// Produce the initial handshake packet to send to the peer.
    pub fn start_handshake<'a>(&mut self, dst: &'a mut [u8]) -> Result<Action<'a>> {
        let res = self.tunn.encapsulate(&[], dst);
        Self::map(res)
    }

    /// Encrypt an outbound IP packet read from the TUN device.
    pub fn encapsulate<'a>(&mut self, packet: &[u8], dst: &'a mut [u8]) -> Result<Action<'a>> {
        let res = self.tunn.encapsulate(packet, dst);
        Self::map(res)
    }

    /// Decrypt an inbound datagram received from the peer over UDP.
    pub fn decapsulate<'a>(&mut self, datagram: &[u8], dst: &'a mut [u8]) -> Result<Action<'a>> {
        let res = self.tunn.decapsulate(None, datagram, dst);
        Self::map(res)
    }

    /// Service handshake / keepalive timers; may produce a packet to send.
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> Result<Action<'a>> {
        let res = self.tunn.update_timers(dst);
        Self::map(res)
    }

    /// Translate a boringtun [`TunnResult`] into our [`Action`].
    fn map(res: TunnResult<'_>) -> Result<Action<'_>> {
        match res {
            TunnResult::Done => Ok(Action::Done),
            TunnResult::Err(e) => Err(TunnelError::WireGuard(e)),
            TunnResult::WriteToNetwork(b) => Ok(Action::SendToPeer(b)),
            TunnResult::WriteToTunnelV4(b, ip) => Ok(Action::WriteToTun(b, IpAddr::V4(ip))),
            TunnResult::WriteToTunnelV6(b, ip) => Ok(Action::WriteToTun(b, IpAddr::V6(ip))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_core::keys::KeyPair;

    /// Drive a full handshake between two in-process sessions, then verify an
    /// IP packet survives a round trip encrypted -> decrypted (PRD M4 + M5).
    #[test]
    fn handshake_and_packet_roundtrip() {
        let a_keys = KeyPair::generate();
        let b_keys = KeyPair::generate();

        let mut a =
            Session::from_bytes(a_keys.private.to_bytes(), b_keys.public.to_bytes(), 1).unwrap();
        let mut b =
            Session::from_bytes(b_keys.private.to_bytes(), a_keys.public.to_bytes(), 2).unwrap();

        let mut buf = vec![0u8; MAX_PACKET];

        // A initiates the handshake.
        let init: Vec<u8> = match a.start_handshake(&mut buf).unwrap() {
            Action::SendToPeer(b) => b.to_vec(),
            other => panic!("expected handshake init, got {other:?}"),
        };

        // B receives init, replies with handshake response.
        let mut buf2 = vec![0u8; MAX_PACKET];
        let resp: Vec<u8> = match b.decapsulate(&init, &mut buf2).unwrap() {
            Action::SendToPeer(b) => b.to_vec(),
            other => panic!("expected handshake response, got {other:?}"),
        };

        // A receives the response; handshake completes.
        let mut buf3 = vec![0u8; MAX_PACKET];
        match a.decapsulate(&resp, &mut buf3).unwrap() {
            Action::Done | Action::SendToPeer(_) => {}
            other => panic!("unexpected after handshake response: {other:?}"),
        }

        // A minimal but well-formed IPv4 packet (header only) to tunnel.
        let inner = sample_ipv4_packet();

        // A encrypts it...
        let mut enc_buf = vec![0u8; MAX_PACKET];
        let encrypted: Vec<u8> = match a.encapsulate(&inner, &mut enc_buf).unwrap() {
            Action::SendToPeer(b) => b.to_vec(),
            other => panic!("expected encrypted packet, got {other:?}"),
        };
        assert_ne!(encrypted, inner, "payload must not travel in plaintext");

        // ...B decrypts it back to the original.
        let mut dec_buf = vec![0u8; MAX_PACKET];
        match b.decapsulate(&encrypted, &mut dec_buf).unwrap() {
            Action::WriteToTun(plain, _ip) => {
                assert_eq!(plain, &inner[..], "decrypted packet must match original");
            }
            other => panic!("expected decrypted tun packet, got {other:?}"),
        }
    }

    #[test]
    fn rejects_mismatched_peer_keys() {
        // A points at B, but B points at a third party -> handshake must fail.
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let c = KeyPair::generate();

        let mut sa = Session::from_bytes(a.private.to_bytes(), b.public.to_bytes(), 1).unwrap();
        let mut sb = Session::from_bytes(b.private.to_bytes(), c.public.to_bytes(), 2).unwrap();

        let mut buf = vec![0u8; MAX_PACKET];
        let init = match sa.start_handshake(&mut buf).unwrap() {
            Action::SendToPeer(b) => b.to_vec(),
            other => panic!("expected init, got {other:?}"),
        };
        let mut buf2 = vec![0u8; MAX_PACKET];
        // B cannot authenticate A as the expected peer.
        assert!(sb.decapsulate(&init, &mut buf2).is_err());
    }

    /// Simulate a peer restart (NFR5): A and B handshake and exchange data, then
    /// B is replaced by a fresh session B2 with the same keys (lost state). B2
    /// initiates a new handshake; A must accept it and data must flow again.
    #[test]
    fn recovers_when_peer_restarts_and_rehandshakes() {
        let a_keys = KeyPair::generate();
        let b_keys = KeyPair::generate();

        let mut a =
            Session::from_bytes(a_keys.private.to_bytes(), b_keys.public.to_bytes(), 1).unwrap();
        let mut b =
            Session::from_bytes(b_keys.private.to_bytes(), a_keys.public.to_bytes(), 2).unwrap();

        // First handshake A -> B and back.
        complete_handshake(&mut a, &mut b);

        // Confirm data flows before the "restart".
        assert!(
            data_flows(&mut a, &mut b),
            "data should flow after first handshake"
        );

        // Peer B restarts: brand-new session, same keys, fresh session index.
        let mut b2 =
            Session::from_bytes(b_keys.private.to_bytes(), a_keys.public.to_bytes(), 99).unwrap();

        // B2 initiates a fresh handshake toward A; A must accept the new session.
        let mut buf = vec![0u8; MAX_PACKET];
        let init = match b2.start_handshake(&mut buf).unwrap() {
            Action::SendToPeer(p) => p.to_vec(),
            other => panic!("expected re-handshake init, got {other:?}"),
        };
        let mut buf2 = vec![0u8; MAX_PACKET];
        let resp = match a.decapsulate(&init, &mut buf2).unwrap() {
            Action::SendToPeer(p) => p.to_vec(),
            other => panic!("A should answer re-handshake, got {other:?}"),
        };
        let mut buf3 = vec![0u8; MAX_PACKET];
        match b2.decapsulate(&resp, &mut buf3).unwrap() {
            Action::Done | Action::SendToPeer(_) => {}
            other => panic!("unexpected after re-handshake response: {other:?}"),
        }

        // Data must flow again over the new session. B2 is the initiator of the
        // re-handshake, so it sends first (A, as responder, adopts the new session
        // on receipt of the initiator's first transport packet).
        assert!(
            data_flows(&mut b2, &mut a),
            "data should flow after peer re-handshake"
        );
    }

    /// Drive the Noise handshake to completion between two sessions (A initiates).
    fn complete_handshake(a: &mut Session, b: &mut Session) {
        let mut buf = vec![0u8; MAX_PACKET];
        let init = match a.start_handshake(&mut buf).unwrap() {
            Action::SendToPeer(p) => p.to_vec(),
            other => panic!("expected init, got {other:?}"),
        };
        let mut buf2 = vec![0u8; MAX_PACKET];
        let resp = match b.decapsulate(&init, &mut buf2).unwrap() {
            Action::SendToPeer(p) => p.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };
        let mut buf3 = vec![0u8; MAX_PACKET];
        let _ = a.decapsulate(&resp, &mut buf3).unwrap();
    }

    /// Return true if a sample packet encapsulated by `from` decrypts at `to`.
    fn data_flows(from: &mut Session, to: &mut Session) -> bool {
        let inner = sample_ipv4_packet();
        let mut enc = vec![0u8; MAX_PACKET];
        let encrypted = match from.encapsulate(&inner, &mut enc).unwrap() {
            Action::SendToPeer(p) => p.to_vec(),
            // Not yet keyed -> would queue; treat as "not flowing".
            _ => return false,
        };
        let mut dec = vec![0u8; MAX_PACKET];
        matches!(
            to.decapsulate(&encrypted, &mut dec).unwrap(),
            Action::WriteToTun(plain, _) if plain == &inner[..]
        )
    }

    #[test]
    fn session_builds_from_base64() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert!(Session::from_base64(&a.private_base64(), &b.public_base64()).is_ok());
    }

    /// Build a 20-byte IPv4 header (no payload) good enough for boringtun to route.
    fn sample_ipv4_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        let total_len = 20u16.to_be_bytes();
        p[2] = total_len[0];
        p[3] = total_len[1];
        p[8] = 64; // TTL
        p[9] = 0; // protocol
                  // src 10.8.0.1
        p[12..16].copy_from_slice(&[10, 8, 0, 1]);
        // dst 10.8.0.2
        p[16..20].copy_from_slice(&[10, 8, 0, 2]);
        p
    }
}
