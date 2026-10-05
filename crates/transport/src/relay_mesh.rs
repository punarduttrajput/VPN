//! The relay mesh (PRD `relay-mesh.md`): sibling relays forward `Data` frames
//! for each other's clients, so peers registered on different relays (anycast
//! PoPs, or a scaled-out pool) can still reach each other in one extra hop.
//!
//! This module is the protocol: message encoding and authentication, replay
//! protection, and the table of keys held by siblings. [`RelayServer`] owns the
//! mesh socket and does the I/O (see `relay.rs`).
//!
//! Wire format, on the mesh socket only (never the client socket):
//!
//! ```text
//! magic "FRM1" (4) | type (1) | sender (8) | counter (8) | body | tag (16)
//! ```
//!
//! `tag` is keyed BLAKE2s (the deployment's mesh key) over everything before
//! it, truncated to 16 bytes. `sender` identifies one relay process (its start
//! time in microseconds) and `counter` increases with every message it sends.
//! Control messages (Present, Gone, Sync) must be newer than the last one seen
//! from that sibling; Data isn't replay-checked, because its payload is
//! WireGuard, which rejects replays itself.
//!
//! [`RelayServer`]: crate::RelayServer

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use blake2::digest::{KeyInit, Mac};
use blake2::Blake2sMac256;
use subtle::ConstantTimeEq;

use crate::relay::PublicKey;

/// How a relay joins a mesh (static membership; PRD M1).
#[derive(Clone, Debug)]
pub struct MeshConfig {
    /// This relay's mesh listener, on a network the siblings can reach.
    pub listen: SocketAddr,
    /// The siblings' mesh listeners.
    pub peers: Vec<SocketAddr>,
    /// The deployment's shared mesh key.
    pub key: [u8; 32],
}

const MAGIC: &[u8; 4] = b"FRM1";
const HEADER: usize = 4 + 1 + 8 + 8;
const TAG: usize = 16;
const KEY_LEN: usize = 32;

pub(crate) const TYPE_PRESENT: u8 = 0x01;
pub(crate) const TYPE_GONE: u8 = 0x02;
pub(crate) const TYPE_DATA: u8 = 0x03;
pub(crate) const TYPE_SYNC: u8 = 0x04;

/// Keys per Present/Gone message, so one stays under a 1280-byte datagram.
const MAX_ENTRIES: usize = 32;
const PRESENT_ENTRY: usize = KEY_LEN + 4;

/// How often a relay re-announces every key it holds.
pub(crate) const ANNOUNCE_EVERY: Duration = Duration::from_secs(30);
/// A sibling's key not re-announced for this long is forgotten (the sibling
/// died, or the client went quiet there).
pub(crate) const REMOTE_TTL: Duration = Duration::from_secs(90);

/// One decoded mesh message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Msg<'a> {
    /// "I hold these keys, and last heard from each this many ms ago."
    Present(Vec<(PublicKey, u32)>),
    /// "These keys aren't here."
    Gone(Vec<PublicKey>),
    /// A client data frame for one of the receiver's clients.
    Data {
        src: PublicKey,
        dst: PublicKey,
        payload: &'a [u8],
    },
    /// "Send me every key you hold."
    Sync,
}

impl Msg<'_> {
    /// Whether this message must pass the replay check.
    pub(crate) fn is_control(&self) -> bool {
        !matches!(self, Msg::Data { .. })
    }
}

fn tag(key: &[u8; 32], data: &[u8]) -> [u8; TAG] {
    let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(key).expect("32-byte key");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    full[..TAG].try_into().expect("sized")
}

/// Builds authenticated mesh messages for one relay process.
pub(crate) struct Codec {
    key: [u8; 32],
    sender: u64,
    counter: AtomicU64,
}

impl Codec {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        // The start time, so a restarted relay's messages are newer than its
        // previous run's (see `Replay`).
        let sender = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(1);
        Self::with_sender(key, sender)
    }

    pub(crate) fn with_sender(key: [u8; 32], sender: u64) -> Self {
        Self {
            key,
            sender,
            counter: AtomicU64::new(1),
        }
    }

    fn seal(&self, kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + body.len() + TAG);
        out.extend_from_slice(MAGIC);
        out.push(kind);
        out.extend_from_slice(&self.sender.to_be_bytes());
        out.extend_from_slice(&self.counter.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        out.extend_from_slice(body);
        let t = tag(&self.key, &out);
        out.extend_from_slice(&t);
        out
    }

    /// Present messages for `entries` (key, ms since last heard).
    pub(crate) fn present(&self, entries: &[(PublicKey, u32)]) -> Vec<Vec<u8>> {
        entries
            .chunks(MAX_ENTRIES)
            .map(|chunk| {
                let mut body = Vec::with_capacity(chunk.len() * PRESENT_ENTRY);
                for (k, age) in chunk {
                    body.extend_from_slice(k);
                    body.extend_from_slice(&age.to_be_bytes());
                }
                self.seal(TYPE_PRESENT, &body)
            })
            .collect()
    }

    pub(crate) fn gone(&self, keys: &[PublicKey]) -> Vec<Vec<u8>> {
        keys.chunks(MAX_ENTRIES)
            .map(|chunk| self.seal(TYPE_GONE, &chunk.concat()))
            .collect()
    }

    pub(crate) fn data(&self, src: &PublicKey, dst: &PublicKey, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(2 * KEY_LEN + payload.len());
        body.extend_from_slice(src);
        body.extend_from_slice(dst);
        body.extend_from_slice(payload);
        self.seal(TYPE_DATA, &body)
    }

    pub(crate) fn sync(&self) -> Vec<u8> {
        self.seal(TYPE_SYNC, &[])
    }
}

/// Check `datagram`'s magic and tag and decode it. Returns the sender id, the
/// counter and the message, or `None` for anything forged or malformed.
pub(crate) fn open<'a>(key: &[u8; 32], datagram: &'a [u8]) -> Option<(u64, u64, Msg<'a>)> {
    if datagram.len() < HEADER + TAG || &datagram[..4] != MAGIC {
        return None;
    }
    let (signed, got) = datagram.split_at(datagram.len() - TAG);
    if !bool::from(tag(key, signed).ct_eq(got)) {
        return None;
    }
    let kind = signed[4];
    let sender = u64::from_be_bytes(signed[5..13].try_into().ok()?);
    let counter = u64::from_be_bytes(signed[13..21].try_into().ok()?);
    let body = &signed[HEADER..];
    let msg = match kind {
        TYPE_PRESENT if !body.is_empty() && body.len() % PRESENT_ENTRY == 0 => Msg::Present(
            body.as_chunks::<PRESENT_ENTRY>()
                .0
                .iter()
                .map(|e| {
                    let k: PublicKey = e[..KEY_LEN].try_into().expect("sized");
                    let age = u32::from_be_bytes(e[KEY_LEN..].try_into().expect("sized"));
                    (k, age)
                })
                .collect(),
        ),
        TYPE_GONE if !body.is_empty() && body.len() % KEY_LEN == 0 => {
            Msg::Gone(body.as_chunks::<KEY_LEN>().0.to_vec())
        }
        TYPE_DATA if body.len() >= 2 * KEY_LEN => Msg::Data {
            src: body[..KEY_LEN].try_into().expect("sized"),
            dst: body[KEY_LEN..2 * KEY_LEN].try_into().expect("sized"),
            payload: &body[2 * KEY_LEN..],
        },
        TYPE_SYNC if body.is_empty() => Msg::Sync,
        _ => return None,
    };
    Some((sender, counter, msg))
}

/// Per-sibling replay check for control messages: accept only a newer sender
/// (a restarted relay) or the same sender with a higher counter.
#[derive(Default)]
pub(crate) struct Replay {
    last: HashMap<SocketAddr, (u64, u64)>,
}

impl Replay {
    pub(crate) fn accept(&mut self, from: SocketAddr, sender: u64, counter: u64) -> bool {
        let fresh = match self.last.get(&from) {
            None => true,
            Some(&(s, c)) => sender > s || (sender == s && counter > c),
        };
        if fresh {
            self.last.insert(from, (sender, counter));
        }
        fresh
    }
}

/// Which sibling holds each key it has announced, and when that sibling last
/// heard from the client.
#[derive(Default)]
pub(crate) struct Remote {
    map: HashMap<PublicKey, (SocketAddr, Instant)>,
}

impl Remote {
    /// Record that `sibling` holds `key` and heard from it at `heard_at`. If
    /// another sibling reported the key more recently, that one is kept.
    pub(crate) fn learn(&mut self, key: PublicKey, sibling: SocketAddr, heard_at: Instant) {
        match self.map.get(&key) {
            Some(&(other, at)) if other != sibling && at > heard_at => {}
            _ => {
                self.map.insert(key, (sibling, heard_at));
            }
        }
    }

    /// `sibling` says it doesn't hold `key`.
    pub(crate) fn forget(&mut self, key: &PublicKey, sibling: SocketAddr) {
        if self.map.get(key).is_some_and(|&(s, _)| s == sibling) {
            self.map.remove(key);
        }
    }

    /// The sibling to forward `key`'s frames to.
    pub(crate) fn lookup(&self, key: &PublicKey, now: Instant) -> Option<SocketAddr> {
        self.map
            .get(key)
            .filter(|&&(_, at)| now.saturating_duration_since(at) <= REMOTE_TTL)
            .map(|&(s, _)| s)
    }

    /// Forget keys not refreshed within [`REMOTE_TTL`].
    pub(crate) fn expire(&mut self, now: Instant) {
        self.map
            .retain(|_, &mut (_, at)| now.saturating_duration_since(at) <= REMOTE_TTL);
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

/// When a sibling announces a key this relay also holds: give it up only if
/// this relay heard from the client less recently than the sibling did. Two
/// crossed announcements can't both give the client up.
pub(crate) fn yields_to_sibling(local_age: Duration, sibling_age: Duration) -> bool {
    local_age > sibling_age
}

/// Milliseconds since `at`, saturating at `u32::MAX`.
pub(crate) fn age_ms(at: Instant, now: Instant) -> u32 {
    u32::try_from(now.saturating_duration_since(at).as_millis()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9; 32];

    fn k(b: u8) -> PublicKey {
        [b; 32]
    }

    #[test]
    fn messages_round_trip() {
        let c = Codec::with_sender(KEY, 7);
        let entries: Vec<_> = (0..40u8).map(|i| (k(i), u32::from(i) * 100)).collect();
        let present = c.present(&entries);
        assert_eq!(present.len(), 2, "40 keys split into chunks of 32");
        let mut decoded = Vec::new();
        for m in &present {
            assert!(m.len() <= 1280, "{} bytes", m.len());
            match open(&KEY, m).unwrap() {
                (7, _, Msg::Present(e)) => decoded.extend(e),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(decoded, entries);

        let gone = c.gone(&[k(1), k(2)]);
        let (_, _, gone) = open(&KEY, &gone[0]).unwrap();
        assert_eq!(gone, Msg::Gone(vec![k(1), k(2)]));
        let data = c.data(&k(1), &k(2), b"wg");
        assert_eq!(
            open(&KEY, &data).unwrap().2,
            Msg::Data {
                src: k(1),
                dst: k(2),
                payload: b"wg"
            }
        );
        assert_eq!(open(&KEY, &c.sync()).unwrap().2, Msg::Sync);
    }

    #[test]
    fn counters_increase_per_message() {
        let c = Codec::with_sender(KEY, 7);
        let (_, a, _) = open(&KEY, &c.sync()).unwrap();
        let (_, b, _) = open(&KEY, &c.sync()).unwrap();
        assert!(b > a);
    }

    #[test]
    fn forged_or_malformed_messages_are_rejected() {
        let c = Codec::with_sender(KEY, 7);
        let good = c.data(&k(1), &k(2), b"payload");
        assert!(open(&[8; 32], &good).is_none(), "wrong mesh key");
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 1;
            assert!(open(&KEY, &bad).is_none(), "flipped byte {i} accepted");
        }
        assert!(open(&KEY, &good[..good.len() - 1]).is_none(), "truncated");
        assert!(open(&KEY, b"FRM1").is_none());
        assert!(open(&KEY, &[]).is_none());
        // Correctly tagged, but a body that doesn't fit its type.
        assert!(open(&KEY, &c.seal(TYPE_PRESENT, &[0; 35])).is_none());
        assert!(open(&KEY, &c.seal(TYPE_GONE, &[])).is_none());
        assert!(open(&KEY, &c.seal(TYPE_DATA, &[0; 63])).is_none());
        assert!(open(&KEY, &c.seal(TYPE_SYNC, &[0])).is_none());
        assert!(open(&KEY, &c.seal(0x7f, &[])).is_none(), "unknown type");
    }

    #[test]
    fn replayed_control_messages_are_rejected() {
        let a: SocketAddr = "10.0.0.1:7000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:7000".parse().unwrap();
        let mut r = Replay::default();
        assert!(r.accept(a, 100, 1));
        assert!(!r.accept(a, 100, 1), "same counter");
        assert!(r.accept(a, 100, 2));
        assert!(!r.accept(a, 100, 1), "older counter");
        assert!(r.accept(b, 100, 1), "tracked per sibling");
        assert!(r.accept(a, 200, 1), "a restarted sibling");
        assert!(!r.accept(a, 100, 50), "its previous run");
    }

    #[test]
    fn remote_table_keeps_the_freshest_report_and_expires() {
        let a: SocketAddr = "10.0.0.1:7000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:7000".parse().unwrap();
        let now = Instant::now();
        let mut r = Remote::default();
        r.learn(k(1), a, now);
        assert_eq!(r.lookup(&k(1), now), Some(a));
        // An older report from another sibling doesn't take over…
        r.learn(k(1), b, now - Duration::from_secs(5));
        assert_eq!(r.lookup(&k(1), now), Some(a));
        // …a newer one does.
        r.learn(k(1), b, now + Duration::from_secs(1));
        assert_eq!(r.lookup(&k(1), now), Some(b));
        // Only the holder's Gone removes it.
        r.forget(&k(1), a);
        assert_eq!(r.lookup(&k(1), now), Some(b));
        r.forget(&k(1), b);
        assert_eq!(r.lookup(&k(1), now), None);

        r.learn(k(2), a, now);
        let later = now + REMOTE_TTL + Duration::from_secs(1);
        assert_eq!(r.lookup(&k(2), later), None, "stale entries aren't used");
        r.expire(later);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn only_the_less_recent_holder_yields() {
        let s = Duration::from_secs;
        // The client moved here 2 s ago; the old relay last heard from it 40 s ago.
        assert!(yields_to_sibling(s(40), s(2)), "old relay gives it up");
        assert!(!yields_to_sibling(s(2), s(40)), "new relay keeps it");
        assert!(!yields_to_sibling(s(5), s(5)), "a tie keeps it");
    }
}
