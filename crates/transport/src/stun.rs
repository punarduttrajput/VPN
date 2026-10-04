//! Minimal STUN client for server-reflexive candidate discovery (PRD Phase 4
//! FR1/FR2, milestone M1).
//!
//! ICE needs each peer to learn how it looks *from the outside* — the public
//! `ip:port` a NAT maps its local socket to (the **server-reflexive candidate**).
//! A STUN Binding request to a public STUN server returns exactly that: the
//! server echoes back the source address it observed, which is the NAT's mapping.
//!
//! This is a deliberately small, dependency-free implementation of the STUN
//! Binding transaction (RFC 5389 / RFC 8489): build a Binding request, send it
//! over UDP, and parse the `XOR-MAPPED-ADDRESS` (or legacy `MAPPED-ADDRESS`) out
//! of the success response. It does not implement TURN, message integrity, or
//! the full attribute set — only what server-reflexive gathering requires. This
//! mirrors the project's in-tree approach elsewhere (e.g. the hand-rolled OIDC
//! verifier) and avoids pulling a heavyweight ICE stack for M1.
//!
//! Reuse the *same* local socket/port for the STUN query and the data plane:
//! the reflexive mapping is per-socket, so a candidate discovered on one port is
//! only valid for traffic from that same port. [`query`] takes a caller-owned
//! socket for this reason; [`reflexive_address`] is a convenience that binds one.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::warn;

use crate::TransportError;

/// Fixed STUN magic cookie (RFC 5389 §6); also the high 32 bits of the XOR key.
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN message type: Binding request (class request, method binding).
const BINDING_REQUEST: u16 = 0x0001;
/// STUN message type: Binding success response.
const BINDING_SUCCESS: u16 = 0x0101;
/// Attribute: `MAPPED-ADDRESS` (legacy, un-obfuscated).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// Attribute: `XOR-MAPPED-ADDRESS` (preferred; address XORed with the cookie/txid).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Address family markers inside a (XOR-)MAPPED-ADDRESS attribute.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
/// Fixed STUN message header length.
const HEADER_LEN: usize = 20;

/// Per-attempt receive timeout. STUN over UDP is unreliable, so [`query`]
/// retransmits the request a few times before giving up.
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(500);
/// Number of Binding-request attempts before reporting failure.
const MAX_ATTEMPTS: usize = 3;

/// A 96-bit STUN transaction ID, used to match a response to its request.
pub(crate) type TransactionId = [u8; 12];

/// Discover this host's server-reflexive address by querying `stun_server` from
/// a socket bound to `local`.
///
/// Binds a fresh UDP socket at `local` (use the data plane's listen port, e.g.
/// `0.0.0.0:51820`, so the discovered mapping matches the port peers will reach)
/// and returns the public `ip:port` the STUN server observed.
pub async fn reflexive_address(
    local: SocketAddr,
    stun_server: SocketAddr,
) -> Result<SocketAddr, TransportError> {
    let socket = UdpSocket::bind(local).await?;
    query(&socket, stun_server).await
}

/// Gather this device's NAT-traversal candidates (PRD Phase 4, milestone M2) on
/// `listen_port` — the port the data plane will actually use.
///
/// Returns, best-effort and in priority order:
/// 1. the **host** candidate — the primary local address (the kernel's chosen
///    source IP toward `stun_server`) paired with `listen_port`, useful when
///    peers share a LAN; and
/// 2. the **server-reflexive** candidate — the public `ip:port` `stun_server`
///    observes for a socket on `listen_port` (the NAT mapping).
///
/// A candidate that can't be determined is logged and skipped rather than
/// failing the bring-up, so a flaky/unreachable STUN server never blocks the
/// tunnel (the advertised endpoint is always probed regardless). With no
/// `stun_server` this returns empty — there is nothing to discover.
///
/// Call this *before* binding the data-plane transport on `listen_port`: it
/// briefly binds a socket on that port for the STUN query, so the discovered
/// mapping matches the port peers will reach (the mapping is per-port, see
/// [`query`]). On an endpoint-independent-mapping NAT (the common case) the
/// data plane then re-binds the same port to the same external mapping.
pub async fn gather_candidates(
    listen_port: u16,
    stun_server: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut candidates: Vec<SocketAddr> = Vec::new();
    let Some(stun) = stun_server else {
        return candidates;
    };

    // Host candidate: the local source IP the kernel routes toward the STUN
    // server, on the data-plane port. A connected UDP socket sends nothing; it
    // just resolves the route so `local_addr` reports the chosen source IP.
    match local_source_ip(stun).await {
        Some(ip) => candidates.push(SocketAddr::new(ip, listen_port)),
        None => warn!("could not determine local host candidate"),
    }

    // Server-reflexive candidate: ask the STUN server what public ip:port it
    // sees for a socket bound to our listen port.
    let local: SocketAddr = match stun {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, listen_port).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, listen_port).into(),
    };
    match reflexive_address(local, stun).await {
        Ok(addr) => candidates.push(addr),
        Err(e) => warn!("STUN server-reflexive candidate discovery failed: {e}"),
    }

    candidates.dedup();
    candidates
}

/// Resolve the local source IP the kernel would use to reach `reference`.
///
/// Binds an ephemeral socket and connects it (no packets are sent — UDP connect
/// only fixes the peer and resolves the route), then reads back the local
/// address the kernel picked. Returns `None` if the socket can't be set up.
async fn local_source_ip(reference: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match reference {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let probe = UdpSocket::bind(bind).await.ok()?;
    probe.connect(reference).await.ok()?;
    Some(probe.local_addr().ok()?.ip())
}

/// Run a STUN Binding transaction over `socket` against `stun_server` and return
/// the reflexive address it reports.
///
/// Uses the caller's socket so the NAT mapping discovered here is the one the
/// data plane will actually use. Retransmits up to [`MAX_ATTEMPTS`] times; a
/// datagram that isn't a matching Binding success response is ignored (the
/// socket may legitimately carry other traffic).
pub async fn query(
    socket: &UdpSocket,
    stun_server: SocketAddr,
) -> Result<SocketAddr, TransportError> {
    let txid = new_transaction_id();
    let request = build_binding_request(&txid);
    let mut buf = [0u8; 512];

    for _ in 0..MAX_ATTEMPTS {
        socket.send_to(&request, stun_server).await?;

        // Keep reading until this attempt's timeout: ignore stray/non-matching
        // datagrams rather than failing, then retransmit on timeout.
        loop {
            match timeout(ATTEMPT_TIMEOUT, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    if from != stun_server {
                        continue; // not from our STUN server
                    }
                    if let Some(addr) = parse_binding_response(&buf[..n], &txid) {
                        return Ok(addr);
                    }
                    // Matching source but unparseable/!match: keep waiting.
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break, // attempt timed out; retransmit
            }
        }
    }

    Err(TransportError::Connection(format!(
        "STUN: no Binding response from {stun_server} after {MAX_ATTEMPTS} attempts"
    )))
}

/// Build a 20-byte STUN Binding request with no attributes.
fn build_binding_request(txid: &TransactionId) -> [u8; HEADER_LEN] {
    let mut msg = [0u8; HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length (attributes only) is zero for a bare Binding request.
    msg[2..4].copy_from_slice(&0u16.to_be_bytes());
    msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(txid);
    msg
}

/// Parse a STUN Binding success response, returning the mapped address.
///
/// Validates the message type, magic cookie, and transaction ID, then scans
/// attributes for `XOR-MAPPED-ADDRESS` (preferred) or `MAPPED-ADDRESS`. Returns
/// `None` if the buffer is not a matching, well-formed success response.
pub(crate) fn parse_binding_response(buf: &[u8], txid: &TransactionId) -> Option<SocketAddr> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_SUCCESS {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE || buf[8..20] != txid[..] {
        return None;
    }
    if HEADER_LEN + msg_len > buf.len() {
        return None;
    }

    // Walk the TLV attribute list. Each attribute is a 2-byte type, 2-byte
    // length, value, then padding to a 4-byte boundary.
    let attrs = &buf[HEADER_LEN..HEADER_LEN + msg_len];
    let mut mapped: Option<SocketAddr> = None;
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > attrs.len() {
            break; // truncated attribute
        }
        let value = &attrs[value_start..value_end];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_address(value, txid, true) {
                    // XOR-MAPPED-ADDRESS is authoritative; return immediately.
                    return Some(addr);
                }
            }
            // Keep the first MAPPED-ADDRESS as a fallback; prefer XOR-MAPPED,
            // which returns immediately above if present.
            ATTR_MAPPED_ADDRESS if mapped.is_none() => {
                mapped = parse_address(value, txid, false);
            }
            _ => {}
        }
        // Advance past the value and its 4-byte alignment padding.
        offset = value_end + ((4 - (attr_len % 4)) % 4);
    }
    mapped
}

/// Parse a (XOR-)MAPPED-ADDRESS attribute value into a [`SocketAddr`].
///
/// Layout: 1 reserved byte, 1 family byte, 2-byte port, then 4 (IPv4) or 16
/// (IPv6) address bytes. When `xor` is set, the port and address are XORed with
/// the magic cookie (and, for IPv6, the transaction ID) per RFC 5389 §15.2.
fn parse_address(value: &[u8], txid: &TransactionId, xor: bool) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return None;
            }
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for (b, c) in octets.iter_mut().zip(cookie.iter()) {
                    *b ^= *c;
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                // XOR key = magic cookie (4 bytes) followed by the transaction ID.
                let mut key = [0u8; 16];
                key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                key[4..16].copy_from_slice(txid);
                for (b, k) in octets.iter_mut().zip(key.iter()) {
                    *b ^= *k;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

/// Generate a transaction ID unique enough to match a response to its request.
///
/// STUN only needs the ID to disambiguate concurrent transactions on one socket
/// (it is not a security boundary here), so a process-wide counter mixed with
/// the wall clock is sufficient and keeps the crate dependency-free.
fn new_transaction_id() -> TransactionId {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut id = [0u8; 12];
    id[0..8].copy_from_slice(&nanos.to_be_bytes());
    id[8..12].copy_from_slice(&(count as u32).to_be_bytes());
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Binding success response carrying a single XOR-MAPPED-ADDRESS for
    /// `addr`, echoing `txid` — i.e. what a STUN server would send back.
    fn build_xor_mapped_response(txid: &TransactionId, addr: SocketAddr) -> Vec<u8> {
        let (family, addr_bytes): (u8, Vec<u8>) = match addr.ip() {
            IpAddr::V4(v4) => (FAMILY_IPV4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (FAMILY_IPV6, v6.octets().to_vec()),
        };
        // XOR the port and address with the cookie/txid key.
        let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
        let mut key = Vec::with_capacity(16);
        key.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        key.extend_from_slice(txid);
        let xaddr: Vec<u8> = addr_bytes
            .iter()
            .zip(key.iter())
            .map(|(b, k)| b ^ k)
            .collect();

        let mut value = Vec::new();
        value.push(0); // reserved
        value.push(family);
        value.extend_from_slice(&xport.to_be_bytes());
        value.extend_from_slice(&xaddr);

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attr.extend_from_slice(&value);
        // Pad to a 4-byte boundary.
        while attr.len() % 4 != 0 {
            attr.push(0);
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes()); // total attribute-section length
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&attr);
        msg
    }

    #[test]
    fn binding_request_is_well_formed() {
        let txid = new_transaction_id();
        let req = build_binding_request(&txid);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0); // no attributes
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &txid[..]);
    }

    #[test]
    fn parses_xor_mapped_ipv4() {
        let txid = new_transaction_id();
        let want: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let resp = build_xor_mapped_response(&txid, want);
        assert_eq!(parse_binding_response(&resp, &txid), Some(want));
    }

    #[test]
    fn parses_xor_mapped_ipv6() {
        let txid = new_transaction_id();
        let want: SocketAddr = "[2001:db8::1]:9999".parse().unwrap();
        let resp = build_xor_mapped_response(&txid, want);
        assert_eq!(parse_binding_response(&resp, &txid), Some(want));
    }

    #[test]
    fn parses_legacy_mapped_address() {
        let txid = new_transaction_id();
        let addr: SocketAddr = "198.51.100.9:1234".parse().unwrap();
        // Build a MAPPED-ADDRESS (un-XORed) response by hand.
        let mut value = vec![0u8, FAMILY_IPV4];
        value.extend_from_slice(&addr.port().to_be_bytes());
        match addr.ip() {
            IpAddr::V4(v4) => value.extend_from_slice(&v4.octets()),
            _ => unreachable!(),
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
        msg.extend_from_slice(&value);
        assert_eq!(parse_binding_response(&msg, &txid), Some(addr));
    }

    #[test]
    fn rejects_wrong_transaction_id() {
        let txid = new_transaction_id();
        let other = new_transaction_id();
        let resp = build_xor_mapped_response(&other, "203.0.113.7:51820".parse().unwrap());
        assert_eq!(parse_binding_response(&resp, &txid), None);
    }

    #[test]
    fn rejects_short_and_non_success_messages() {
        let txid = new_transaction_id();
        assert_eq!(parse_binding_response(&[0u8; 4], &txid), None);
        // A Binding *request* type is not a success response.
        let req = build_binding_request(&txid);
        assert_eq!(parse_binding_response(&req, &txid), None);
    }

    /// End-to-end over loopback: a mock STUN server echoes the client's observed
    /// source address back as XOR-MAPPED-ADDRESS; the client recovers it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn query_recovers_reflexive_address_from_mock_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Mock STUN server: read one Binding request, reply with the source addr.
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            // Echo the transaction ID from the request (bytes 8..20).
            let mut txid = [0u8; 12];
            txid.copy_from_slice(&buf[8..20]);
            let _ = n;
            let resp = build_xor_mapped_response(&txid, from);
            server.send_to(&resp, from).await.unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let expected = client.local_addr().unwrap();
        let reflexive = query(&client, server_addr).await.unwrap();
        assert_eq!(reflexive, expected);
    }

    /// With no STUN server there is nothing to discover, so gathering yields no
    /// candidates (the advertised endpoint still covers the basic path).
    #[tokio::test]
    async fn gather_without_stun_server_is_empty() {
        assert!(gather_candidates(51820, None).await.is_empty());
    }

    /// End-to-end gather: against a mock STUN server, `gather_candidates` returns
    /// at least the server-reflexive candidate on the requested listen port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gather_collects_reflexive_candidate_on_listen_port() {
        // Mock STUN server: echo each request's source back as XOR-MAPPED-ADDRESS.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, from) = server.recv_from(&mut buf).await.unwrap();
            let mut txid = [0u8; 12];
            txid.copy_from_slice(&buf[8..20]);
            let resp = build_xor_mapped_response(&txid, from);
            server.send_to(&resp, from).await.unwrap();
        });

        // Pick a free port for the data plane, then release it so gather can bind it.
        let port = {
            let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            tmp.local_addr().unwrap().port()
        };

        let candidates = gather_candidates(port, Some(server_addr)).await;
        // The reflexive (and host) candidate is on the data-plane listen port.
        assert!(
            candidates.iter().any(|c| c.port() == port),
            "expected a candidate on the listen port, got {candidates:?}"
        );
    }
}
