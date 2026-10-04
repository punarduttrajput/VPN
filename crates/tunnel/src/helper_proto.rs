//! Wire protocol between the unprivileged GUI and the privileged helper daemon
//! (Phase 5): a request/response protocol carried over a [`UnixStream`], with
//! [`HelperResponse::TunOpened`] additionally carrying a TUN file descriptor as
//! `SCM_RIGHTS` ancillary data (see [`crate::fdpass`]).
//!
//! This framing is transport-agnostic in shape (plain JSON messages); a future
//! Windows helper service would carry the same [`HelperRequest`]/[`HelperResponse`]
//! types over a named pipe instead of a `UnixStream` — not built this pass.

use std::io::{self, Read, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

use crate::device::TunConfig;
use crate::fdpass;

/// A request from the GUI to the helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperRequest {
    /// Open and configure a TUN interface; the response carries its fd.
    OpenTun {
        name: String,
        /// A [`ferrum_core::config::Cidr`], serialized as its string form.
        address: String,
        mtu: u16,
    },
    /// Install the kill-switch firewall rules on `iface`, allowing egress to
    /// each of `allow_ips` (string-formatted `IpAddr`s) in addition to loopback
    /// and the tunnel interface.
    KillSwitchEngage {
        iface: String,
        allow_ips: Vec<String>,
    },
    /// Remove the kill-switch firewall rules.
    KillSwitchDisengage,
    /// Point system DNS at `servers` (string-formatted `IpAddr`s) for the life
    /// of the connection (PRD leak-protection.md FR3): per-link on `iface` via
    /// systemd-resolved, else the `/etc/resolv.conf` swap.
    SetDns { iface: String, servers: Vec<String> },
    /// Restore pre-connection DNS (safe to send unconditionally on disconnect).
    RestoreDns { iface: String },
    /// Install the leak-guard firewall rules on `iface` (PRD leak-protection.md
    /// FR4): lock DNS (53/853) to `dns_servers`/the tunnel, and drop off-tunnel
    /// IPv6 when `block_ipv6` (loopback/link-local/neighbor-discovery exempt).
    LeakGuardEngage {
        iface: String,
        dns_servers: Vec<String>,
        block_ipv6: bool,
    },
    /// Remove the leak-guard firewall rules.
    LeakGuardDisengage,
}

/// A response from the helper to the GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperResponse {
    /// A request with no payload to return (kill-switch, DNS, leak-guard)
    /// succeeded.
    Ok,
    /// An `OpenTun` request succeeded; the fd travels alongside this response
    /// as `SCM_RIGHTS` ancillary data (see [`send_response`]/[`recv_response`]).
    TunOpened,
    /// The request failed; `0` is a human-readable reason.
    Err(String),
}

/// Largest response payload we expect (generously sized for the tiny, fixed
/// set of JSON messages above). A response — including any ancillary fd — is
/// always sent and received in a single `sendmsg`/`recvmsg` call, which on a
/// local Unix stream socket delivers a small write whole; this module doesn't
/// implement reassembly for a response split across multiple reads.
const MAX_RESPONSE: usize = 4096;

/// Largest request payload [`recv_request`] accepts. Requests are tiny JSON
/// messages; without a cap the length prefix alone would let any caller make
/// the (root) helper allocate up to 4 GiB (SEC-005).
pub const MAX_REQUEST: usize = 64 * 1024;

/// Write a length-prefixed JSON `HelperRequest` to `stream`. Uses ordinary
/// `Write`/`read_exact` framing (robust to partial reads/writes) since a
/// request never carries an fd.
pub fn send_request(stream: &mut UnixStream, req: &HelperRequest) -> io::Result<()> {
    let bytes = serde_json::to_vec(req).map_err(io::Error::other)?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

/// Read a length-prefixed JSON `HelperRequest` from `stream`.
pub fn recv_request(stream: &mut UnixStream) -> io::Result<HelperRequest> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("helper request of {len} bytes exceeds the {MAX_REQUEST}-byte limit"),
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(io::Error::other)
}

/// Send a response, optionally carrying a fd (for `HelperResponse::TunOpened`)
/// as `SCM_RIGHTS` ancillary data in the same call. The fd is borrowed: the
/// caller keeps (and must close) its own copy.
pub fn send_response(
    stream: &UnixStream,
    resp: &HelperResponse,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(io::Error::other)?;
    match fd {
        Some(fd) => fdpass::send_with_fd(stream, &bytes, fd),
        None => {
            let mut s = stream;
            s.write_all(&bytes)
        }
    }
}

/// Receive a response, and the fd if one was attached (owned: it closes on
/// drop unless the caller keeps it, so an unexpected fd can't leak).
pub fn recv_response(stream: &UnixStream) -> io::Result<(HelperResponse, Option<OwnedFd>)> {
    let mut buf = [0u8; MAX_RESPONSE];
    let (n, fd) = fdpass::recv_with_fd(stream, &mut buf)?;
    let resp: HelperResponse = serde_json::from_slice(&buf[..n]).map_err(io::Error::other)?;
    Ok((resp, fd))
}

/// Build the `OpenTun` request for `cfg`.
pub fn open_tun_request(cfg: &TunConfig) -> HelperRequest {
    HelperRequest::OpenTun {
        name: cfg.name.clone(),
        address: format!("{}/{}", cfg.address.addr, cfg.address.prefix),
        mtu: cfg.mtu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_over_a_socket_pair() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let req = HelperRequest::KillSwitchEngage {
            iface: "ferrum0".to_string(),
            allow_ips: vec!["203.0.113.7".to_string()],
        };
        send_request(&mut a, &req).unwrap();
        let got = recv_request(&mut b).unwrap();
        match got {
            HelperRequest::KillSwitchEngage { iface, allow_ips } => {
                assert_eq!(iface, "ferrum0");
                assert_eq!(allow_ips, vec!["203.0.113.7".to_string()]);
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn oversized_request_is_rejected_before_allocating() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        // Only the length prefix is sent: the receiver must refuse on the
        // prefix alone rather than allocate and wait for a 4 GiB body.
        a.write_all(&u32::MAX.to_le_bytes()).unwrap();
        let err = recv_request(&mut b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn leak_protection_requests_roundtrip() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let reqs = [
            HelperRequest::SetDns {
                iface: "ferrum0".to_string(),
                servers: vec!["10.99.0.53".to_string()],
            },
            HelperRequest::RestoreDns {
                iface: "ferrum0".to_string(),
            },
            HelperRequest::LeakGuardEngage {
                iface: "ferrum0".to_string(),
                dns_servers: vec!["10.99.0.53".to_string(), "fd00::53".to_string()],
                block_ipv6: true,
            },
            HelperRequest::LeakGuardDisengage,
        ];
        for req in reqs {
            send_request(&mut a, &req).unwrap();
            let got = recv_request(&mut b).unwrap();
            // The enums have no PartialEq (they carry no invariants worth one);
            // JSON equality is an exact structural round-trip check.
            assert_eq!(
                serde_json::to_string(&got).unwrap(),
                serde_json::to_string(&req).unwrap()
            );
        }
    }

    #[test]
    fn response_without_fd_roundtrips() {
        let (a, b) = UnixStream::pair().unwrap();
        send_response(&a, &HelperResponse::Err("boom".to_string()), None).unwrap();
        let (resp, fd) = recv_response(&b).unwrap();
        assert!(fd.is_none());
        match resp {
            HelperResponse::Err(msg) => assert_eq!(msg, "boom"),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn tun_opened_response_carries_the_fd() {
        use std::os::fd::AsFd;

        let (a, b) = UnixStream::pair().unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();

        send_response(&a, &HelperResponse::TunOpened, Some(reader.as_fd())).unwrap();
        drop(reader); // our copy is no longer needed once sent

        let (resp, fd) = recv_response(&b).unwrap();
        assert!(matches!(resp, HelperResponse::TunOpened));
        let received = fd.expect("a fd should have been received");

        writer.write_all(b"hi").unwrap();
        drop(writer);
        let mut got = Vec::new();
        std::fs::File::from(received).read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hi");
    }
}
