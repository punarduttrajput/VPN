//! Wire protocol between the unprivileged GUI and the privileged helper daemon
//! (Phase 5): a request/response protocol carried over a [`UnixStream`], with
//! [`HelperResponse::TunOpened`] additionally carrying a TUN file descriptor as
//! `SCM_RIGHTS` ancillary data (see [`crate::fdpass`]).
//!
//! This framing is transport-agnostic in shape (plain JSON messages); a future
//! Windows helper service would carry the same [`HelperRequest`]/[`HelperResponse`]
//! types over a named pipe instead of a `UnixStream` — not built this pass.

use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;
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
}

/// A response from the helper to the GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperResponse {
    /// A `KillSwitchEngage`/`KillSwitchDisengage` request succeeded.
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
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(io::Error::other)
}

/// Send a response, optionally carrying a fd (for `HelperResponse::TunOpened`)
/// as `SCM_RIGHTS` ancillary data in the same call.
pub fn send_response(
    stream: &UnixStream,
    resp: &HelperResponse,
    fd: Option<RawFd>,
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

/// Receive a response, and the fd if one was attached.
pub fn recv_response(stream: &UnixStream) -> io::Result<(HelperResponse, Option<RawFd>)> {
    let mut buf = [0u8; MAX_RESPONSE];
    let (n, fd) = fdpass::recv_with_fd(stream, &mut buf)?;
    let resp: HelperResponse = serde_json::from_slice(&buf[..n]).map_err(io::Error::other)?;
    Ok((resp, fd.map(std::os::unix::io::IntoRawFd::into_raw_fd)))
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
        let (a, b) = UnixStream::pair().unwrap();
        let mut pipe_fds = [0i32; 2];
        // SAFETY: fills `pipe_fds` with a valid, connected pipe pair.
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let (read_end, write_end) = (pipe_fds[0], pipe_fds[1]);

        send_response(&a, &HelperResponse::TunOpened, Some(read_end)).unwrap();
        // SAFETY: our copy is no longer needed once sent.
        unsafe { libc::close(read_end) };

        let (resp, fd) = recv_response(&b).unwrap();
        assert!(matches!(resp, HelperResponse::TunOpened));
        let received = fd.expect("a fd should have been received");

        let payload = b"hi";
        // SAFETY: `write_end` is a valid, open pipe write fd.
        unsafe { libc::write(write_end, payload.as_ptr().cast(), payload.len()) };
        let mut rbuf = [0u8; 8];
        // SAFETY: `received` is the fd handed back by `recv_response`.
        let r = unsafe { libc::read(received, rbuf.as_mut_ptr().cast(), rbuf.len()) };
        assert_eq!(r, payload.len() as isize);

        // SAFETY: close the fds we still own.
        unsafe {
            libc::close(write_end);
            libc::close(received);
        }
    }
}
