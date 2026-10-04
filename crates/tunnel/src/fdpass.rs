//! Passing a file descriptor across a Unix domain socket (`SCM_RIGHTS`).
//!
//! This is the primitive the privileged helper daemon (Phase 5) uses to hand a
//! freshly-opened TUN fd to the unprivileged GUI process: the fd travels as
//! ancillary data alongside a small payload on an ordinary [`UnixStream`].
//!
//! Built on `rustix`'s typed `sendmsg`/`recvmsg` (SEC-016). This module used to
//! hand-roll them on `libc`, with a control buffer that wasn't guaranteed to be
//! `cmsghdr`-aligned, no `MSG_CMSG_CLOEXEC` (so the TUN fd leaked into child
//! processes such as `nft`), and no check for truncated control data. It is now
//! free of `unsafe`.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};

/// Send `payload` on `stream`, carrying `fd` as ancillary `SCM_RIGHTS` data.
///
/// The peer must call [`recv_with_fd`] to receive both. `fd` is borrowed: the
/// kernel duplicates it into the receiver, and the caller still owns (and must
/// eventually close) its own copy.
pub fn send_with_fd(stream: &UnixStream, payload: &[u8], fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(io::Error::other("SCM_RIGHTS control buffer too small"));
    }
    sendmsg(
        stream,
        &[IoSlice::new(payload)],
        &mut control,
        SendFlags::empty(),
    )?;
    Ok(())
}

/// Receive a payload (into `buf`) and an optional fd sent by [`send_with_fd`].
///
/// Returns the number of payload bytes read and, if the sender attached one,
/// the received fd, owned by the caller and closed on drop. The fd is received
/// close-on-exec, so it never leaks into a process the caller spawns. Truncated
/// ancillary data (the sender attached more than we accept) is an error, and
/// any surplus fds the kernel did deliver are closed rather than leaked.
pub fn recv_with_fd(stream: &UnixStream, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(
        stream,
        &mut [IoSliceMut::new(buf)],
        &mut control,
        recv_flags(),
    )?;

    // Collect every delivered fd (as OwnedFd, so any we don't keep are closed).
    let mut fds: Vec<OwnedFd> = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    if msg.flags.contains(ReturnFlags::CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated SCM_RIGHTS control data (sender attached more than one fd)",
        ));
    }
    if fds.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected at most one fd, received several",
        ));
    }
    let fd = fds.pop();
    #[cfg(target_vendor = "apple")]
    if let Some(fd) = &fd {
        // No MSG_CMSG_CLOEXEC on Apple platforms: set it right after receipt.
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok((msg.bytes, fd))
}

/// `MSG_CMSG_CLOEXEC` where the platform has it (everywhere but Apple's).
fn recv_flags() -> RecvFlags {
    #[cfg(not(target_vendor = "apple"))]
    {
        RecvFlags::CMSG_CLOEXEC
    }
    #[cfg(target_vendor = "apple")]
    {
        RecvFlags::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    /// A `UnixStream::pair()` gives two connected, unprivileged sockets —
    /// enough to exercise real `SCM_RIGHTS` fd-passing without root or a real
    /// TUN device. The passed fd is a pipe end, verified usable on the
    /// receiving side (the same underlying pipe) and close-on-exec.
    #[test]
    fn fd_travels_across_the_socket_and_is_usable() {
        let (a, b) = UnixStream::pair().unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();

        send_with_fd(&a, b"hello", reader.as_fd()).unwrap();
        // The kernel duplicated the fd, so closing ours doesn't affect theirs.
        drop(reader);

        let mut buf = [0u8; 16];
        let (n, fd) = recv_with_fd(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        let received = fd.expect("a fd should have been received");
        let flags = rustix::io::fcntl_getfd(&received).unwrap();
        assert!(
            flags.contains(rustix::io::FdFlags::CLOEXEC),
            "received fd must be close-on-exec"
        );

        writer.write_all(b"through-the-pipe").unwrap();
        drop(writer);
        let mut got = Vec::new();
        std::fs::File::from(received).read_to_end(&mut got).unwrap();
        assert_eq!(got, b"through-the-pipe");
    }

    #[test]
    fn no_fd_attached_is_reported_as_none() {
        let (a, b) = UnixStream::pair().unwrap();
        (&a).write_all(b"plain").unwrap();
        let mut buf = [0u8; 16];
        let (n, fd) = recv_with_fd(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"plain");
        assert!(fd.is_none());
    }

    /// A sender that attaches more fds than we accept gets an error, not a
    /// silently dropped (leaked) descriptor.
    #[test]
    fn surplus_fds_are_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r1, _w1) = std::io::pipe().unwrap();
        let (r2, _w2) = std::io::pipe().unwrap();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let two = [r1.as_fd(), r2.as_fd()];
        assert!(control.push(SendAncillaryMessage::ScmRights(&two)));
        sendmsg(&a, &[IoSlice::new(b"x")], &mut control, SendFlags::empty()).unwrap();

        let mut buf = [0u8; 4];
        let err = recv_with_fd(&b, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
