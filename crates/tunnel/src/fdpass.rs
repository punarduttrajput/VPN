//! Passing a file descriptor across a Unix domain socket (`SCM_RIGHTS`).
//!
//! This is the primitive the privileged helper daemon (Phase 5) uses to hand a
//! freshly-opened TUN fd to the unprivileged GUI process: the fd travels as
//! ancillary data alongside a small payload on an ordinary [`UnixStream`].
//! Hand-rolled on `libc::sendmsg`/`recvmsg` (no fd-passing crate) to keep this
//! small and auditable, mirroring the project's existing bias for hand-rolling
//! small security-adjacent primitives (see `ferrum-transport::stun`, the OIDC
//! verifier).

use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Send `payload` on `stream`, carrying `fd` as ancillary `SCM_RIGHTS` data.
///
/// The peer must call [`recv_with_fd`] to receive both. `fd` is borrowed here
/// (not consumed) — the kernel duplicates it into the receiver; the caller
/// still owns and must close (or let it stay owned via `OwnedFd`/`Drop`) its
/// original descriptor.
pub fn send_with_fd(stream: &UnixStream, payload: &[u8], fd: RawFd) -> io::Result<()> {
    let iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };

    let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: `msg` points at a zero-initialized `msghdr` with valid `iov` and
    // `control` buffers sized for exactly one fd; `CMSG_FIRSTHDR` on a
    // non-null `msg_control` of that size always returns a valid pointer
    // within `cmsg_buf`.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write(libc::CMSG_DATA(cmsg) as *mut RawFd, fd);
    }

    // SAFETY: `stream`'s fd is valid for the duration of this call; `msg` is
    // fully initialized above.
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a payload (into `buf`) and an optional fd sent by [`send_with_fd`].
///
/// Returns the number of payload bytes read and, if the sender attached one,
/// the received fd (owned by the caller — closes on drop if not otherwise
/// used).
pub fn recv_with_fd(stream: &UnixStream, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };

    let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: `stream`'s fd is valid; `msg` describes a single-element iovec
    // over `buf` and a control buffer sized for at most one fd.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    // `msg_controllen`'s type varies by Unix flavor (e.g. `usize` on Linux,
    // `socklen_t` on macOS); the cast is a no-op on this host but needed for
    // portability, hence the explicit allow.
    #[allow(clippy::unnecessary_cast)]
    let controllen = msg.msg_controllen as usize;
    let fd = if controllen >= size_of::<libc::cmsghdr>() {
        // SAFETY: `msg_controllen` indicates the kernel wrote at least one
        // cmsghdr into `cmsg_buf`; `CMSG_FIRSTHDR` returns a pointer into it.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                None
            } else {
                let raw = std::ptr::read(libc::CMSG_DATA(cmsg) as *const RawFd);
                Some(OwnedFd::from_raw_fd(raw))
            }
        }
    } else {
        None
    };

    Ok((n as usize, fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;

    /// A `UnixStream::pair()` gives two connected, unprivileged sockets —
    /// enough to exercise real `SCM_RIGHTS` fd-passing without root or a real
    /// TUN device. The passed fd is a pipe end, verified usable on the
    /// receiving side (distinct fd number, same underlying file).
    #[test]
    fn fd_travels_across_the_socket_and_is_usable() {
        let (a, b) = UnixStream::pair().unwrap();

        let mut pipe_fds = [0i32; 2];
        // SAFETY: fills `pipe_fds` with a valid, connected pipe pair.
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let (read_end, write_end) = (pipe_fds[0], pipe_fds[1]);

        send_with_fd(&a, b"hello", read_end).unwrap();

        let mut buf = [0u8; 16];
        let (n, fd) = recv_with_fd(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        let received = fd.expect("a fd should have been received").into_raw_fd();
        // The kernel duplicates the fd rather than transferring the original
        // number, so both are simultaneously open and distinct file
        // descriptions — closing ours here must not affect `received`.
        // SAFETY: closes our copy now that it's been sent; the receiver holds
        // its own duplicate from the kernel.
        unsafe { libc::close(read_end) };

        // Write through the original pipe's write end; read back through the
        // *received* fd to prove it's the same underlying pipe.
        let payload = b"through-the-pipe";
        // SAFETY: `write_end` is a valid, open pipe write fd.
        let w = unsafe { libc::write(write_end, payload.as_ptr().cast(), payload.len()) };
        assert_eq!(w, payload.len() as isize);

        let mut rbuf = [0u8; 32];
        // SAFETY: `received` is the fd handed back by `recv_with_fd`.
        let r = unsafe { libc::read(received, rbuf.as_mut_ptr().cast(), rbuf.len()) };
        assert_eq!(r, payload.len() as isize);
        assert_eq!(&rbuf[..r as usize], payload);

        // SAFETY: close the fds we still own.
        unsafe {
            libc::close(write_end);
            libc::close(received);
        }
    }

    #[test]
    fn no_fd_attached_is_reported_as_none() {
        let (a, b) = UnixStream::pair().unwrap();
        use std::io::Write;
        (&a).write_all(b"plain").unwrap();
        let mut buf = [0u8; 16];
        let (n, fd) = recv_with_fd(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"plain");
        assert!(fd.is_none());
    }
}
