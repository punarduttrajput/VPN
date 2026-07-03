//! TUN device abstraction (PRD FR1).
//!
//! The data plane talks to an OS virtual interface only through the [`TunDevice`]
//! trait. The real implementation exists on Unix (Phase 1 scope: Linux/macOS);
//! other platforms get a stub that fails at construction, and tests use a mock.

use crate::Result;

/// A virtual network interface that yields and accepts raw IP packets.
///
/// Methods return `Send` futures so the data plane can drive the device from a
/// spawned task (see the runner's pipeline).
pub trait TunDevice: Send {
    /// Read one outbound IP packet from the OS into `buf`; returns its length.
    fn read_packet(
        &mut self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = Result<usize>> + Send;
    /// Write one decrypted IP packet to the OS.
    fn write_packet(
        &mut self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Parameters for bringing up a TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Desired interface name (best effort; OS may rename).
    pub name: String,
    /// CIDR address to assign, e.g. `10.8.0.1/24`.
    pub address: ferrum_core::config::Cidr,
    /// MTU for the interface.
    pub mtu: u16,
}

#[cfg(all(any(unix, windows), feature = "real-tun"))]
mod imp {
    use super::*;
    use tun::AsyncDevice;

    /// Real OS TUN device backed by the `tun` crate — `/dev/net/tun` (or the
    /// macOS utun) on Unix, the **wintun** adapter on Windows. The crate exposes
    /// the same `AsyncDevice` (impl tokio `AsyncRead`/`AsyncWrite`) on every
    /// platform, so the I/O path below is shared; only adapter creation differs
    /// (and the `tun` crate handles that per-platform).
    ///
    /// Windows note: the wintun adapter only takes an **IPv4** address. The `tun`
    /// crate's Windows backend stores the configured address as an `Ipv4Addr` and
    /// would *panic* on an IPv6 one, so [`Self::open`] rejects an IPv6 tunnel
    /// address with a clean error there (see the guard below). Full IPv6 support
    /// would need the v6 address set out-of-band (e.g. `netsh interface ipv6` on
    /// the named adapter, or `wintun`'s `set_network_addresses_tuple`, neither of
    /// which the `tun` crate exposes) and is a documented follow-up. Unix handles
    /// v4 and v6 alike.
    /// Build the `tun` crate's `Configuration` for `cfg`, applying the same
    /// Windows IPv6 guard either device-construction path needs. Shared by
    /// [`RealTun::open`] (async, in-process privileged use) and `open_raw`
    /// (sync, Unix-only — the privileged helper daemon's path, Phase 5) so the
    /// two never drift apart.
    fn build_tun_config(cfg: &TunConfig) -> Result<tun::Configuration> {
        // On Windows the wintun backend is IPv4-only; an IPv6 address would
        // panic inside the `tun` crate (`Ipv4Addr` conversion `unwrap`). Reject
        // it cleanly before touching the driver (no elevation needed to hit
        // this path). On Unix the kernel configures either family.
        #[cfg(windows)]
        if cfg.address.addr.is_ipv6() {
            return Err(crate::TunnelError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "IPv6 tunnel addresses are not yet supported on Windows (wintun); use IPv4",
            )));
        }
        let mut tcfg = tun::Configuration::default();
        tcfg.name(&cfg.name)
            .address(cfg.address.addr)
            .mtu(cfg.mtu as i32)
            .up();
        // Netmask derived from prefix for IPv4.
        if cfg.address.addr.is_ipv4() {
            let mask = prefix_to_netmask_v4(cfg.address.prefix);
            tcfg.netmask(mask);
        }
        Ok(tcfg)
    }

    pub struct RealTun {
        dev: AsyncDevice,
    }

    impl RealTun {
        /// Create and bring up the interface (requires elevated privileges; on
        /// Windows also requires `wintun.dll` to be loadable at runtime).
        pub fn open(cfg: &TunConfig) -> Result<Self> {
            let tcfg = build_tun_config(cfg)?;
            let dev = tun::create_as_async(&tcfg)
                .map_err(|e| crate::TunnelError::Io(std::io::Error::other(e.to_string())))?;
            Ok(Self { dev })
        }
    }

    /// Synchronously create and configure the TUN interface, returning its raw
    /// fd rather than wrapping it (Unix only). This is what the privileged
    /// helper daemon (Phase 5) calls: it creates the interface (needing the
    /// same elevated privileges as [`RealTun::open`]) and hands the fd to the
    /// unprivileged GUI process via [`crate::fdpass`], instead of driving the
    /// device's I/O itself.
    #[cfg(unix)]
    pub fn open_raw(cfg: &TunConfig) -> Result<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;

        let tcfg = build_tun_config(cfg)?;
        let dev = tun::create(&tcfg)
            .map_err(|e| crate::TunnelError::Io(std::io::Error::other(e.to_string())))?;
        Ok(dev.into_raw_fd())
    }

    impl TunDevice for RealTun {
        async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            use tokio::io::AsyncReadExt as _;
            let n = self.dev.read(buf).await?;
            Ok(n)
        }

        async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
            use tokio::io::AsyncWriteExt as _;
            self.dev.write_all(packet).await?;
            Ok(())
        }
    }

    fn prefix_to_netmask_v4(prefix: u8) -> std::net::Ipv4Addr {
        let bits: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix.min(32))
        };
        std::net::Ipv4Addr::from(bits)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn prefix_to_netmask_v4_is_correct() {
            assert_eq!(
                prefix_to_netmask_v4(24),
                std::net::Ipv4Addr::new(255, 255, 255, 0)
            );
            assert_eq!(
                prefix_to_netmask_v4(16),
                std::net::Ipv4Addr::new(255, 255, 0, 0)
            );
            assert_eq!(
                prefix_to_netmask_v4(32),
                std::net::Ipv4Addr::new(255, 255, 255, 255)
            );
            assert_eq!(prefix_to_netmask_v4(0), std::net::Ipv4Addr::new(0, 0, 0, 0));
        }

        /// On Windows, an IPv6 tunnel address must fail with a clean error rather
        /// than panicking inside the `tun` crate. This returns before any driver
        /// access, so it needs no elevation / loadable `wintun.dll`.
        #[cfg(windows)]
        #[test]
        fn open_rejects_ipv6_on_windows() {
            let cfg = TunConfig {
                name: "ferrum-test".to_string(),
                address: "fd00::1/64".parse().unwrap(),
                mtu: 1280,
            };
            match RealTun::open(&cfg) {
                Err(crate::TunnelError::Io(e)) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::Unsupported)
                }
                Err(other) => panic!("expected an Io(Unsupported) error, got {other:?}"),
                Ok(_) => panic!("IPv6 must be rejected on Windows"),
            }
        }
    }
}

/// Open the platform TUN device, or fail with [`crate::TunnelError::UnsupportedPlatform`].
#[cfg(all(any(unix, windows), feature = "real-tun"))]
pub fn open(cfg: &TunConfig) -> Result<impl TunDevice> {
    imp::RealTun::open(cfg)
}

/// Synchronously create and configure the TUN device, returning its raw fd
/// (Unix only). See [`imp::open_raw`] — used by the privileged helper daemon
/// (Phase 5) to create the interface and hand its fd to an unprivileged caller.
#[cfg(all(unix, feature = "real-tun"))]
pub fn open_raw(cfg: &TunConfig) -> Result<std::os::unix::io::RawFd> {
    imp::open_raw(cfg)
}

/// Open a TUN device by asking the privileged helper daemon (Phase 5) to
/// create one and hand back its fd, rather than opening `/dev/net/tun`
/// in-process. Connects to `socket_path` (the helper's `UnixListener`),
/// sends an `OpenTun` request, and wraps the returned fd with [`from_fd`] —
/// so the caller's I/O path is identical to the fd-from-native-shell case.
#[cfg(all(unix, feature = "helper-ipc"))]
pub fn open_via_helper(socket_path: &str, cfg: &TunConfig) -> Result<impl TunDevice> {
    use crate::helper_proto::{self, HelperResponse};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    helper_proto::send_request(&mut stream, &helper_proto::open_tun_request(cfg))?;
    let (resp, fd) = helper_proto::recv_response(&stream)?;
    match resp {
        HelperResponse::TunOpened => {
            let fd = fd.ok_or_else(|| {
                crate::TunnelError::Io(std::io::Error::other(
                    "helper reported TunOpened but sent no fd",
                ))
            })?;
            from_fd(fd)
        }
        HelperResponse::Err(msg) => Err(crate::TunnelError::Io(std::io::Error::other(format!(
            "helper: {msg}"
        )))),
        HelperResponse::Ok => Err(crate::TunnelError::Io(std::io::Error::other(
            "helper sent an unexpected Ok response to an OpenTun request",
        ))),
    }
}

/// Stub when the real device is unavailable (no `real-tun` feature, or a platform
/// without a real backend).
#[cfg(not(all(any(unix, windows), feature = "real-tun")))]
pub fn open(_cfg: &TunConfig) -> Result<NoopTun> {
    Err(crate::TunnelError::UnsupportedPlatform)
}

/// A do-nothing device type used so builds without a real device still type-check.
/// Returned by [`open`] when no real backend is compiled in, and by [`from_fd`] on
/// non-Unix (where there is no fd-based TUN). Defined unconditionally — and so
/// unused on platforms that have a real device — hence `allow(dead_code)`.
#[allow(dead_code)]
pub struct NoopTun;

impl TunDevice for NoopTun {
    async fn read_packet(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Err(crate::TunnelError::UnsupportedPlatform)
    }
    async fn write_packet(&mut self, _packet: &[u8]) -> Result<()> {
        Err(crate::TunnelError::UnsupportedPlatform)
    }
}

/// Wrap a platform-provided TUN file descriptor (Phase 5).
///
/// Native VPN shells (iOS `NEPacketTunnelProvider`, Android `FerrumService`) don't
/// open `/dev/net/tun` themselves — the OS hands them an already-configured fd.
/// [`from_fd`] adopts that fd and does readiness-based async I/O on it directly
/// (the `tun` crate ignores a supplied fd on Linux, and no address/MTU setup is
/// needed — the platform already did it). Takes ownership: the fd is closed on
/// drop.
#[cfg(unix)]
pub fn from_fd(fd: std::os::unix::io::RawFd) -> Result<impl TunDevice> {
    fd_device::FdTun::from_raw_fd(fd)
}

/// Stub on non-Unix: there is no fd-based TUN.
#[cfg(not(unix))]
pub fn from_fd(_fd: i32) -> Result<NoopTun> {
    Err(crate::TunnelError::UnsupportedPlatform)
}

#[cfg(unix)]
mod fd_device {
    use std::io;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use tokio::io::unix::AsyncFd;

    use super::TunDevice;
    use crate::Result;

    /// A [`TunDevice`] backed by a raw, OS-provided fd.
    pub struct FdTun {
        inner: AsyncFd<OwnedFd>,
    }

    impl FdTun {
        /// Adopt `fd` (must be a valid, open TUN fd) and prepare it for async I/O.
        pub fn from_raw_fd(fd: RawFd) -> Result<Self> {
            if fd < 0 {
                return Err(crate::TunnelError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid TUN file descriptor",
                )));
            }
            set_nonblocking(fd)?;
            // SAFETY: the caller transfers ownership of a valid, open fd; the
            // resulting `OwnedFd` closes it on drop.
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Self {
                inner: AsyncFd::new(owned)?,
            })
        }
    }

    impl TunDevice for FdTun {
        async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            loop {
                let mut guard = self.inner.readable().await?;
                match guard.try_io(|fd| {
                    // SAFETY: read up to `buf.len()` bytes into `buf` from a fd the
                    // reactor reports readable; returns the count or -1 + errno.
                    let n = unsafe {
                        libc::read(fd.get_ref().as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(result) => return result.map_err(Into::into),
                    Err(_would_block) => continue,
                }
            }
        }

        async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
            loop {
                let mut guard = self.inner.writable().await?;
                match guard.try_io(|fd| {
                    // SAFETY: write `packet.len()` bytes from `packet` to a fd the
                    // reactor reports writable; returns the count or -1 + errno.
                    let n = unsafe {
                        libc::write(
                            fd.get_ref().as_raw_fd(),
                            packet.as_ptr().cast(),
                            packet.len(),
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                }) {
                    Ok(result) => return result.map_err(Into::into),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    /// Put `fd` into non-blocking mode so `AsyncFd` can drive it.
    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY: F_GETFL/F_SETFL on a valid fd only read/modify status flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A socketpair gives two connected fds that behave enough like a TUN
        /// (readiness-driven, bidirectional) to exercise the `AsyncFd` I/O path
        /// without `/dev/net/tun` or root.
        #[tokio::test]
        async fn fd_tun_reads_and_writes_over_socketpair() {
            let mut fds = [0 as RawFd; 2];
            // SAFETY: socketpair fills the 2-element array with connected fds.
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "socketpair failed");
            let (ours, peer) = (fds[0], fds[1]);

            let mut tun = FdTun::from_raw_fd(ours).unwrap();

            // Peer writes a "packet"; FdTun reads it.
            let payload = b"hello-tun";
            // SAFETY: write `payload` to the peer fd.
            let n = unsafe { libc::write(peer, payload.as_ptr().cast(), payload.len()) };
            assert_eq!(n, payload.len() as isize);
            let mut buf = [0u8; 64];
            let got = tun.read_packet(&mut buf).await.unwrap();
            assert_eq!(&buf[..got], payload);

            // FdTun writes a "packet"; peer reads it.
            tun.write_packet(b"from-tun").await.unwrap();
            let mut rbuf = [0u8; 64];
            // SAFETY: read from the peer fd into `rbuf`.
            let m = unsafe { libc::read(peer, rbuf.as_mut_ptr().cast(), rbuf.len()) };
            assert!(m > 0);
            assert_eq!(&rbuf[..m as usize], b"from-tun");

            // SAFETY: close the peer fd (FdTun owns and closes `ours`).
            unsafe { libc::close(peer) };
        }
    }
}

pub mod mock {
    //! An in-memory TUN device for tests: packets written by the runner are
    //! captured, and packets to deliver to the runner are queued.
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Shared state between the test and the mock device.
    #[derive(Default, Clone)]
    pub struct MockTun {
        /// Packets the runner wants to inject (read side).
        pub to_runner: Arc<Mutex<VecDeque<Vec<u8>>>>,
        /// Packets the runner wrote to the device (write side).
        pub from_runner: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl TunDevice for MockTun {
        async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            loop {
                if let Some(p) = self.to_runner.lock().unwrap().pop_front() {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    return Ok(n);
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
        async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
            self.from_runner.lock().unwrap().push(packet.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn mock_roundtrips_packets() {
        let mut m = MockTun::default();
        m.to_runner.lock().unwrap().push_back(vec![1, 2, 3]);
        let mut buf = [0u8; 16];
        let n = m.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3]);
        m.write_packet(&[9, 9]).await.unwrap();
        assert_eq!(m.from_runner.lock().unwrap()[0], vec![9, 9]);
    }
}
