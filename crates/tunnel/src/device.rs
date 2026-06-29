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
    /// Windows note: the `tun` crate's Windows (wintun) backend is **IPv4-only** —
    /// it stores the configured address as an `Ipv4Addr` and would *panic* on an
    /// IPv6 one. So for an IPv6 tunnel on Windows, [`Self::open`] brings the
    /// adapter up *without* an address through the crate and then assigns the v6
    /// address + MTU **out-of-band via `netsh interface ipv6`** on the named
    /// adapter (see [`configure_ipv6_windows`]). IPv4 on Windows, and both
    /// families on Unix, are configured by the `tun` crate directly.
    pub struct RealTun {
        dev: AsyncDevice,
    }

    impl RealTun {
        /// Create and bring up the interface (requires elevated privileges; on
        /// Windows also requires `wintun.dll` to be loadable at runtime).
        pub fn open(cfg: &TunConfig) -> Result<Self> {
            let mut tcfg = tun::Configuration::default();
            tcfg.name(&cfg.name).mtu(cfg.mtu as i32).up();

            // The `tun` crate's Windows (wintun) backend is IPv4-only and panics
            // on an IPv6 address, so for an IPv6 tunnel on Windows we leave the
            // address off here and assign it via `netsh` after the adapter exists.
            // Everywhere else (and for IPv4 on Windows) the crate sets it directly.
            let v6_out_of_band = cfg!(windows) && cfg.address.addr.is_ipv6();
            if !v6_out_of_band {
                tcfg.address(cfg.address.addr);
                if cfg.address.addr.is_ipv4() {
                    tcfg.netmask(prefix_to_netmask_v4(cfg.address.prefix));
                }
            }

            let dev = tun::create_as_async(&tcfg)
                .map_err(|e| crate::TunnelError::Io(std::io::Error::other(e.to_string())))?;

            #[cfg(windows)]
            if v6_out_of_band {
                configure_ipv6_windows(cfg)?;
            }

            Ok(Self { dev })
        }
    }

    /// Assign an IPv6 address (with its on-link prefix) and MTU to the named
    /// wintun adapter via `netsh`, working around the `tun` crate's IPv4-only
    /// Windows backend. Called only after the adapter exists; needs elevation.
    #[cfg(windows)]
    fn configure_ipv6_windows(cfg: &TunConfig) -> Result<()> {
        run_netsh(&netsh_add_v6_address_args(
            &cfg.name,
            cfg.address.addr,
            cfg.address.prefix,
        ))?;
        run_netsh(&netsh_set_v6_mtu_args(&cfg.name, cfg.mtu))?;
        Ok(())
    }

    /// Build the `netsh interface ipv6 add address …` argument vector. Factored
    /// out (and `IpAddr`-typed) so it is unit-testable without invoking `netsh`.
    /// The address carries its prefix (`fd00::1/64`), which sets the on-link route
    /// — the v6 analogue of the IPv4 address+netmask pair.
    #[cfg(windows)]
    fn netsh_add_v6_address_args(name: &str, addr: std::net::IpAddr, prefix: u8) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv6".into(),
            "add".into(),
            "address".into(),
            format!("interface={name}"),
            format!("address={addr}/{prefix}"),
        ]
    }

    /// Build the `netsh interface ipv6 set subinterface …` MTU argument vector.
    #[cfg(windows)]
    fn netsh_set_v6_mtu_args(name: &str, mtu: u16) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv6".into(),
            "set".into(),
            "subinterface".into(),
            format!("interface={name}"),
            format!("mtu={mtu}"),
            "store=active".into(),
        ]
    }

    /// Run `netsh` with `args`, mapping a spawn failure or non-zero exit to a
    /// clear [`crate::TunnelError::Io`].
    #[cfg(windows)]
    fn run_netsh(args: &[String]) -> Result<()> {
        let out = std::process::Command::new("netsh")
            .args(args)
            .output()
            .map_err(|e| {
                crate::TunnelError::Io(std::io::Error::other(format!("failed to spawn netsh: {e}")))
            })?;
        if !out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(crate::TunnelError::Io(std::io::Error::other(format!(
                "`netsh {}` failed ({}): {} {}",
                args.join(" "),
                out.status,
                stdout.trim(),
                stderr.trim(),
            ))));
        }
        Ok(())
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

        /// On Windows an IPv6 tunnel address is assigned out-of-band via `netsh`
        /// (the `tun` crate is IPv4-only there). These cover the pure arg-building
        /// — no elevation / driver access — so they run on any Windows host. The
        /// address carries its `/prefix`, mirroring the IPv4 address+netmask pair.
        #[cfg(windows)]
        #[test]
        fn netsh_v6_address_args_are_correct() {
            let addr: std::net::IpAddr = "fd00::1".parse().unwrap();
            let expected: Vec<String> = [
                "interface",
                "ipv6",
                "add",
                "address",
                "interface=ferrum0",
                "address=fd00::1/64",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            assert_eq!(netsh_add_v6_address_args("ferrum0", addr, 64), expected);
        }

        #[cfg(windows)]
        #[test]
        fn netsh_v6_mtu_args_are_correct() {
            let expected: Vec<String> = [
                "interface",
                "ipv6",
                "set",
                "subinterface",
                "interface=ferrum0",
                "mtu=1280",
                "store=active",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            assert_eq!(netsh_set_v6_mtu_args("ferrum0", 1280), expected);
        }
    }
}

/// Open the platform TUN device, or fail with [`crate::TunnelError::UnsupportedPlatform`].
#[cfg(all(any(unix, windows), feature = "real-tun"))]
pub fn open(cfg: &TunConfig) -> Result<impl TunDevice> {
    imp::RealTun::open(cfg)
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
