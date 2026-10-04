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

    /// Build the `tun` crate's `Configuration` for `cfg`, applying the same
    /// Windows-IPv6-out-of-band logic either device-construction path needs.
    /// Shared by [`RealTun::open`] (async, in-process privileged use) and
    /// `open_raw` (sync, Unix-only — the privileged helper daemon's path,
    /// Phase 5) so the two never drift apart. Returns whether the address was
    /// left unset (Windows + IPv6) — the caller then assigns it out-of-band.
    fn build_tun_config(cfg: &TunConfig) -> (tun::Configuration, bool) {
        let mut tcfg = tun::Configuration::default();
        tcfg.name(&cfg.name).mtu(cfg.mtu as i32).up();

        // The `tun` crate's Windows (wintun) backend is IPv4-only and panics
        // on an IPv6 address, so for an IPv6 tunnel on Windows we leave the
        // address off here and assign it via `netsh` after the adapter exists.
        // Everywhere else (and for IPv4 on Windows) the crate sets it directly.
        // Inert on Unix: `cfg!(windows)` is compile-time `false` there, so the
        // address is always set in-crate (`open_raw`, Unix-only, never hits
        // the out-of-band path).
        let v6_out_of_band = cfg!(windows) && cfg.address.addr.is_ipv6();
        if !v6_out_of_band {
            tcfg.address(cfg.address.addr);
            if cfg.address.addr.is_ipv4() {
                tcfg.netmask(prefix_to_netmask_v4(cfg.address.prefix));
            }
        }
        (tcfg, v6_out_of_band)
    }

    impl RealTun {
        /// Create and bring up the interface (requires elevated privileges; on
        /// Windows also requires `wintun.dll` to be loadable at runtime).
        pub fn open(cfg: &TunConfig) -> Result<Self> {
            let (tcfg, v6_out_of_band) = build_tun_config(cfg);
            let dev = tun::create_as_async(&tcfg)
                .map_err(|e| crate::TunnelError::Io(std::io::Error::other(e.to_string())))?;

            #[cfg(windows)]
            if v6_out_of_band {
                configure_ipv6_windows(cfg)?;
            }
            #[cfg(not(windows))]
            let _ = v6_out_of_band;

            Ok(Self { dev })
        }
    }

    /// Synchronously create and configure the TUN interface, returning its raw
    /// fd rather than wrapping it (Unix only). This is what the privileged
    /// helper daemon (Phase 5) calls: it creates the interface (needing the
    /// same elevated privileges as [`RealTun::open`]) and hands the fd to the
    /// unprivileged GUI process via [`crate::fdpass`], instead of driving the
    /// device's I/O itself. (Unix always sets the address in-crate, so the
    /// out-of-band flag from `build_tun_config` is never true here.)
    ///
    /// Returns an [`OwnedFd`](std::os::fd::OwnedFd): the caller owns the
    /// descriptor and dropping it closes it. The helper sends a *duplicate* to
    /// its client and must close its own copy, or every request leaks one and
    /// keeps the interface alive after the client exits (SEC-012). The name
    /// is validated first ([`crate::ifname::validate`]): it may come from an
    /// unprivileged helper client.
    #[cfg(unix)]
    pub fn open_raw(cfg: &TunConfig) -> Result<std::os::fd::OwnedFd> {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::io::IntoRawFd;

        crate::ifname::validate(&cfg.name)?;
        let (tcfg, _) = build_tun_config(cfg);
        let dev = tun::create(&tcfg)
            .map_err(|e| crate::TunnelError::Io(std::io::Error::other(e.to_string())))?;
        let raw = dev.into_raw_fd();
        // SAFETY: `into_raw_fd` just released this fd from the device we
        // exclusively owned; nothing else holds or will close it. (The `tun`
        // crate offers no `Into<OwnedFd>`, so this one conversion is unsafe.)
        #[allow(unsafe_code)]
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(owned)
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

/// Synchronously create and configure the TUN device, returning its raw fd
/// (Unix only). See [`imp::open_raw`] — used by the privileged helper daemon
/// (Phase 5) to create the interface and hand its fd to an unprivileged caller.
#[cfg(all(unix, feature = "real-tun"))]
pub fn open_raw(cfg: &TunConfig) -> Result<std::os::fd::OwnedFd> {
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
            from_owned_fd(fd)
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

/// Wrap an owned, platform-provided TUN file descriptor (Phase 5).
///
/// Native VPN shells (iOS `NEPacketTunnelProvider`, Android `FerrumService`) don't
/// open `/dev/net/tun` themselves — the OS hands them an already-configured fd.
/// This adopts that fd and does readiness-based async I/O on it directly (the
/// `tun` crate ignores a supplied fd on Linux, and no address/MTU setup is
/// needed — the platform already did it). The fd is closed on drop.
#[cfg(unix)]
pub fn from_owned_fd(fd: std::os::fd::OwnedFd) -> Result<impl TunDevice> {
    fd_device::FdTun::new(fd)
}

/// [`from_owned_fd`] for a raw fd number, as it arrives across an FFI boundary.
///
/// # Safety
///
/// `fd` must be an open file descriptor that the caller **owns and hands over**:
/// nothing else may use or close it afterwards, since the returned device closes
/// it on drop (SEC-016: this used to be a safe function, which let any integer
/// be adopted and later closed out from under its real owner).
#[cfg(unix)]
#[allow(unsafe_code)]
pub unsafe fn from_fd(fd: std::os::unix::io::RawFd) -> Result<impl TunDevice> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if fd < 0 {
        return Err(crate::TunnelError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid TUN file descriptor",
        )));
    }
    // SAFETY: the caller guarantees `fd` is open and owned, and transfers it.
    from_owned_fd(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Stub on non-Unix: there is no fd-based TUN.
///
/// # Safety
///
/// Nothing to uphold (the fd is ignored); `unsafe` only to match the Unix
/// signature.
#[cfg(not(unix))]
#[allow(unsafe_code)]
pub unsafe fn from_fd(_fd: i32) -> Result<NoopTun> {
    Err(crate::TunnelError::UnsupportedPlatform)
}

#[cfg(unix)]
mod fd_device {
    use std::io;
    use std::os::fd::OwnedFd;

    use tokio::io::unix::AsyncFd;

    use super::TunDevice;
    use crate::Result;

    /// A [`TunDevice`] backed by an OS-provided fd. Its I/O goes through
    /// `rustix`'s safe wrappers (SEC-016), so this module has no `unsafe`.
    pub struct FdTun {
        inner: AsyncFd<OwnedFd>,
    }

    impl FdTun {
        /// Adopt `fd` (an open TUN fd) and prepare it for async I/O.
        pub fn new(fd: OwnedFd) -> Result<Self> {
            // Non-blocking, so `AsyncFd` can drive it.
            rustix::io::ioctl_fionbio(&fd, true).map_err(io::Error::from)?;
            Ok(Self {
                inner: AsyncFd::new(fd)?,
            })
        }
    }

    impl TunDevice for FdTun {
        async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            loop {
                let mut guard = self.inner.readable().await?;
                match guard
                    .try_io(|fd| rustix::io::read(fd.get_ref(), &mut *buf).map_err(io::Error::from))
                {
                    Ok(result) => return result.map_err(Into::into),
                    Err(_would_block) => continue,
                }
            }
        }

        async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
            loop {
                let mut guard = self.inner.writable().await?;
                match guard.try_io(|fd| {
                    // A TUN write takes the whole packet or fails; a short count
                    // isn't expected, but don't silently report success on one.
                    let n = rustix::io::write(fd.get_ref(), packet).map_err(io::Error::from)?;
                    if n == packet.len() {
                        Ok(())
                    } else {
                        Err(io::Error::new(io::ErrorKind::WriteZero, "short TUN write"))
                    }
                }) {
                    Ok(result) => return result.map_err(Into::into),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A socketpair gives two connected fds that behave enough like a TUN
        /// (readiness-driven, bidirectional) to exercise the `AsyncFd` I/O path
        /// without `/dev/net/tun` or root.
        #[tokio::test]
        async fn fd_tun_reads_and_writes_over_socketpair() {
            use std::io::{Read, Write};

            let (ours, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut tun = FdTun::new(OwnedFd::from(ours)).unwrap();

            // Peer writes a "packet"; FdTun reads it.
            peer.write_all(b"hello-tun").unwrap();
            let mut buf = [0u8; 64];
            let got = tun.read_packet(&mut buf).await.unwrap();
            assert_eq!(&buf[..got], b"hello-tun");

            // FdTun writes a "packet"; peer reads it.
            tun.write_packet(b"from-tun").await.unwrap();
            let mut rbuf = [0u8; 64];
            let m = peer.read(&mut rbuf).unwrap();
            assert_eq!(&rbuf[..m], b"from-tun");
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
