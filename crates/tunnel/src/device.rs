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
    pub address: vpn_core::config::Cidr,
    /// MTU for the interface.
    pub mtu: u16,
}

#[cfg(all(unix, feature = "real-tun"))]
mod imp {
    use super::*;
    use tun::AsyncDevice;

    /// Real Unix TUN device backed by the `tun` crate.
    pub struct UnixTun {
        dev: AsyncDevice,
    }

    impl UnixTun {
        /// Create and bring up the interface (requires elevated privileges).
        pub fn open(cfg: &TunConfig) -> Result<Self> {
            let mut tcfg = tun::Configuration::default();
            tcfg.name(&cfg.name)
                .address(cfg.address.addr)
                .mtu(cfg.mtu as i32)
                .up();
            // Netmask derived from prefix for IPv4.
            if let std::net::IpAddr::V4(_) = cfg.address.addr {
                let mask = prefix_to_netmask_v4(cfg.address.prefix);
                tcfg.netmask(mask);
            }
            let dev = tun::create_as_async(&tcfg).map_err(|e| {
                crate::TunnelError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;
            Ok(Self { dev })
        }
    }

    impl TunDevice for UnixTun {
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
}

/// Open the platform TUN device, or fail with [`crate::TunnelError::UnsupportedPlatform`].
#[cfg(all(unix, feature = "real-tun"))]
pub fn open(cfg: &TunConfig) -> Result<impl TunDevice> {
    imp::UnixTun::open(cfg)
}

/// Stub when the real device is unavailable (no `real-tun` feature, or non-Unix).
#[cfg(not(all(unix, feature = "real-tun")))]
pub fn open(_cfg: &TunConfig) -> Result<NoopTun> {
    Err(crate::TunnelError::UnsupportedPlatform)
}

/// A do-nothing device type used so builds without a real device still type-check.
#[cfg(not(all(unix, feature = "real-tun")))]
pub struct NoopTun;

#[cfg(not(all(unix, feature = "real-tun")))]
impl TunDevice for NoopTun {
    async fn read_packet(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Err(crate::TunnelError::UnsupportedPlatform)
    }
    async fn write_packet(&mut self, _packet: &[u8]) -> Result<()> {
        Err(crate::TunnelError::UnsupportedPlatform)
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
