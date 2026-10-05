//! Linux TUN devices and their routing, for UE and UPF sessions.
//!
//! [`TunPort::create`] makes the TUN and sets up its address, routes, rule
//! or VRF over rtnetlink. [`TunPort::try_close`] removes them, reporting
//! cleanup failures so they can be retried. [`TunPort::close`] and dropping
//! the last clone of the port perform best-effort cleanup. It needs
//! `CAP_NET_ADMIN`.

use crate::netlink::Netlink;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

mod device;
mod error;
mod routing;
use device::TunDevice;
use routing::RoutingLease;

/// How Linux routes a TUN's traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Routing {
    /// A UE session: the TUN gets `address`, and a rule with `priority`
    /// sends packets from it to `table`, whose default route is the TUN.
    UePolicy {
        /// The UE's address.
        address: Ipv4Addr,
        /// The session's routing table, not 0 or 253..=255.
        table: u32,
        /// The rule's priority, 1..=32765, before the main table's rule.
        priority: u32,
    },
    /// A UE session: the TUN gets `address` and joins a new VRF `vrf_name`
    /// for `table`, whose default route is the TUN.
    UeVrf {
        /// The UE's address.
        address: Ipv4Addr,
        /// The VRF's routing table, not 0 or 253..=255.
        table: u32,
        /// The VRF's name.
        vrf_name: String,
    },
    /// A UPF session: the main table routes `ue_address` to the TUN.
    Upf {
        /// The UE's address.
        ue_address: Ipv4Addr,
    },
}

/// A TUN device to create.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TunConfig {
    /// The interface name: 1 to 15 ASCII letters, digits, `_` or `-`.
    pub name: String,
    /// Its routing.
    pub routing: Routing,
}

impl TunConfig {
    /// A TUN named `name` with `routing`.
    pub fn new(name: impl Into<String>, routing: Routing) -> Self {
        Self {
            name: name.into(),
            routing,
        }
    }
}

/// A TUN device that exchanges raw IPv4 and IPv6 packets with Linux.
/// Clones share the device, as for a task that reads it and one that
/// writes; dropping the last one removes the TUN and its routing.
///
/// ```no_run
/// use oxirush_gtp_u::tun::{Routing, TunConfig, TunPort};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> std::io::Result<()> {
/// // A UE's TUN: Linux routes into it what is sent from the UE's address.
/// let routing = Routing::UePolicy {
///     address: "10.45.0.2".parse().unwrap(),
///     table: 100,
///     priority: 100,
/// };
/// let tun = TunPort::create(TunConfig::new("ue0", routing))?;
///
/// let mut packet = vec![0; 65535];
/// let length = tun.recv(&mut packet).await?;
/// // `packet[..length]` goes into the UE's tunnel, and what the tunnel
/// // brings for the UE goes to Linux:
/// # let downlink = &packet[..length];
/// tun.send(downlink).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TunPort {
    inner: Arc<Inner>,
}

struct Inner {
    // Routing must drop before the descriptor: cleanup still identifies the live device.
    routing: RoutingLease,
    device: TunDevice,
    index: u32,
}

impl TunPort {
    /// Create the TUN and set up its routing. A name already in use is an
    /// [`AlreadyExists`](io::ErrorKind::AlreadyExists) error. On any error,
    /// what was set up is removed.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub fn create(config: TunConfig) -> io::Result<Self> {
        routing::validate(&config)?;
        let mut netlink = Netlink::new()?;
        let device = TunDevice::create(&config.name)?;
        let index = netlink.index_of(&config.name)?;
        let routing = RoutingLease::create(config.name, netlink, index, config.routing)?;
        Ok(Self {
            inner: Arc::new(Inner {
                routing,
                device,
                index,
            }),
        })
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        self.inner.routing.name()
    }

    /// The interface index, in the network namespace of its creation.
    pub fn index(&self) -> u32 {
        self.inner.index
    }

    /// Read a raw IPv4 or IPv6 packet that Linux routed to the TUN. A
    /// packet longer than `buffer` is cut to it: 65535 bytes hold any, and
    /// 1500 those of a TUN whose MTU was not changed.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.device.recv(buffer).await
    }

    /// Hand a raw IPv4 or IPv6 packet to Linux, as if the TUN received it.
    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.inner.device.send(packet).await
    }

    /// Remove the TUN, its address and routes, and its rule or VRF in the
    /// network namespace where it was created. The other clones of the
    /// port then observe `recv` and `send` errors.
    ///
    /// Attempts every remaining resource and returns the first failure.
    /// Successfully removed or already absent resources are forgotten;
    /// failed removals are retained for the next call. This blocks while
    /// waiting for netlink acknowledgements and requires `CAP_NET_ADMIN`
    /// in the creation namespace.
    pub fn try_close(&self) -> io::Result<()> {
        self.inner.routing.try_close()
    }

    /// Perform best-effort cleanup, logging any failure. Later calls retry
    /// remaining resources; use [`try_close`](Self::try_close) to inspect failures.
    pub fn close(&self) {
        self.inner.routing.close();
    }
}

impl fmt::Debug for TunPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunPort")
            .field("name", &self.name())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::error::context;
    use super::*;

    #[test]
    fn context_preserves_the_original_io_error() {
        let error = context(io::Error::from_raw_os_error(libc::EPERM), "remove TUN");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().starts_with("remove TUN: "));
        let source = error.get_ref().unwrap().source().unwrap();
        assert_eq!(
            source.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EPERM)
        );
    }

    #[test]
    fn tun_port_can_be_shared_between_tasks() {
        fn assert_shared<T: Clone + Send + Sync>() {}
        assert_shared::<TunPort>();
    }
}
