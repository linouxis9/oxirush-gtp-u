//! Linux TUN devices and their routing, for UE and UPF sessions.
//!
//! [`TunPort::create`] makes the TUN and sets up its address, routes, rule
//! or VRF over rtnetlink. [`TunPort::close`], or dropping the port, removes
//! all of them. It needs `CAP_NET_ADMIN`.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::sync::Mutex;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::netlink::{MAIN_TABLE, Netlink, Rule, index_of, name_of};
use crate::path::lock;

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
pub struct TunPort {
    io: AsyncFd<File>,
    name: String,
    cleanup: Mutex<Cleanup>,
}

/// What `close` removes. The TUN's address and routes go with it.
struct Cleanup {
    index: u32,
    rule: Option<Rule>,
    vrf: Option<(u32, String)>,
    closed: bool,
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(invalid(format!(
            "interface name {name:?} must have 1 to 15 bytes"
        )));
    }
    if !name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(invalid(format!(
            "interface name {name:?} has characters other than letters, digits, _ and -"
        )));
    }
    Ok(())
}

fn validate_table(table: u32) -> io::Result<()> {
    // Unspecified, default, main and local.
    if table == 0 || (253..=255).contains(&table) {
        return Err(invalid(format!("routing table {table} is reserved")));
    }
    Ok(())
}

fn context(error: io::Error, what: impl fmt::Display) -> io::Error {
    io::Error::new(error.kind(), format!("{what}: {error}"))
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
        validate_name(&config.name)?;
        match &config.routing {
            Routing::UePolicy {
                table, priority, ..
            } => {
                validate_table(*table)?;
                if !(1..32766).contains(priority) {
                    return Err(invalid(format!(
                        "rule priority {priority} is outside 1..=32765"
                    )));
                }
            }
            Routing::UeVrf {
                table, vrf_name, ..
            } => {
                validate_table(*table)?;
                validate_name(vrf_name)?;
            }
            Routing::Upf { .. } => {}
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        // SAFETY: ifreq is plain data, for which all zeros is valid.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        // The name is at most 15 bytes, so the last byte stays NUL.
        for (target, byte) in request.ifr_name.iter_mut().zip(config.name.bytes()) {
            *target = byte as libc::c_char;
        }
        // IFF_TUN_EXCL: fail instead of attaching to an existing device.
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
        // SAFETY: TUNSETIFF reads and writes the ifreq, which outlives the
        // call, on a valid /dev/net/tun descriptor.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::EBUSY) => io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("network interface {} already exists", config.name),
                ),
                _ => context(error, format_args!("create TUN {}", config.name)),
            });
        }
        set_nonblocking(&file)?;
        let index = index_of(&config.name)?;
        let port = Self {
            io: AsyncFd::new(file)?,
            name: config.name,
            cleanup: Mutex::new(Cleanup {
                index,
                rule: None,
                vrf: None,
                closed: false,
            }),
        };
        // On error, dropping `port` removes what was set up.
        port.configure(config.routing)?;
        Ok(port)
    }

    fn configure(&self, routing: Routing) -> io::Result<()> {
        let mut netlink = Netlink::new()?;
        let index = lock(&self.cleanup).index;
        let name = &self.name;
        // The routing is IPv4 only. Without IPv6 addresses, Linux sends no
        // router solicitations through the TUN. A kernel without IPv6 has
        // none to disable.
        match netlink.disable_ipv6_addresses(index) {
            Err(error)
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::EAFNOSUPPORT | libc::EOPNOTSUPP)
                ) =>
            {
                return Err(context(
                    error,
                    format_args!("disable IPv6 addresses on {name}"),
                ));
            }
            _ => {}
        }
        match routing {
            Routing::UePolicy {
                address,
                table,
                priority,
            } => {
                netlink
                    .add_address(index, address)
                    .map_err(|e| context(e, format_args!("add {address}/32 to {name}")))?;
                netlink
                    .set_up(index)
                    .map_err(|e| context(e, format_args!("set {name} up")))?;
                netlink.add_route(None, index, table).map_err(|e| {
                    context(
                        e,
                        format_args!("add default route via {name} to table {table}"),
                    )
                })?;
                let rule = Rule {
                    source: address,
                    table,
                    priority,
                };
                netlink.add_rule(rule).map_err(|e| {
                    context(
                        e,
                        format_args!("add rule {priority}: from {address} lookup {table}"),
                    )
                })?;
                lock(&self.cleanup).rule = Some(rule);
            }
            Routing::UeVrf {
                address,
                table,
                vrf_name,
            } => {
                let vrf = netlink.add_vrf(&vrf_name, table).map_err(|e| {
                    context(e, format_args!("add VRF {vrf_name} for table {table}"))
                })?;
                lock(&self.cleanup).vrf = Some((vrf, vrf_name.clone()));
                netlink
                    .set_controller(index, vrf)
                    .map_err(|e| context(e, format_args!("put {name} in VRF {vrf_name}")))?;
                netlink
                    .add_address(index, address)
                    .map_err(|e| context(e, format_args!("add {address}/32 to {name}")))?;
                netlink
                    .set_up(index)
                    .map_err(|e| context(e, format_args!("set {name} up")))?;
                netlink
                    .set_up(vrf)
                    .map_err(|e| context(e, format_args!("set {vrf_name} up")))?;
                netlink.add_route(None, index, table).map_err(|e| {
                    context(
                        e,
                        format_args!("add default route via {name} to table {table}"),
                    )
                })?;
            }
            Routing::Upf { ue_address } => {
                netlink
                    .set_up(index)
                    .map_err(|e| context(e, format_args!("set {name} up")))?;
                netlink
                    .add_route(Some(ue_address), index, MAIN_TABLE)
                    .map_err(|e| {
                        context(e, format_args!("add route {ue_address}/32 via {name}"))
                    })?;
            }
        }
        Ok(())
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read a raw IPv4 or IPv6 packet that Linux routed to the TUN.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            // Error readiness wakes a reader when `close` removes the TUN.
            let mut ready = self.io.ready(Interest::READABLE | Interest::ERROR).await?;
            match ready.try_io(|inner| inner.get_ref().read(buffer)) {
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Hand a raw IPv4 or IPv6 packet to Linux, as if the TUN received it.
    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.io.ready(Interest::WRITABLE | Interest::ERROR).await?;
            match ready.try_io(|inner| inner.get_ref().write(packet)) {
                Ok(Ok(written)) if written == packet.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }

    /// Remove the TUN, with its address and routes, and the rule or VRF it
    /// got, even while other tasks still hold the port: their `recv` and
    /// `send` then fail. Later calls, and the one by `Drop`, do nothing. It
    /// acts in the network namespace of the calling thread, which should be
    /// the one the port was created in.
    pub fn close(&self) {
        let mut cleanup = lock(&self.cleanup);
        if cleanup.closed {
            return;
        }
        cleanup.closed = true;
        let mut netlink = match Netlink::new() {
            Ok(netlink) => netlink,
            Err(error) => {
                tracing::warn!("TUN {} not removed: {error}", self.name);
                return;
            }
        };
        let mut removals = Vec::new();
        if let Some(rule) = cleanup.rule.take() {
            removals.push(("rule", netlink.delete_rule(rule)));
        }
        // An interface removed by someone else may have left its index to
        // another one.
        if name_of(cleanup.index).as_deref() == Some(self.name.as_str()) {
            removals.push(("TUN", netlink.delete_link(cleanup.index)));
        }
        if let Some((vrf, vrf_name)) = cleanup.vrf.take() {
            if name_of(vrf).as_deref() == Some(vrf_name.as_str()) {
                removals.push(("VRF", netlink.delete_link(vrf)));
            }
        }
        for (what, result) in removals {
            if let Err(error) = result {
                tracing::warn!("{what} of TUN {} not removed: {error}", self.name);
            }
        }
    }
}

impl Drop for TunPort {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for TunPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunPort").field("name", &self.name).finish()
    }
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL only act on this valid descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
