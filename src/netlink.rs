//! The rtnetlink requests of the TUN module. Each waits for the kernel's
//! acknowledgement, which comes at once, and a second at most.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{
    AfSpecInet6, AfSpecUnspec, In6AddrGenMode, InfoData, InfoKind, InfoVrf, LinkAttribute,
    LinkFlags, LinkInfo, LinkMessage,
};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};

/// The main routing table.
pub(crate) const MAIN_TABLE: u32 = 254;

/// A policy routing rule: packets from `source` use `table`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rule {
    pub source: Ipv4Addr,
    pub table: u32,
    pub priority: u32,
}

/// How long a request waits for the kernel's answer. The kernel answers
/// within the request's system call; an answer that does not come, as
/// when the socket's buffer was full, must not hold the caller for ever:
/// the calls of an endpoint run in a task of the caller's runtime.
const ANSWER: Duration = Duration::from_secs(1);

/// A NETLINK_ROUTE socket.
pub(crate) struct Netlink {
    socket: Socket,
    sequence: u32,
}

/// A socket whose receive waits [`ANSWER`] at most.
fn socket() -> io::Result<Socket> {
    let socket = Socket::new(NETLINK_ROUTE)?;
    let timeout = libc::timeval {
        tv_sec: ANSWER.as_secs() as libc::time_t,
        tv_usec: ANSWER.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: the option's value is a timeval, which outlives the call.
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// The next datagram from the kernel into `buffer`, within [`ANSWER`].
fn receive(socket: &Socket, buffer: &mut Vec<u8>) -> io::Result<()> {
    buffer.clear();
    match socket.recv(buffer, 0) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the kernel said nothing over rtnetlink in {ANSWER:?}"),
        )),
        Err(error) => Err(error),
    }
}

impl Netlink {
    pub fn new() -> io::Result<Self> {
        let mut socket = socket()?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    /// The next datagram from the kernel, within [`ANSWER`].
    fn receive(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
        receive(&self.socket, buffer)
    }

    /// Send `message` and wait for the kernel's acknowledgement.
    fn request(&mut self, message: RouteNetlinkMessage, flags: u16) -> io::Result<()> {
        self.exchange(message, flags).map(|_| ())
    }

    /// Send `message` and return what the kernel answers before its
    /// acknowledgement: the link or the route asked for.
    fn exchange(
        &mut self,
        message: RouteNetlinkMessage,
        flags: u16,
    ) -> io::Result<Option<RouteNetlinkMessage>> {
        self.sequence = self.sequence.wrapping_add(1);
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        header.sequence_number = self.sequence;
        let mut request = NetlinkMessage::new(header, NetlinkPayload::from(message));
        request.finalize();
        let mut bytes = vec![0; request.buffer_len()];
        request.serialize(&mut bytes);
        self.socket.send(&bytes, 0)?;
        let mut buffer = Vec::with_capacity(65536);
        let mut answer = None;
        loop {
            self.receive(&mut buffer)?;
            let mut datagram = buffer.as_slice();
            while !datagram.is_empty() {
                let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(datagram)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                if reply.header.sequence_number == self.sequence {
                    match reply.payload {
                        NetlinkPayload::Error(error) => {
                            return match error.code {
                                None => Ok(answer),
                                Some(_) => Err(error.to_io()),
                            };
                        }
                        NetlinkPayload::InnerMessage(message) => answer = Some(message),
                        _ => {}
                    }
                }
                // Messages are aligned to 4 octets.
                let length = (reply.header.length as usize + 3) & !3;
                if length == 0 || length >= datagram.len() {
                    break;
                }
                datagram = &datagram[length..];
            }
        }
    }

    /// Resolve a link in the namespace this socket was created in.
    fn get_link(&mut self, message: LinkMessage) -> io::Result<LinkMessage> {
        match self.exchange(RouteNetlinkMessage::GetLink(message), 0)? {
            Some(RouteNetlinkMessage::NewLink(link)) => Ok(link),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing link reply",
            )),
        }
    }

    /// The interface through which Linux routes packets from the local
    /// address `source` to `destination`: loopback when both are this host's.
    #[cfg(fast_path)]
    pub fn route_interface(&mut self, source: Ipv4Addr, destination: Ipv4Addr) -> io::Result<u32> {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet;
        message.header.destination_prefix_length = 32;
        message.header.source_prefix_length = 32;
        message
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(destination)));
        message
            .attributes
            .push(RouteAttribute::Source(RouteAddress::Inet(source)));
        let interface =
            match self.exchange(RouteNetlinkMessage::GetRoute(message), 0)? {
                Some(RouteNetlinkMessage::NewRoute(route)) => route
                    .attributes
                    .into_iter()
                    .find_map(|attribute| match attribute {
                        RouteAttribute::Oif(index) => Some(index),
                        _ => None,
                    }),
                _ => None,
            };
        interface.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                format!("no route from {source} to {destination}"),
            )
        })
    }

    pub fn index_of(&mut self, name: &str) -> io::Result<u32> {
        let mut message = LinkMessage::default();
        message
            .attributes
            .push(LinkAttribute::IfName(name.to_owned()));
        Ok(self.get_link(message)?.header.index)
    }

    pub fn name_of(&mut self, index: u32) -> io::Result<Option<String>> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        let link = match self.get_link(message) {
            Ok(link) => link,
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Ok(None),
            Err(error) => return Err(error),
        };
        link.attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::IfName(name) => Some(name),
                _ => None,
            })
            .map(Some)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing link name"))
    }

    pub fn set_up(&mut self, index: u32) -> io::Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.header.flags = LinkFlags::Up;
        message.header.change_mask = LinkFlags::Up;
        self.request(RouteNetlinkMessage::SetLink(message), 0)
    }

    /// Give link `index` no IPv6 addresses, not even a link-local one.
    pub fn disable_ipv6_addresses(&mut self, index: u32) -> io::Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message
            .attributes
            .push(LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(
                vec![AfSpecInet6::AddrGenMode(In6AddrGenMode::None)],
            )]));
        self.request(RouteNetlinkMessage::SetLink(message), 0)
    }

    /// Make link `index` a port of `controller`, such as a VRF.
    pub fn set_controller(&mut self, index: u32, controller: u32) -> io::Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message
            .attributes
            .push(LinkAttribute::Controller(controller));
        self.request(RouteNetlinkMessage::SetLink(message), 0)
    }

    /// Create VRF `name` for `table` and return its index.
    pub fn add_vrf(&mut self, name: &str, table: u32) -> io::Result<u32> {
        let mut message = LinkMessage::default();
        message
            .attributes
            .push(LinkAttribute::IfName(name.to_owned()));
        message.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vrf),
            LinkInfo::Data(InfoData::Vrf(vec![InfoVrf::TableId(table)])),
        ]));
        self.request(
            RouteNetlinkMessage::NewLink(message),
            NLM_F_CREATE | NLM_F_EXCL,
        )?;
        self.index_of(name)
    }

    /// Create veth `name` with its other end `peer`, both with the largest
    /// MTU: whatever enters one end must be let through the other.
    #[cfg(fast_path)]
    pub fn add_veth(&mut self, name: &str, peer: &str) -> io::Result<()> {
        use netlink_packet_route::link::InfoVeth;
        let mtu = u32::from(u16::MAX);
        let mut far = LinkMessage::default();
        far.attributes.push(LinkAttribute::IfName(peer.to_owned()));
        far.attributes.push(LinkAttribute::Mtu(mtu));
        let mut message = LinkMessage::default();
        message
            .attributes
            .push(LinkAttribute::IfName(name.to_owned()));
        message.attributes.push(LinkAttribute::Mtu(mtu));
        message.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(far))),
        ]));
        self.request(
            RouteNetlinkMessage::NewLink(message),
            NLM_F_CREATE | NLM_F_EXCL,
        )
    }

    /// Whether link `index` is a veth that was set up.
    #[cfg(fast_path)]
    pub fn is_up_veth(&mut self, index: u32) -> bool {
        let mut message = LinkMessage::default();
        message.header.index = index;
        self.get_link(message).is_ok_and(|link| {
            link.header.flags.contains(LinkFlags::Up)
                && link.attributes.iter().any(|attribute| {
                    matches!(attribute, LinkAttribute::LinkInfo(info)
                        if info.contains(&LinkInfo::Kind(InfoKind::Veth)))
                })
        })
    }

    /// The MTU of link `index`.
    #[cfg(fast_path)]
    pub fn mtu_of(&mut self, index: u32) -> io::Result<u32> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        self.get_link(message)?
            .attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::Mtu(mtu) => Some(mtu),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing link MTU"))
    }

    pub fn delete_link(&mut self, index: u32) -> io::Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        self.request(RouteNetlinkMessage::DelLink(message), 0)
    }

    /// Give link `index` the address `address/32`.
    pub fn add_address(&mut self, index: u32, address: Ipv4Addr) -> io::Result<()> {
        let mut message = AddressMessage::default();
        message.header.family = AddressFamily::Inet;
        message.header.prefix_len = 32;
        message.header.index = index;
        message
            .attributes
            .push(AddressAttribute::Local(address.into()));
        message
            .attributes
            .push(AddressAttribute::Address(address.into()));
        self.request(
            RouteNetlinkMessage::NewAddress(message),
            NLM_F_CREATE | NLM_F_EXCL,
        )
    }

    /// Route `destination/32`, or everything, through link `index` in
    /// `table`.
    pub fn add_route(
        &mut self,
        destination: Option<Ipv4Addr>,
        index: u32,
        table: u32,
    ) -> io::Result<()> {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet;
        // Tables above 255 are only in the attribute.
        message.header.table = u8::try_from(table).unwrap_or(0);
        message.header.protocol = RouteProtocol::Boot;
        message.header.scope = RouteScope::Link;
        message.header.kind = RouteType::Unicast;
        if let Some(destination) = destination {
            message.header.destination_prefix_length = 32;
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(destination)));
        }
        message.attributes.push(RouteAttribute::Oif(index));
        message.attributes.push(RouteAttribute::Table(table));
        self.request(
            RouteNetlinkMessage::NewRoute(message),
            NLM_F_CREATE | NLM_F_EXCL,
        )
    }

    pub fn add_rule(&mut self, rule: Rule) -> io::Result<()> {
        self.request(
            RouteNetlinkMessage::NewRule(rule_message(rule)),
            NLM_F_CREATE | NLM_F_EXCL,
        )
    }

    pub fn delete_rule(&mut self, rule: Rule) -> io::Result<()> {
        self.request(RouteNetlinkMessage::DelRule(rule_message(rule)), 0)
    }
}

/// What Linux announces of the links of the network namespace that it was
/// made in (`RTNLGRP_LINK`).
#[cfg(fast_path)]
pub(crate) struct LinkEvents {
    socket: Socket,
    buffer: Vec<u8>,
}

#[cfg(fast_path)]
impl LinkEvents {
    pub fn new() -> io::Result<Self> {
        let mut socket = socket()?;
        // The group of the links, RTMGRP_LINK.
        socket.bind(&SocketAddr::new(0, 1))?;
        Ok(Self {
            socket,
            buffer: Vec::with_capacity(65536),
        })
    }

    /// The links whose announcement the next datagram has, with their MTU,
    /// within [`ANSWER`]: `TimedOut` past it. `ENOBUFS` says that
    /// announcements were lost.
    pub fn next(&mut self) -> io::Result<Vec<(u32, u32)>> {
        receive(&self.socket, &mut self.buffer)?;
        Ok(link_mtus(&self.buffer))
    }
}

/// The index and the MTU of each link of the `RTM_NEWLINK` messages of
/// `datagram`.
#[cfg(fast_path)]
fn link_mtus(mut datagram: &[u8]) -> Vec<(u32, u32)> {
    let mut mtus = Vec::new();
    // Each message starts with its length, which a message that does not
    // parse still gives.
    while let Some(length) = datagram
        .first_chunk::<4>()
        .map(|length| u32::from_ne_bytes(*length))
    {
        let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(datagram);
        if let Ok(NetlinkMessage {
            payload: NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
            ..
        }) = message
            && let Some(mtu) = link
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::Mtu(mtu) => Some(*mtu),
                    _ => None,
                })
        {
            mtus.push((link.header.index, mtu));
        }
        // Messages are aligned to 4 octets.
        let length = (length as usize + 3) & !3;
        if length == 0 || length >= datagram.len() {
            break;
        }
        datagram = &datagram[length..];
    }
    mtus
}

fn rule_message(rule: Rule) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.src_len = 32;
    message.header.table = u8::try_from(rule.table).unwrap_or(0);
    message.header.action = RuleAction::ToTable;
    message
        .attributes
        .push(RuleAttribute::Priority(rule.priority));
    message
        .attributes
        .push(RuleAttribute::Source(rule.source.into()));
    message.attributes.push(RuleAttribute::Table(rule.table));
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The announcements of two links, one of which changed its MTU, and of
    /// an address, in one datagram.
    #[cfg(fast_path)]
    #[test]
    fn the_mtu_of_announced_links_is_read() {
        let message = |payload: RouteNetlinkMessage| {
            let mut message = NetlinkMessage::new(NetlinkHeader::default(), payload.into());
            message.finalize();
            let mut bytes = vec![0; message.buffer_len()];
            message.serialize(&mut bytes);
            bytes
        };
        let link = |index, mtu: Option<u32>| {
            let mut link = LinkMessage::default();
            link.header.index = index;
            link.attributes
                .push(LinkAttribute::IfName(format!("n3{index}")));
            link.attributes.extend(mtu.map(LinkAttribute::Mtu));
            RouteNetlinkMessage::NewLink(link)
        };
        let mut address = AddressMessage::default();
        address.header.index = 7;
        let datagram = [
            message(link(7, Some(1400))),
            message(RouteNetlinkMessage::NewAddress(address)),
            message(link(9, None)),
            message(link(1, Some(65536))),
        ]
        .concat();
        assert_eq!(link_mtus(&datagram), [(7, 1400), (1, 65536)]);
        assert_eq!(link_mtus(&datagram[..3]), []);
    }

    /// Linux announces the change of a link's MTU to the socket of the
    /// links' events, in the namespace that it was made in. In a network
    /// namespace of its own, as root or in a user namespace:
    /// `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="unshare --user
    /// --map-root-user --net --" cargo test --features ebpf --lib -- --ignored
    /// announced`.
    #[cfg(fast_path)]
    #[test]
    #[ignore = "needs CAP_NET_ADMIN"]
    fn the_change_of_an_mtu_is_announced() {
        // SAFETY: unshare only changes this thread's namespace.
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET) },
            0,
            "a network namespace of its own: {}",
            io::Error::last_os_error()
        );
        let mut events = LinkEvents::new().unwrap();
        let mut netlink = Netlink::new().unwrap();
        let lo = netlink.index_of("lo").unwrap();
        let status = std::process::Command::new("ip")
            .args(["link", "set", "lo", "mtu", "1400"])
            .status()
            .unwrap();
        assert!(status.success());
        let announced = loop {
            let changed = events.next().unwrap();
            if let Some(&(_, mtu)) = changed.iter().find(|(index, _)| *index == lo) {
                break mtu;
            }
        };
        assert_eq!(announced, 1400);
        assert_eq!(netlink.mtu_of(lo).unwrap(), 1400);
    }

    /// A request whose answer does not come returns an error, and does not
    /// hold its caller, a task of the runtime, for ever.
    #[test]
    fn waiting_for_an_answer_that_does_not_come_ends() {
        let (sender, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut netlink = Netlink::new().unwrap();
            let started = std::time::Instant::now();
            let error = netlink.receive(&mut Vec::with_capacity(4096)).unwrap_err();
            sender.send((error.kind(), started.elapsed())).unwrap();
        });
        let (kind, waited) = answer
            .recv_timeout(4 * ANSWER)
            .expect("still waiting for the kernel");
        assert_eq!(kind, io::ErrorKind::TimedOut);
        assert!(waited >= ANSWER / 2, "{waited:?}");
    }
}
