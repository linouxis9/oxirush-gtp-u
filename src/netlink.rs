//! The rtnetlink requests of the TUN module. Each waits for the kernel's
//! acknowledgement, which comes at once.

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;

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

/// A NETLINK_ROUTE socket.
pub(crate) struct Netlink {
    socket: Socket,
    sequence: u32,
}

impl Netlink {
    pub fn new() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    /// Send `message` and wait for the kernel's acknowledgement.
    fn request(&mut self, message: RouteNetlinkMessage, flags: u16) -> io::Result<()> {
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
        loop {
            buffer.clear();
            self.socket.recv(&mut buffer, 0)?;
            let mut datagram = buffer.as_slice();
            while !datagram.is_empty() {
                let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(datagram)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                if reply.header.sequence_number == self.sequence {
                    if let NetlinkPayload::Error(error) = reply.payload {
                        return match error.code {
                            None => Ok(()),
                            Some(_) => Err(error.to_io()),
                        };
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
        index_of(name)
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

/// The name of the network interface with index `index`, if any.
pub(crate) fn name_of(index: u32) -> Option<String> {
    let mut name = [0; libc::IF_NAMESIZE];
    // SAFETY: the buffer has the IF_NAMESIZE bytes if_indextoname writes to.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return None;
    }
    // SAFETY: on success, the buffer holds a NUL-terminated name.
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

/// The index of network interface `name`.
pub(crate) fn index_of(name: &str) -> io::Result<u32> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}
