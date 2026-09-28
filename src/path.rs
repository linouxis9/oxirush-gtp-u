//! What TS 29.281 requires of every GTP-U node, whatever its tunnels.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::{ECHO_REQUEST, ExtensionHeader, G_PDU, PORT, Packet};

/// The extension header types the endpoint and the test UPF understand.
const SUPPORTED_EXTENSION_HEADERS: [u8; 2] = [
    ExtensionHeader::UDP_PORT,
    ExtensionHeader::PDU_SESSION_CONTAINER,
];

/// Answer an Echo Request, and discard a message with an extension header
/// that the receiver must understand but does not, answering a request or
/// G-PDU with a Supported Extension Headers Notification (TS 29.281
/// §5.2.1). Returns whether `packet` needs nothing else.
pub(crate) async fn answer(socket: &UdpSocket, packet: &Packet, from: SocketAddr) -> bool {
    let unsupported = packet.extension_headers.iter().any(|header| {
        matches!(header, ExtensionHeader::Other { .. }) && header.comprehension_required()
    });
    if unsupported {
        warn!("GTP-U: dropped a message with an unsupported extension header from {from}");
        if matches!(packet.message_type, ECHO_REQUEST | G_PDU) {
            let notification =
                Packet::supported_extension_headers_notification(&SUPPORTED_EXTENSION_HEADERS);
            send(socket, &notification, user_plane_port(from)).await;
        }
        return true;
    }
    if packet.message_type == ECHO_REQUEST {
        let response = Packet::echo_response(packet.sequence.unwrap_or(0));
        send(socket, &response, from).await;
        return true;
    }
    false
}

/// Answer a G-PDU with TEID `teid`, which has no tunnel here, with an
/// Error Indication (TS 29.281 §7.3.1). It goes to port 2152 of the
/// sender (§4.4.2.4), so it carries the G-PDU's UDP source port.
pub(crate) async fn error_indication(socket: &UdpSocket, teid: u32, from: SocketAddr) {
    if teid == 0 {
        return;
    }
    let Some(local) = local_ip(socket, from) else {
        debug!("GTP-U: no local address toward {from} for an Error Indication");
        return;
    };
    let mut indication = Packet::error_indication(teid, local);
    indication
        .extension_headers
        .push(ExtensionHeader::UdpPort(from.port()));
    send(socket, &indication, user_plane_port(from)).await;
}

/// Port 2152 of `address`, where Error Indication and Supported Extension
/// Headers Notification go whatever the source port of what triggered them
/// (TS 29.281 §4.4.2.4, §4.4.2.5).
fn user_plane_port(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip(), PORT)
}

async fn send(socket: &UdpSocket, packet: &Packet, to: SocketAddr) {
    let Ok(bytes) = packet.encode() else {
        return;
    };
    if let Err(error) = socket.send_to(&bytes, to).await {
        debug!("GTP-U: reply to {to} failed: {error}");
    }
}

/// The address a G-PDU from `peer` reached: the socket's, or for a
/// wildcard socket, the source address of the route back to the peer.
fn local_ip(socket: &UdpSocket, peer: SocketAddr) -> Option<IpAddr> {
    let local = socket.local_addr().ok()?.ip().to_canonical();
    if !local.is_unspecified() {
        return Some(local);
    }
    let peer = peer.ip().to_canonical();
    let unspecified = match peer {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let probe = std::net::UdpSocket::bind((unspecified, 0)).ok()?;
    probe.connect((peer, crate::PORT)).ok()?;
    Some(probe.local_addr().ok()?.ip())
}

/// `address` in the family of a socket: IPv4-mapped for an IPv6 socket,
/// which is how a dual-stack socket reaches IPv4 peers.
pub(crate) fn destination(ipv6_socket: bool, address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(ip) if ipv6_socket => {
            SocketAddr::new(ip.to_ipv6_mapped().into(), address.port())
        }
        _ => address,
    }
}

/// `address` with an IPv4-mapped IPv6 address, as a dual-stack socket
/// reports IPv4 peers, turned into the IPv4 address.
pub(crate) fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Whether two addresses are the same host, IPv4-mapped or not.
pub(crate) fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    a.to_canonical() == b.to_canonical()
}

/// Whether a receive error concerns an earlier datagram, as ICMP errors
/// reported on unconnected sockets by some systems, rather than the socket.
pub(crate) fn transient(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionRefused, ConnectionReset, Interrupted};
    matches!(
        error.kind(),
        ConnectionRefused | ConnectionReset | Interrupted
    )
}

/// Lock a mutex whose data stays consistent even if a holder panicked.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
