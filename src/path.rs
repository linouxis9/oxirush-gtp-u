//! What TS 29.281 requires of every GTP-U node, whatever its tunnels.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::{ECHO_REQUEST, ExtensionHeader, G_PDU, InformationElement, PORT, Packet};

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
    // TS 29.281 section 9.1 imports TS 29.060 section 11.1.10:
    // signalling IEs must be in ascending type order. The raw codec keeps
    // their received order for lossless re-encoding.
    if packet.message_type != G_PDU
        && packet.information_elements().is_ok_and(|elements| {
            elements
                .windows(2)
                .any(|pair| pair[0].kind() > pair[1].kind())
        })
    {
        warn!("GTP-U: dropped a message with out-of-sequence information elements from {from}");
        if packet.message_type == ECHO_REQUEST {
            // TS 29.060 section 11.1.10 requires an error response with
            // Cause 193 (Invalid message format). Retain the mandatory
            // Recovery IE of the Echo Response (TS 29.281 section 7.2.2).
            let response = echo_error_response(packet.sequence.unwrap_or(0));
            send(socket, &response, from).await;
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

/// A complete Echo Request with an inconsistent GTP length still receives
/// an error response (TS 29.281 section 9.1, TS 29.060 section 11.1.2).
/// Truncated headers and unsupported versions are silently discarded.
pub(crate) async fn answer_length_error(socket: &UdpSocket, bytes: &[u8], from: SocketAddr) {
    let Some(header) = bytes.first_chunk::<8>() else {
        return;
    };
    let flags = header[0];
    if flags & 0xf0 != 0x30 || header[1] != ECHO_REQUEST {
        return;
    }
    let header_length = if flags & 0x07 != 0 { 12 } else { 8 };
    if bytes.len() < header_length {
        return;
    }
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if length == bytes.len() - 8 {
        return;
    }
    let sequence = if flags & 0x02 != 0 {
        u16::from_be_bytes([bytes[8], bytes[9]])
    } else {
        0
    };
    send(socket, &echo_error_response(sequence), from).await;
}

fn echo_error_response(sequence: u16) -> Packet {
    let mut response = Packet::echo_response(sequence);
    response.payload = InformationElement::encode_all(&[
        InformationElement::OtherTv {
            kind: 1,
            value: vec![193],
        },
        InformationElement::Recovery(0),
    ])
    .expect("fixed-length Cause and Recovery IEs encode");
    response
}

/// Answer a G-PDU with TEID `teid`, which has no tunnel here, with an
/// Error Indication (TS 29.281 §7.3.1). It goes to port 2152 of the
/// sender (§4.4.2.4), so it carries the G-PDU's UDP source port.
pub(crate) async fn error_indication(socket: &UdpSocket, teid: u32, from: SocketAddr) {
    if teid == 0 {
        return;
    }
    let Ok(local) = socket
        .local_addr()
        .map(|address| address.ip().to_canonical())
    else {
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
fn user_plane_port(mut address: SocketAddr) -> SocketAddr {
    address.set_port(PORT);
    address
}

async fn send(socket: &UdpSocket, packet: &Packet, to: SocketAddr) {
    let Ok(bytes) = packet.encode() else {
        return;
    };
    if let Err(error) = socket.send_to(&bytes, to).await {
        debug!("GTP-U: reply to {to} failed: {error}");
    }
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
    match address.ip().to_canonical() {
        IpAddr::V4(ip) => SocketAddr::new(ip.into(), address.port()),
        IpAddr::V6(_) => address,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV6};

    #[test]
    fn path_reply_port_preserves_native_ipv6_metadata() {
        let address = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            49152,
            0x12345,
            7,
        ));
        let mut expected = address;
        expected.set_port(PORT);
        assert_eq!(user_plane_port(address), expected);
    }

    #[test]
    fn canonicalization_preserves_native_ipv6_and_converts_mapped_ipv4() {
        let address = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            2152,
            0x12345,
            7,
        ));
        assert_eq!(canonical(address), address);

        let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let native = SocketAddr::new(ipv4.into(), 2152);
        assert_eq!(canonical(native), native);
        let mapped = SocketAddr::V6(SocketAddrV6::new(ipv4.to_ipv6_mapped(), 2152, 0, 0));
        assert_eq!(canonical(mapped), native);
    }
}
