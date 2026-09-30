// Tests that need a second loopback address are left out on macOS.
#![cfg_attr(target_os = "macos", allow(unused_imports))]

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use oxirush_gtp_u::{
    ECHO_REQUEST, ECHO_RESPONSE, END_MARKER, ERROR_INDICATION, Endpoint, ExtensionHeader,
    InformationElement, Packet, PduSessionContainer, ReceivedPacket, RemoteTunnel,
    SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(100);

#[tokio::test]
async fn custom_packet_send_preserves_fields_and_source_socket() {
    let (endpoint, _, peer, _) = setup().await;
    let mut packet = Packet::g_pdu(44, vec![0x45]);
    packet.sequence = Some(123);
    packet.extension_headers.push(ExtensionHeader::UdpPort(42));
    endpoint
        .send_to(&packet, peer.local_addr().unwrap())
        .await
        .unwrap();
    let mut buffer = [0; 128];
    let (size, from) = timeout(WAIT, peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, endpoint.local_addr().unwrap());
    assert_eq!(Packet::decode(&buffer[..size]).unwrap(), packet);
}

#[tokio::test]
async fn explicit_local_teids_are_validated_and_replace_routes_atomically() {
    let (endpoint, mut received, peer, original) = setup().await;
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 44,
    };
    endpoint.install_with_teid(7, 1, 99, remote, None).unwrap();
    assert_ne!(original, 99);
    assert_eq!(endpoint.local_teid(7, 1), Some(99));
    assert_eq!(
        endpoint
            .install_with_teid(8, 1, 99, remote, None)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(endpoint.install_with_teid(7, 1, 0, remote, None).is_err());
    assert!(
        endpoint
            .install_with_teid(7, 1, 100, remote, Some(64))
            .is_err()
    );
    assert_eq!(endpoint.local_teid(7, 1), Some(99));
    send(&peer, &endpoint, &Packet::g_pdu(99, vec![1])).await;
    assert_eq!(delivered(&mut received).await.packet.teid, 99);
}

#[tokio::test]
async fn shutdown_is_shared_and_awaits_receiver_completion() {
    let (endpoint, mut received, peer, _) = setup().await;
    let clone = endpoint.clone();
    assert!(endpoint.is_running());
    endpoint.shutdown().await.unwrap();
    assert!(!clone.is_running());
    assert!(received.recv().await.is_none());
    clone.shutdown().await.unwrap();
    assert_eq!(
        clone
            .send_to(&Packet::echo_request(1), peer.local_addr().unwrap())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn counters_distinguish_malformed_closed_and_path_messages() {
    let (endpoint, received, peer, teid) = setup().await;
    drop(received);
    peer.send_to(&[0], endpoint.local_addr().unwrap())
        .await
        .unwrap();
    send(&peer, &endpoint, &Packet::g_pdu(teid, vec![1])).await;
    send(&peer, &endpoint, &Packet::echo_request(7)).await;
    assert_eq!(reply(&peer).await.sequence, Some(7));
    let stats = endpoint.stats();
    assert_eq!(stats.received_datagrams, 3);
    assert_eq!(stats.malformed_datagrams, 1);
    assert_eq!(stats.receiver_closed_drops, 1);
    assert_eq!(stats.path_messages, 1);
}

/// An endpoint and a peer socket, both on 127.0.0.1, with the tunnel of RAN
/// UE 7 and PDU session 1 between them. Returns the tunnel's local TEID.
async fn setup() -> (Endpoint, Receiver<ReceivedPacket>, UdpSocket, u32) {
    let (endpoint, received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 44,
    };
    let local_teid = endpoint.install(7, 1, remote, 9);
    (endpoint, received, peer, local_teid)
}

async fn send(from: &UdpSocket, endpoint: &Endpoint, packet: &Packet) {
    from.send_to(&packet.encode().unwrap(), endpoint.local_addr().unwrap())
        .await
        .unwrap();
}

async fn reply(socket: &UdpSocket) -> Packet {
    let mut buffer = [0; 2048];
    let (size, _) = timeout(WAIT, socket.recv_from(&mut buffer))
        .await
        .expect("no reply")
        .unwrap();
    Packet::decode(&buffer[..size]).unwrap()
}

/// A socket on port 2152 of 127.0.0.`host`, where Error Indications and
/// Supported Extension Headers Notifications go (TS 29.281 §4.4.2.4,
/// §4.4.2.5), and one on another port of that address to send from. Each
/// test takes its own address; macOS has no loopback address but 127.0.0.1.
#[cfg(not(target_os = "macos"))]
async fn user_plane_peer(host: u8) -> (UdpSocket, UdpSocket) {
    let address = Ipv4Addr::new(127, 0, 0, host);
    let listener = UdpSocket::bind((address, oxirush_gtp_u::PORT))
        .await
        .expect("port 2152 of the test address must be free");
    let sender = UdpSocket::bind((address, 0)).await.unwrap();
    (listener, sender)
}

async fn quiet(socket: &UdpSocket) -> bool {
    let mut buffer = [0; 2048];
    timeout(QUIET, socket.recv_from(&mut buffer)).await.is_err()
}

async fn delivered(received: &mut Receiver<ReceivedPacket>) -> ReceivedPacket {
    timeout(WAIT, received.recv())
        .await
        .expect("nothing delivered")
        .unwrap()
}

#[tokio::test]
async fn carries_g_pdus_both_ways() {
    let (endpoint, mut received, peer, local_teid) = setup().await;
    endpoint.send(7, 1, vec![0x45, 0]).await.unwrap();
    let uplink = reply(&peer).await;
    assert_eq!(
        (uplink.teid, uplink.payload.as_slice()),
        (44, [0x45, 0].as_slice())
    );
    assert_eq!(
        uplink.pdu_session_container(),
        Some(&PduSessionContainer::uplink(9))
    );
    send(
        &peer,
        &endpoint,
        &Packet::downlink(local_teid, 9, vec![0x45, 1]),
    )
    .await;
    let downlink = delivered(&mut received).await;
    assert_eq!((downlink.ran_id, downlink.session_id), (7, 1));
    assert_eq!(downlink.from, peer.local_addr().unwrap());
    assert_eq!(downlink.packet.qfi(), Some(9));
    assert_eq!(downlink.packet.payload, vec![0x45, 1]);
}

#[tokio::test]
async fn answers_echo_requests() {
    let (endpoint, _received, peer, _) = setup().await;
    send(&peer, &endpoint, &Packet::echo_request(77)).await;
    let response = reply(&peer).await;
    assert_eq!(response.message_type, ECHO_RESPONSE);
    assert_eq!((response.teid, response.sequence), (0, Some(77)));
    assert_eq!(
        response.information_elements().unwrap(),
        vec![InformationElement::Recovery(0)]
    );
    // Without a sequence number, the response still has one.
    send(&peer, &endpoint, &Packet::new(ECHO_REQUEST, 0, vec![])).await;
    assert_eq!(reply(&peer).await.sequence, Some(0));
}

#[tokio::test]
async fn rejects_wildcard_bind_addresses() {
    for address in ["0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"] {
        let error = Endpoint::bind(address.parse().unwrap()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn answers_out_of_sequence_echo_request_with_error_cause() {
    let (endpoint, _, peer, _) = setup().await;
    let mut request = Packet::echo_request(77);
    request.payload = InformationElement::encode_all(&[
        InformationElement::PrivateExtension {
            identifier: 1,
            value: vec![],
        },
        InformationElement::Recovery(0),
    ])
    .unwrap();
    send(&peer, &endpoint, &request).await;
    let response = reply(&peer).await;
    assert_eq!(
        (response.message_type, response.sequence),
        (ECHO_RESPONSE, Some(77))
    );
    assert_eq!(
        response.information_elements().unwrap(),
        vec![
            InformationElement::OtherTv {
                kind: 1,
                value: vec![193]
            },
            InformationElement::Recovery(0),
        ]
    );
    let wire = response.encode().unwrap();
    assert_eq!(Packet::decode(&wire).unwrap().encode().unwrap(), wire);
}

#[tokio::test]
async fn answers_echo_request_length_errors_with_error_cause() {
    let (endpoint, _, peer, _) = setup().await;
    // All E/S/PN combinations and both values of the ignored spare bit.
    for flags in 0u8..16 {
        let mut request = Packet::echo_request(77);
        request.payload = vec![255, 0, 2, 0, 1]; // Private Extension.
        let mut wire = request.encode().unwrap();
        wire[0] = 0x30 | flags;
        if flags & 7 == 0 {
            wire.drain(8..12);
        }
        let actual_length = (wire.len() - 8) as u16;
        for length in [actual_length - 1, actual_length + 1] {
            wire[2..4].copy_from_slice(&length.to_be_bytes());
            peer.send_to(&wire, endpoint.local_addr().unwrap())
                .await
                .unwrap();
            // TS 29.060 section 11.1.2, imported by TS 29.281 section 9.1.
            let response = reply(&peer).await;
            assert_eq!(response.sequence, Some(if flags & 2 != 0 { 77 } else { 0 }));
            assert_eq!(
                response.information_elements().unwrap(),
                vec![
                    InformationElement::OtherTv {
                        kind: 1,
                        value: vec![193]
                    },
                    InformationElement::Recovery(0),
                ]
            );
        }
    }
    let mut unsupported = Packet::echo_request(77).encode().unwrap();
    unsupported[0] = 0x52;
    unsupported[2..4].copy_from_slice(&0u16.to_be_bytes());
    let truncated = &unsupported[..7];
    for wire in [truncated, &unsupported, &[0x32, 1, 0, 0, 0, 0, 0, 0][..]] {
        peer.send_to(wire, endpoint.local_addr().unwrap())
            .await
            .unwrap();
        assert!(quiet(&peer).await);
    }
}

#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn specific_echo_response_uses_the_request_destination() {
    let (endpoint, _) = Endpoint::bind("127.0.0.2:0".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = std::net::SocketAddr::new(
        Ipv4Addr::new(127, 0, 0, 2).into(),
        endpoint.local_addr().unwrap().port(),
    );
    peer.send_to(&Packet::echo_request(1).encode().unwrap(), destination)
        .await
        .unwrap();
    let mut buffer = [0; 100];
    let (_, from) = timeout(WAIT, peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    // TS 29.281 section 4.4.3.2 requires copying the destination address.
    assert_eq!(from, destination);
}

#[tokio::test]
async fn keeps_answering_echo_while_the_receiver_lags() {
    let (endpoint, _unread, peer, local_teid) = setup().await;
    // More than the receiver's queue of 256.
    let downlink = Packet::downlink(local_teid, 9, vec![0x45; 32]);
    for _ in 0..400 {
        send(&peer, &endpoint, &downlink).await;
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(QUIET).await;
    send(&peer, &endpoint, &Packet::echo_request(1)).await;
    let response = reply(&peer).await;
    assert_eq!(
        (response.message_type, response.sequence),
        (ECHO_RESPONSE, Some(1))
    );
    assert!(endpoint.stats().queue_full_drops > 0);
}

#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn sends_error_indication_for_an_unknown_teid() {
    let (endpoint, mut received, _peer, _) = setup().await;
    let (listener, sender) = user_plane_peer(21).await;
    send(&sender, &endpoint, &Packet::downlink(999, 9, vec![0x45])).await;
    // To port 2152, with the G-PDU's source port in the UDP Port header.
    let indication = reply(&listener).await;
    assert_eq!(indication.message_type, ERROR_INDICATION);
    assert_eq!((indication.teid, indication.sequence), (0, Some(0)));
    assert_eq!(
        indication.extension_headers,
        vec![ExtensionHeader::UdpPort(
            sender.local_addr().unwrap().port()
        )]
    );
    assert_eq!(
        indication.information_elements().unwrap(),
        vec![
            InformationElement::TeidDataI(999),
            InformationElement::GtpUPeerAddress(Ipv4Addr::LOCALHOST.into()),
        ]
    );
    assert!(quiet(&sender).await);
    // Not for TEID 0.
    send(&sender, &endpoint, &Packet::g_pdu(0, vec![0x45])).await;
    assert!(quiet(&listener).await);
    assert!(received.try_recv().is_err());
}

/// The Error Indication names the actual destination address.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn error_indication_names_the_specific_socket_s_address() {
    let (endpoint, _received) = Endpoint::bind("127.0.0.2:0".parse().unwrap())
        .await
        .unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let (listener, sender) = user_plane_peer(22).await;
    let to = (Ipv4Addr::new(127, 0, 0, 2), port);
    sender
        .send_to(&Packet::g_pdu(5, vec![]).encode().unwrap(), to)
        .await
        .unwrap();
    assert!(
        reply(&listener)
            .await
            .information_elements()
            .unwrap()
            .contains(&InformationElement::GtpUPeerAddress(
                Ipv4Addr::new(127, 0, 0, 2).into()
            ))
    );
}

#[tokio::test]
async fn delivers_the_peer_s_error_indication_to_its_tunnel() {
    let (endpoint, mut received, peer, _) = setup().await;
    let peer_ip = peer.local_addr().unwrap().ip();
    send(&peer, &endpoint, &Packet::error_indication(44, peer_ip)).await;
    let indication = delivered(&mut received).await;
    assert_eq!((indication.ran_id, indication.session_id), (7, 1));
    assert_eq!(indication.packet.message_type, ERROR_INDICATION);
    // One naming another tunnel is not delivered.
    send(&peer, &endpoint, &Packet::error_indication(45, peer_ip)).await;
    assert!(timeout(QUIET, received.recv()).await.is_err());
}

#[tokio::test]
async fn discards_error_indication_with_out_of_sequence_ies() {
    let (endpoint, mut received, peer, _) = setup().await;
    let mut indication = Packet::error_indication(44, peer.local_addr().unwrap().ip());
    let mut elements = indication.information_elements().unwrap();
    elements.reverse();
    indication.payload = InformationElement::encode_all(&elements).unwrap();
    send(&peer, &endpoint, &indication).await;
    // TS 29.281 section 9.1 imports TS 29.060 section 11.1.10.
    assert!(timeout(QUIET, received.recv()).await.is_err());
}

#[tokio::test]
async fn skips_known_unexpected_tv_ie_in_error_indication() {
    let (endpoint, mut received, peer, _) = setup().await;
    let mut indication = Packet::error_indication(44, peer.local_addr().unwrap().ip());
    // Cause (type 1, one value octet) is known in TS 29.060 section 7.7.1
    // but unexpected here. Section 11.1.11 requires skipping it.
    indication.payload.splice(0..0, [1, 128]);
    send(&peer, &endpoint, &indication).await;
    let received = delivered(&mut received).await;
    assert_eq!((received.ran_id, received.session_id), (7, 1));
}

#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn rejects_an_unsupported_required_extension_header() {
    let (endpoint, mut received, _peer, local_teid) = setup().await;
    let (listener, sender) = user_plane_peer(23).await;
    let unsupported = ExtensionHeader::Other {
        kind: 0xc5,
        content: vec![0, 0],
    };
    // A G-PDU or a request gets a notification at port 2152 and is dropped.
    let mut packet = Packet::downlink(local_teid, 9, vec![0x45]);
    packet.extension_headers.push(unsupported.clone());
    let mut request = Packet::echo_request(1);
    request.extension_headers.push(unsupported.clone());
    for message in [&packet, &request] {
        send(&sender, &endpoint, message).await;
        let notification = reply(&listener).await;
        assert_eq!(
            notification.message_type,
            SUPPORTED_EXTENSION_HEADERS_NOTIFICATION
        );
        assert_eq!(
            notification.information_elements().unwrap(),
            vec![InformationElement::ExtensionHeaderTypeList(vec![
                0x40, 0x85
            ])]
        );
        assert!(quiet(&sender).await);
    }
    assert!(timeout(QUIET, received.recv()).await.is_err());
    // Other messages are only dropped (TS 29.281 §5.2.1).
    let mut marker = Packet::end_marker(local_teid);
    marker.extension_headers.push(unsupported.clone());
    let mut response = Packet::echo_response(1);
    response.extension_headers.push(unsupported);
    for message in [&marker, &response] {
        send(&sender, &endpoint, message).await;
    }
    assert!(quiet(&listener).await);
    assert!(timeout(QUIET, received.recv()).await.is_err());
    // A header that needs no comprehension is ignored.
    packet.extension_headers[1] = ExtensionHeader::Other {
        kind: 0x45,
        content: vec![0, 0],
    };
    send(&sender, &endpoint, &packet).await;
    assert_eq!(delivered(&mut received).await.packet, packet);
}

/// The TEID alone identifies the tunnel: free5GC's UPF, for one, sends
/// downlink from another address than its N3 F-TEID's.
// macOS has no loopback address but 127.0.0.1 by default.
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn accepts_g_pdus_from_another_address_of_the_peer() {
    let (endpoint, mut received, _peer, local_teid) = setup().await;
    let other_address = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let downlink = Packet::downlink(local_teid, 9, vec![0x45]);
    send(&other_address, &endpoint, &downlink).await;
    assert_eq!(delivered(&mut received).await.packet, downlink);
}

#[tokio::test]
async fn delivers_end_markers() {
    let (endpoint, mut received, peer, local_teid) = setup().await;
    send(&peer, &endpoint, &Packet::end_marker(local_teid)).await;
    let marker = delivered(&mut received).await;
    assert_eq!((marker.ran_id, marker.packet.message_type), (7, END_MARKER));
    // An End Marker for an unknown tunnel gets no Error Indication.
    send(&peer, &endpoint, &Packet::end_marker(999)).await;
    assert!(quiet(&peer).await);
}

#[tokio::test]
async fn s1u_tunnels_send_plain_g_pdus() {
    let (endpoint, mut received, peer, _) = setup().await;
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 60,
    };
    let local_teid = endpoint.install_s1u(9, 5, remote);
    assert_eq!(endpoint.local_teid(9, 5), Some(local_teid));
    endpoint.send(9, 5, vec![0x45]).await.unwrap();
    let uplink = reply(&peer).await;
    assert_eq!((uplink.teid, uplink.payload.as_slice()), (60, &[0x45][..]));
    assert!(uplink.extension_headers.is_empty());
    // Downlink G-PDUs reach the E-RAB's tunnel.
    send(&peer, &endpoint, &Packet::g_pdu(local_teid, vec![0x46])).await;
    let packet = timeout(WAIT, received.recv()).await.unwrap().unwrap();
    assert_eq!((packet.ran_id, packet.session_id), (9, 5));
    assert_eq!(packet.packet.payload, vec![0x46]);
}

#[tokio::test]
async fn install_and_remove_tunnels() {
    let (endpoint, _received, _peer, local_teid) = setup().await;
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let moved = RemoteTunnel {
        address: other.local_addr().unwrap(),
        teid: 50,
    };
    // Reinstalling keeps the TEID and moves the uplink.
    assert_eq!(endpoint.install(7, 1, moved, 5), local_teid);
    endpoint.send(7, 1, vec![0x45]).await.unwrap();
    let uplink = reply(&other).await;
    assert_eq!((uplink.teid, uplink.qfi()), (50, Some(5)));

    let second = endpoint.install(7, 2, moved, 5);
    let third = endpoint.install(8, 1, moved, 5);
    assert_eq!(
        [local_teid, second, third].len(),
        std::collections::HashSet::from([local_teid, second, third]).len()
    );
    endpoint.remove_ran(7);
    assert_eq!(endpoint.local_teid(7, 1), None);
    assert_eq!(endpoint.local_teid(7, 2), None);
    assert_eq!(endpoint.local_teid(8, 1), Some(third));
    let error = endpoint.send(7, 1, vec![]).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    // The removed tunnel's G-PDUs get an Error Indication.
    #[cfg(not(target_os = "macos"))]
    {
        let (listener, sender) = user_plane_peer(25).await;
        send(&sender, &endpoint, &Packet::g_pdu(local_teid, vec![0x45])).await;
        assert_eq!(reply(&listener).await.message_type, ERROR_INDICATION);
    }
    endpoint.remove(8, 1);
    assert_eq!(endpoint.local_teid(8, 1), None);
}

#[tokio::test]
async fn works_over_ipv6() {
    let (endpoint, mut received) = Endpoint::bind("[::1]:0".parse().unwrap()).await.unwrap();
    let peer = UdpSocket::bind("[::1]:0").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 45,
    };
    let local_teid = endpoint.install(3, 2, remote, 1);
    endpoint.send(3, 2, vec![0x60, 0]).await.unwrap();
    assert_eq!(reply(&peer).await.teid, 45);
    send(
        &peer,
        &endpoint,
        &Packet::downlink(local_teid, 1, vec![0x60, 1]),
    )
    .await;
    assert_eq!(delivered(&mut received).await.packet.payload, vec![0x60, 1]);
}

/// A socket on an IPv4-mapped IPv6 address serves IPv4 peers, which it sees as IPv4-mapped
/// addresses (Linux sockets are dual-stack by default).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn ipv4_mapped_socket_serves_ipv4_peers() {
    let (endpoint, mut received) = Endpoint::bind("[::ffff:127.0.0.1]:0".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 46,
    };
    let local_teid = endpoint.install(4, 1, remote, 2);
    endpoint.send(4, 1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&peer).await.teid, 46);
    let port = endpoint.local_addr().unwrap().port();
    let downlink = Packet::downlink(local_teid, 2, vec![0x45, 2]);
    peer.send_to(&downlink.encode().unwrap(), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let packet = delivered(&mut received).await;
    assert_eq!(packet.packet, downlink);
    // Reported as IPv4, not IPv4-mapped.
    assert_eq!(packet.from, peer.local_addr().unwrap());
    // Its Error Indication names the IPv4 address.
    let (listener, sender) = user_plane_peer(24).await;
    sender
        .send_to(
            &Packet::g_pdu(999, vec![]).encode().unwrap(),
            (Ipv4Addr::LOCALHOST, port),
        )
        .await
        .unwrap();
    assert!(
        reply(&listener)
            .await
            .information_elements()
            .unwrap()
            .contains(&InformationElement::GtpUPeerAddress(
                Ipv4Addr::LOCALHOST.into()
            ))
    );
}

#[tokio::test]
async fn keeps_working_without_a_receiver() {
    let (endpoint, received, peer, local_teid) = setup().await;
    drop(received);
    send(
        &peer,
        &endpoint,
        &Packet::downlink(local_teid, 9, vec![0x45]),
    )
    .await;
    send(&peer, &endpoint, &Packet::echo_request(3)).await;
    assert_eq!(reply(&peer).await.sequence, Some(3));
    endpoint.send(7, 1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&peer).await.teid, 44);
}

#[tokio::test]
async fn releases_the_socket_when_dropped() {
    let (endpoint, received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = endpoint.local_addr().unwrap();
    let clone = endpoint.clone();
    drop(endpoint);
    // A clone keeps it open.
    assert!(UdpSocket::bind(address).await.is_err());
    drop((clone, received));
    tokio::task::yield_now().await; // let the aborted task release its socket
    Endpoint::bind(address).await.unwrap();
}
