// Tests that need a second loopback address are left out on macOS.
#![cfg_attr(target_os = "macos", allow(unused_imports))]

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{
    ECHO_RESPONSE, END_MARKER, ERROR_INDICATION, EchoKind, Endpoint, InformationElement, Packet,
    PduSessionContainer, RemoteTunnel, ipv4_icmp_echo_request, ipv4_udp, parse_ipv4_icmp_echo,
    parse_ipv4_udp,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);

fn udp(payload: &[u8]) -> Vec<u8> {
    ipv4_udp(
        SocketAddrV4::new(Ipv4Addr::new(10, 60, 0, 2), 1234),
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40900),
        payload,
    )
    .unwrap()
}

async fn next<T>(receiver: &mut tokio::sync::mpsc::Receiver<T>) -> T {
    timeout(WAIT, receiver.recv()).await.unwrap().unwrap()
}

async fn reply(socket: &UdpSocket) -> Packet {
    let mut buffer = [0; 2048];
    let (size, _) = timeout(WAIT, socket.recv_from(&mut buffer))
        .await
        .expect("no reply")
        .unwrap();
    Packet::decode(&buffer[..size]).unwrap()
}

#[tokio::test]
async fn n3_packets_follow_the_target_after_a_path_switch() {
    let (upf, mut upf_rx) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (source, mut source_rx) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (target, mut target_rx) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let remote = RemoteTunnel {
        address: upf.local_addr().unwrap(),
        teid: 0x1234_5678,
    };
    let source_teid = source.install(1, 1, remote, 9);
    upf.set_session(Session::new(
        remote.teid,
        source_teid,
        source.local_addr().unwrap(),
        9,
    ));
    source.send(1, 1, udp(b"before handover")).await.unwrap();
    assert_eq!(next(&mut upf_rx).await.uplink_teid, remote.teid);
    let before = next(&mut source_rx).await;
    assert_eq!(
        parse_ipv4_udp(&before.packet.payload).unwrap().2,
        b"before handover"
    );
    assert_eq!(
        before.packet.pdu_session_container(),
        Some(&PduSessionContainer::downlink(9))
    );

    let target_teid = target.install(2, 1, remote, 9);
    upf.switch_downlink(remote.teid, target.local_addr().unwrap(), target_teid)
        .await
        .unwrap();
    // The old path ends with an End Marker.
    let marker = next(&mut source_rx).await;
    assert_eq!(
        (
            marker.ran_id,
            marker.packet.message_type,
            marker.packet.teid
        ),
        (1, END_MARKER, source_teid)
    );
    source.remove(1, 1);
    target.send(2, 1, udp(b"after handover")).await.unwrap();
    assert_eq!(next(&mut upf_rx).await.from, target.local_addr().unwrap());
    let after = next(&mut target_rx).await;
    assert_eq!(
        parse_ipv4_udp(&after.packet.payload).unwrap().2,
        b"after handover"
    );
    assert!(
        timeout(Duration::from_millis(50), source_rx.recv())
            .await
            .is_err()
    );
    // Switching to the same path sends no End Marker, even written as an
    // IPv4-mapped address.
    let target_address = target.local_addr().unwrap();
    let mapped = match target_address.ip() {
        std::net::IpAddr::V4(ip) => {
            std::net::SocketAddr::new(ip.to_ipv6_mapped().into(), target_address.port())
        }
        std::net::IpAddr::V6(_) => target_address,
    };
    for address in [target_address, mapped] {
        upf.switch_downlink(remote.teid, address, target_teid)
            .await
            .unwrap();
    }
    assert!(
        timeout(Duration::from_millis(50), target_rx.recv())
            .await
            .is_err()
    );
}

/// The UPF's Error Indication reaches a gNB endpoint on port 2152, here
/// 127.0.0.27 (macOS has no loopback address but 127.0.0.1).
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn error_indication_from_the_upf_reaches_the_tunnel() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.27:2152".parse().unwrap())
        .await
        .unwrap();
    let remote = RemoteTunnel {
        address: upf.local_addr().unwrap(),
        teid: 0x3030,
    };
    let downlink_teid = gnb.install(4, 2, remote, 9);
    upf.set_session(Session::new(
        remote.teid,
        downlink_teid,
        gnb.local_addr().unwrap(),
        9,
    ));
    upf.remove_session(remote.teid);
    gnb.send(4, 2, udp(b"to a session the UPF lost"))
        .await
        .unwrap();
    let indication = next(&mut received).await;
    assert_eq!((indication.ran_id, indication.session_id), (4, 2));
    assert_eq!(indication.packet.message_type, ERROR_INDICATION);
    assert_eq!(indication.from.ip(), remote.address.ip());
}

#[tokio::test]
async fn built_in_n6_reflects_icmp_echo() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let remote = RemoteTunnel {
        address: upf.local_addr().unwrap(),
        teid: 0x1020,
    };
    let downlink_teid = gnb.install(1, 1, remote, 9);
    upf.set_session(Session::new(
        remote.teid,
        downlink_teid,
        gnb.local_addr().unwrap(),
        9,
    ));
    let request = ipv4_icmp_echo_request(
        Ipv4Addr::new(10, 60, 0, 2),
        Ipv4Addr::new(192, 0, 2, 1),
        0x1234,
        4,
        b"echo",
    )
    .unwrap();
    gnb.send(1, 1, request).await.unwrap();
    let reply = next(&mut received).await;
    let echo = parse_ipv4_icmp_echo(&reply.packet.payload).unwrap();
    assert_eq!(echo.kind, EchoKind::Reply);
    assert_eq!((echo.identifier, echo.sequence), (0x1234, 4));
    assert_eq!(echo.payload, b"echo");
}

#[tokio::test]
async fn answers_echo_requests() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gnb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    gnb.send_to(
        &Packet::echo_request(9).encode().unwrap(),
        upf.local_addr().unwrap(),
    )
    .await
    .unwrap();
    let response = reply(&gnb).await;
    assert_eq!(
        (response.message_type, response.sequence),
        (ECHO_RESPONSE, Some(9))
    );
}

/// The Error Indication goes to port 2152 of the gNB, here 127.0.0.26
/// (macOS has no loopback address but 127.0.0.1).
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn sends_error_indication_for_an_unknown_uplink_teid() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gnb_listener = UdpSocket::bind("127.0.0.26:2152").await.unwrap();
    let gnb = UdpSocket::bind("127.0.0.26:0").await.unwrap();
    gnb.send_to(
        &Packet::uplink(77, 9, vec![0x45]).encode().unwrap(),
        upf.local_addr().unwrap(),
    )
    .await
    .unwrap();
    let indication = reply(&gnb_listener).await;
    assert_eq!(indication.message_type, ERROR_INDICATION);
    assert_eq!(
        indication.information_elements().unwrap(),
        vec![
            InformationElement::TeidDataI(77),
            InformationElement::GtpUPeerAddress(Ipv4Addr::LOCALHOST.into()),
        ]
    );
}

#[tokio::test]
async fn sends_downlink_packets_and_rejects_unknown_sessions() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gnb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upf.set_session(Session::new(10, 20, gnb.local_addr().unwrap(), 5));
    upf.send_downlink(10, vec![0x60, 0]).await.unwrap();
    let downlink = reply(&gnb).await;
    assert_eq!((downlink.teid, downlink.qfi()), (20, Some(5)));
    assert_eq!(downlink.payload, vec![0x60, 0]);

    let missing = upf.send_downlink(11, vec![]).await.unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    let missing = upf
        .switch_downlink(11, gnb.local_addr().unwrap(), 1)
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    upf.remove_session(10);
    assert_eq!(
        upf.send_downlink(10, vec![]).await.unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

// macOS has no loopback address but 127.0.0.1 by default.
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn accepts_uplink_from_another_address_of_the_gnb() {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gnb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other_address = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    upf.set_session(Session::new(10, 20, gnb.local_addr().unwrap(), 5));
    other_address
        .send_to(
            &Packet::uplink(10, 5, udp(b"x")).encode().unwrap(),
            upf.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let uplink = next(&mut observed).await;
    assert_eq!(
        (uplink.uplink_teid, uplink.from),
        (10, other_address.local_addr().unwrap())
    );
    // The echo reply still goes to the session's gNB address.
    assert_eq!(reply(&gnb).await.teid, 20);
}
