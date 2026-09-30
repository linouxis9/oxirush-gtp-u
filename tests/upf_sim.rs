// Tests that need a second loopback address are left out on macOS.
#![cfg_attr(target_os = "macos", allow(unused_imports))]

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{
    ECHO_RESPONSE, END_MARKER, ERROR_INDICATION, EchoKind, Endpoint, InformationElement, Packet,
    PduSessionContainer, RemoteTunnel, ipv4_icmp_echo_request, ipv4_udp, parse_ipv4_icmp_echo,
    parse_ipv4_udp,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test]
async fn rejects_wildcard_bind_addresses() {
    for address in ["0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"] {
        let error = UpfSimulator::bind(address.parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

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

#[tokio::test]
async fn retrying_a_cancelled_switch_sends_the_pending_end_marker() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upf.set_session(Session::new(1, 2, source.local_addr().unwrap(), 9));
    let mut handover = Box::pin(upf.switch_downlink(1, target.local_addr().unwrap(), 3));
    let mut context = Context::from_waker(Waker::noop());
    // The fresh socket has not observed UDP write readiness yet. Cancelling
    // here exercises the gap between committing the route and sending its marker.
    assert!(matches!(
        handover.as_mut().poll(&mut context),
        Poll::Pending
    ));
    drop(handover);
    assert_eq!(upf.session(1).unwrap().downlink_teid, 3);
    assert_eq!(
        upf.pending_end_marker(1),
        Some(RemoteTunnel {
            address: source.local_addr().unwrap(),
            teid: 2,
        })
    );

    upf.send_downlink(1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&target).await.teid, 3);
    upf.switch_downlink(1, target.local_addr().unwrap(), 3)
        .await
        .unwrap();
    let marker = reply(&source).await;
    assert_eq!((marker.message_type, marker.teid), (END_MARKER, 2));
    assert_eq!(upf.pending_end_marker(1), None);
    upf.switch_downlink(1, target.local_addr().unwrap(), 3)
        .await
        .unwrap();
    let mut buffer = [0; 128];
    assert!(
        timeout(Duration::from_millis(50), source.recv_from(&mut buffer))
            .await
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_end_marker_is_retained_without_rolling_back_the_new_path() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upf.set_session(Session::new(1, 2, "[2001:db8::1]:2152".parse().unwrap(), 9));
    let first = upf
        .switch_downlink(1, target.local_addr().unwrap(), 3)
        .await
        .unwrap_err();
    upf.send_downlink(1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&target).await.teid, 3);
    // Success must not conceal that the previous marker was never sent.
    let retry = upf
        .switch_downlink(1, target.local_addr().unwrap(), 3)
        .await
        .unwrap_err();
    assert_eq!(retry.raw_os_error(), first.raw_os_error());
    assert_eq!(upf.session(1).unwrap().downlink_teid, 3);
    assert_eq!(upf.pending_end_marker(1).unwrap().teid, 2);
    // A third path cannot accumulate another pending marker or change the
    // committed route until the existing send succeeds.
    assert!(
        upf.switch_downlink(1, target.local_addr().unwrap(), 4)
            .await
            .is_err()
    );
    assert_eq!(upf.session(1).unwrap().downlink_teid, 3);
    upf.remove_session(1);
    assert_eq!(upf.pending_end_marker(1), None);
}

#[tokio::test]
async fn invalid_session_qfi_is_rejected_before_replacing_the_live_session() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut session = Session::new(1, 2, target.local_addr().unwrap(), 9);
    upf.set_session(session);
    session.qfi = 64;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            upf.set_session(session);
        }))
        .is_err()
    );
    upf.send_downlink(1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&target).await.qfi(), Some(9));
}

#[tokio::test]
async fn observer_drops_are_counted_without_delaying_path_management() {
    let (upf, observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upf.set_session(Session::new(1, 2, peer.local_addr().unwrap(), 9));
    let address = upf.local_addr().unwrap();
    let pdu = Packet::uplink(1, 9, vec![0x45]).encode().unwrap();
    // Pace each datagram until it is queued/dropped, so this tests the
    // library's bounded observer queue rather than the kernel UDP buffer.
    for total in 1..=257 {
        peer.send_to(&pdu, address).await.unwrap();
        timeout(WAIT, async {
            while upf.stats().received_datagrams < total {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    peer.send_to(&Packet::echo_request(7).encode().unwrap(), address)
        .await
        .unwrap();
    assert_eq!(reply(&peer).await.sequence, Some(7));
    peer.send_to(&[0], address).await.unwrap();
    timeout(WAIT, async {
        while upf.stats().malformed_datagrams == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(observed);
    peer.send_to(&pdu, address).await.unwrap();
    timeout(WAIT, async {
        while upf.stats().receiver_closed_drops == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let stats = upf.stats();
    assert_eq!(stats.received_datagrams, 260);
    assert_eq!(stats.queue_full_drops, 1);
    assert_eq!(stats.receiver_closed_drops, 1);
    assert_eq!(stats.malformed_datagrams, 1);
    assert_eq!(stats.path_messages, 1);
    upf.shutdown().await.unwrap();
    assert_eq!(upf.stats(), stats);
}

#[tokio::test]
async fn cancelled_shutdown_can_be_awaited_again_and_stops_all_clones() {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let other = upf.clone();
    let address = upf.local_addr().unwrap();
    upf.set_session(Session::new(1, 2, address, 9));
    assert!(upf.is_running());
    let mut shutdown = Box::pin(upf.shutdown());
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        shutdown.as_mut().poll(&mut context),
        Poll::Pending
    ));
    drop(shutdown);
    assert!(!other.is_running());
    other.shutdown().await.unwrap();
    assert_eq!(timeout(WAIT, observed.recv()).await.unwrap(), None);
    assert_eq!(
        other.send_downlink(1, vec![]).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        other
            .switch_downlink(1, address, 3)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(UdpSocket::bind(address).await.is_err());
    drop(upf);
    drop(other);
    UdpSocket::bind(address).await.unwrap();
}

#[tokio::test]
async fn replacing_a_session_while_send_waits_for_udp_readiness_rejects_the_old_generation() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let old = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let new = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upf.set_session(Session::new(1, 2, old.local_addr().unwrap(), 9));
    let mut sending = Box::pin(upf.send_downlink(1, vec![0x45]));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(sending.as_mut().poll(&mut context), Poll::Pending));
    upf.set_session(Session::new(1, 3, new.local_addr().unwrap(), 9));
    assert_eq!(sending.await.unwrap_err().kind(), io::ErrorKind::NotFound);
    let mut buffer = [0; 128];
    assert!(
        timeout(Duration::from_millis(25), old.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(25), new.recv_from(&mut buffer))
            .await
            .is_err()
    );
    upf.send_downlink(1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&new).await.teid, 3);
}

#[tokio::test]
async fn replacing_a_session_while_marker_waits_does_not_end_the_replacement_tunnel() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let old = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upf.set_session(Session::new(1, 2, old.local_addr().unwrap(), 9));
    let mut switching = Box::pin(upf.switch_downlink(1, target.local_addr().unwrap(), 3));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        switching.as_mut().poll(&mut context),
        Poll::Pending
    ));
    // Reusing the old peer's TEID means a stale marker could now end an
    // unrelated replacement tunnel, so the send must recheck its generation.
    upf.set_session(Session::new(1, 2, old.local_addr().unwrap(), 9));
    assert_eq!(switching.await.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(upf.pending_end_marker(1), None);
    let mut buffer = [0; 128];
    assert!(
        timeout(Duration::from_millis(25), old.recv_from(&mut buffer))
            .await
            .is_err()
    );
    upf.send_downlink(1, vec![0x45]).await.unwrap();
    let sent = reply(&old).await;
    assert_eq!((sent.message_type, sent.teid), (oxirush_gtp_u::G_PDU, 2));
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
