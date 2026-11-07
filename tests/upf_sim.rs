// Tests that need a second loopback address are left out on macOS.
#![cfg_attr(target_os = "macos", allow(unused_imports))]

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{
    Endpoint, Error, InformationElement, MessageType, Packet, Part, PduSessionContainer,
    RemoteTunnel, ip,
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

/// What `bind` binds on port 2152, once it is free: the same test in another
/// process may hold the address, as when cargo-mutants tests several mutants
/// at once.
async fn on_port_2152<T, F: Future<Output = std::io::Result<T>>>(mut bind: impl FnMut() -> F) -> T {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match bind().await {
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse
                    && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            bound => return bound.unwrap(),
        }
    }
}

const WAIT: Duration = Duration::from_secs(2);

fn udp(payload: &[u8]) -> Vec<u8> {
    ip::udp(
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
    let source_teid = source.install(1, 1, remote, Some(9)).unwrap();
    upf.set_session(Session::new(
        remote.teid,
        source_teid,
        source.local_addr().unwrap(),
        9,
    ))
    .unwrap();
    source.send(1, 1, udp(b"before handover")).await.unwrap();
    assert_eq!(next(&mut upf_rx).await.uplink_teid, remote.teid);
    let before = next(&mut source_rx).await;
    assert_eq!(
        ip::parse_udp(&before.packet.payload).unwrap().2,
        b"before handover"
    );
    assert_eq!(
        before.packet.pdu_session_container(),
        Some(&PduSessionContainer::downlink(9))
    );

    let target_teid = target.install(2, 1, remote, Some(9)).unwrap();
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
        (1, MessageType::END_MARKER, source_teid)
    );
    source.remove(1, 1);
    target.send(2, 1, udp(b"after handover")).await.unwrap();
    assert_eq!(next(&mut upf_rx).await.from, target.local_addr().unwrap());
    let after = next(&mut target_rx).await;
    assert_eq!(
        ip::parse_udp(&after.packet.payload).unwrap().2,
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

/// An End Marker that cannot be sent: the error is returned, and the session
/// stays switched.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_end_marker_leaves_the_session_switched() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // An IPv4 socket cannot send to the IPv6 address of the old path.
    upf.set_session(Session::new(1, 2, "[2001:db8::1]:2152".parse().unwrap(), 9))
        .unwrap();
    assert!(
        upf.switch_downlink(1, target.local_addr().unwrap(), 3)
            .await
            .is_err()
    );
    assert_eq!(upf.session(1).unwrap().downlink_teid, 3);
    upf.send_downlink(1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&target).await.teid, 3);
    // Switching to the path that the session has sends nothing.
    upf.switch_downlink(1, target.local_addr().unwrap(), 3)
        .await
        .unwrap();
    let mut buffer = [0; 128];
    assert!(
        timeout(Duration::from_millis(50), target.recv_from(&mut buffer))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_qfi_above_63_is_refused_and_leaves_the_session_as_it_was() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    upf.set_session(Session::new(1, 2, address, 9)).unwrap();
    // A session is made with any QFI, and refused where it is given: for
    // the TEID of a session that exists and for a new one, whether the QFI
    // came through `new` or through the field.
    let mut changed = Session::new(1, 2, address, 9);
    changed.qfi = 64;
    for session in [changed, Session::new(5, 6, address, 64)] {
        let error = upf.set_session(session).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        // The error of the codec, which a G-PDU with that QFI gets.
        assert_eq!(
            error.get_ref().and_then(|inner| inner.downcast_ref()),
            Some(&qfi_error(64))
        );
        assert_eq!(
            Packet::downlink(2, 64, vec![0x45]).encode(),
            Err(qfi_error(64))
        );
    }
    assert_eq!(upf.session(5), None);
    upf.send_downlink(1, vec![0x45]).await.unwrap();
    assert_eq!(reply(&target).await.qfi(), Some(9));
    // 63 is the highest QFI.
    upf.set_session(Session::new(5, 6, address, 63)).unwrap();
}

fn qfi_error(qfi: u64) -> Error {
    Error::OutOfRange {
        what: Part::Qfi,
        value: qfi,
        max: 63,
    }
}

#[tokio::test]
async fn observer_drops_are_counted_without_delaying_path_management() {
    let (upf, observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upf.set_session(Session::new(1, 2, peer.local_addr().unwrap(), 9))
        .unwrap();
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
async fn shutdown_stops_all_clones() {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let other = upf.clone();
    let address = upf.local_addr().unwrap();
    upf.set_session(Session::new(1, 2, address, 9)).unwrap();
    assert!(upf.is_running());
    upf.shutdown().await.unwrap();
    assert!(!other.is_running());
    other.shutdown().await.unwrap();
    // The sessions go with it
    assert_eq!(other.session(1), None);
    assert_eq!(
        format!("{other:?}"),
        format!("UpfSimulator {{ local_addr: Some({address}), sessions: 0 }}")
    );
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

/// The UPF's Error Indication reaches a gNB endpoint on port 2152, here
/// 127.0.0.27 (macOS has no loopback address but 127.0.0.1).
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn error_indication_from_the_upf_reaches_the_tunnel() {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (gnb, mut received) =
        on_port_2152(|| Endpoint::bind("127.0.0.27:2152".parse().unwrap())).await;
    let remote = RemoteTunnel {
        address: upf.local_addr().unwrap(),
        teid: 0x3030,
    };
    let downlink_teid = gnb.install(4, 2, remote, Some(9)).unwrap();
    upf.set_session(Session::new(
        remote.teid,
        downlink_teid,
        gnb.local_addr().unwrap(),
        9,
    ))
    .unwrap();
    upf.remove_session(remote.teid);
    gnb.send(4, 2, udp(b"to a session the UPF lost"))
        .await
        .unwrap();
    let indication = next(&mut received).await;
    assert_eq!((indication.ran_id, indication.session_id), (4, 2));
    assert_eq!(
        indication.packet.message_type,
        MessageType::ERROR_INDICATION
    );
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
    let downlink_teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    upf.set_session(Session::new(
        remote.teid,
        downlink_teid,
        gnb.local_addr().unwrap(),
        9,
    ))
    .unwrap();
    // An ICMP Echo Request of 10.60.0.2 to 192.0.2.1, identifier 0x1234,
    // sequence number 4, with its checksums.
    let request = [
        0x45, 0, 0, 32, 0, 0, 0x40, 0, 64, 1, 0x6e, 0x9e, 10, 60, 0, 2, 192, 0, 2, 1, // IPv4
        8, 0, 0x17, 0xf5, 0x12, 0x34, 0, 4, b'e', b'c', b'h', b'o', // ICMP
    ];
    gnb.send(1, 1, request).await.unwrap();
    let reply = next(&mut received).await.packet.payload;
    // The addresses swapped, type 0, and the identifier, the sequence
    // number and the data of the request.
    assert_eq!(
        (&reply[12..16], &reply[16..20]),
        (&request[16..20], &request[12..16])
    );
    assert_eq!(reply[20..22], [0, 0]);
    assert_eq!(reply[24..], request[24..]);
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
        (MessageType::ECHO_RESPONSE, Some(9))
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
    let gnb_listener = on_port_2152(|| UdpSocket::bind("127.0.0.26:2152")).await;
    let gnb = UdpSocket::bind("127.0.0.26:0").await.unwrap();
    gnb.send_to(
        &Packet::uplink(77, 9, vec![0x45]).encode().unwrap(),
        upf.local_addr().unwrap(),
    )
    .await
    .unwrap();
    let indication = reply(&gnb_listener).await;
    assert_eq!(indication.message_type, MessageType::ERROR_INDICATION);
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
    upf.set_session(Session::new(10, 20, gnb.local_addr().unwrap(), 5))
        .unwrap();
    upf.send_downlink(10, &[0x60, 0][..]).await.unwrap();
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
    upf.set_session(Session::new(10, 20, gnb.local_addr().unwrap(), 5))
        .unwrap();
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

/// A program that answers the UE for N6 itself turns the echo service off:
/// the gNB then gets its answer alone, and not the echo before it.
#[tokio::test]
async fn a_program_that_answers_for_n6_turns_the_echo_service_off() {
    let (upf, mut uplinks) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert!(upf.echo_service());
    upf.set_echo_service(false);
    assert!(!upf.echo_service());
    let (gnb, mut downlinks) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let teid = gnb
        .install(
            1,
            5,
            RemoteTunnel::new(upf.local_addr().unwrap(), 0x1001),
            Some(9),
        )
        .unwrap();
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr().unwrap(), 9))
        .unwrap();
    gnb.send(1, 5, udp(b"ping")).await.unwrap();
    let uplink = next(&mut uplinks).await;
    let (from, to, payload) = ip::parse_udp(&uplink.packet.payload).unwrap();
    assert_eq!(payload, b"ping");
    upf.send_downlink(0x1001, ip::udp(to, from, b"pong").unwrap())
        .await
        .unwrap();
    let downlink = next(&mut downlinks).await;
    assert_eq!(ip::parse_udp(&downlink.packet.payload).unwrap().2, b"pong");
    assert!(
        timeout(Duration::from_millis(200), downlinks.recv())
            .await
            .is_err()
    );
    // Turned on again, it answers.
    upf.set_echo_service(true);
    gnb.send(1, 5, udp(b"ping")).await.unwrap();
    let downlink = next(&mut downlinks).await;
    assert_eq!(ip::parse_udp(&downlink.packet.payload).unwrap().2, b"ping");
}

/// The program says how it is called when asked.
#[cfg(feature = "cli")]
#[test]
fn the_program_prints_its_usage() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_oxirush-upf-sim"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let usage = String::from_utf8(output.stdout).unwrap();
    assert!(
        usage.starts_with("usage: oxirush-upf-sim <bind-ip:port>"),
        "{usage}"
    );
}

/// The program refuses arguments that it cannot take, and says why.
#[cfg(feature = "cli")]
#[test]
fn the_program_refuses_what_it_cannot_take() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_oxirush-upf-sim"))
        .args(["127.0.0.1:2152", "127.0.0.1:2153", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.starts_with("oxirush-upf-sim: wrong number of arguments\nusage:"),
        "{error}"
    );
}

/// Without TUNs, the program refuses one, and says why.
#[cfg(all(feature = "cli", not(all(target_os = "linux", feature = "tun"))))]
#[test]
fn the_program_without_tuns_refuses_one() {
    use std::io::Read;
    let mut program = std::process::Command::new(env!("CARGO_BIN_EXE_oxirush-upf-sim"))
        .args(["127.0.0.1:0", "127.0.0.1:2152", "1", "2"])
        .args(["--tun", "oxupf", "198.19.0.30"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // A program that took the TUN would serve until it is stopped
    let deadline = std::time::Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = program.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            program.kill().unwrap();
            panic!("the program serves with a TUN that it cannot have");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    let mut error = String::new();
    program
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    assert_eq!(
        error,
        "oxirush-upf-sim: --tun needs Linux and the tun feature\n"
    );
}

/// The program serves its session until it is told to stop: it says where it
/// is, then prints each uplink G-PDU, and ends with success on SIGTERM.
#[cfg(all(feature = "cli", target_os = "linux"))]
#[tokio::test]
async fn the_program_serves_its_session_until_it_is_stopped() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let gnb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gnb_address = gnb.local_addr().unwrap().to_string();
    let mut program = tokio::process::Command::new(env!("CARGO_BIN_EXE_oxirush-upf-sim"))
        .args(["127.0.0.1:0", &gnb_address, "0x1001", "0x2002"])
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(program.stdout.take().unwrap()).lines();
    let first = timeout(WAIT, lines.next_line()).await.unwrap().unwrap();
    let first = first.expect("the program says where it is");
    let (address, _) = first
        .strip_prefix("UPF simulator on ")
        .and_then(|rest| rest.split_once(": "))
        .expect(&first);
    assert_eq!(
        first,
        format!(
            "UPF simulator on {address}: uplink TEID 0x00001001, downlink TEID 0x00002002 \
             at gNB {gnb_address}"
        )
    );
    let uplink = Packet::g_pdu(0x1001, b"payload".to_vec()).encode().unwrap();
    gnb.send_to(&uplink, address).await.unwrap();
    let printed = timeout(WAIT, lines.next_line()).await.unwrap().unwrap();
    assert_eq!(
        printed.as_deref(),
        Some(format!("uplink TEID 0x00001001 from {gnb_address}: 7 octets").as_str())
    );
    let pid = libc::pid_t::try_from(program.id().unwrap()).unwrap();
    // SAFETY: a signal to the child that this test started.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = timeout(WAIT, program.wait()).await.unwrap().unwrap();
    assert!(status.success(), "{status}");
}

/// A simulator that is dropped stops, and leaves its address to another.
#[tokio::test]
async fn a_dropped_simulator_lets_its_address_go() {
    let (upf, receiver) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = upf.local_addr().unwrap();
    drop((upf, receiver));
    tokio::time::sleep(Duration::from_millis(50)).await;
    UpfSimulator::bind(address).await.unwrap();
}
