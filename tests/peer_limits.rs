//! What a peer without a tunnel can make an endpoint or the test UPF send:
//! Error Indications, Supported Extension Headers Notifications and Echo
//! Responses go out within a rate, 1,000 a second from a socket after a burst
//! of 1,000, and the counters have every message. These tests take addresses
//! 127.0.0.60 to 127.0.0.67, which macOS does not have.
#![cfg(not(target_os = "macos"))]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use oxirush_gtp_u::upf_sim::UpfSimulator;
use oxirush_gtp_u::{Endpoint, PORT};
use oxirush_gtp_u::{
    ExtensionHeader, ExtensionHeaderType, MessageType, Packet, ReceiveStats, RemoteTunnel,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

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

/// Send `count` copies of `packet` from `peer`, a few at a time so that
/// the receiver of `to` keeps up, and wait until `stats` counts them.
async fn flood(
    peer: &UdpSocket,
    to: SocketAddr,
    packet: &Packet,
    count: u64,
    stats: impl Fn() -> ReceiveStats,
) {
    flood_datagram(peer, to, &packet.encode().unwrap(), count, stats).await;
}

/// As [`flood`], with a datagram that need not be a message.
async fn flood_datagram(
    peer: &UdpSocket,
    to: SocketAddr,
    datagram: &[u8],
    count: u64,
    stats: impl Fn() -> ReceiveStats,
) {
    let start = stats().received_datagrams;
    for sent in 1..=count {
        peer.send_to(datagram, to).await.unwrap();
        if sent % 20 == 0 || sent == count {
            let caught_up = async {
                while stats().received_datagrams < start + sent {
                    tokio::time::sleep(Duration::from_micros(200)).await;
                }
            };
            timeout(Duration::from_secs(5), caught_up)
                .await
                .expect("the receiver did not get every datagram");
        }
    }
}

/// The messages that reach `socket` until it is quiet, by type.
async fn replies(socket: &UdpSocket) -> Vec<MessageType> {
    let mut buffer = [0; 2048];
    let mut types = Vec::new();
    while let Ok(received) = timeout(Duration::from_millis(100), socket.recv(&mut buffer)).await {
        let size = received.unwrap();
        types.push(Packet::decode(&buffer[..size]).unwrap().message_type);
    }
    types
}

/// The messages that reach `socket` while `flooding` runs and until the
/// socket is quiet after it, by type. They are read as they come: a slow
/// flood has every reply sent, which would overflow the socket's buffer.
async fn replies_during(
    socket: &UdpSocket,
    flooding: impl Future<Output = ()>,
) -> Vec<MessageType> {
    let mut buffer = [0; 2048];
    let mut types = Vec::new();
    let mut flooding = std::pin::pin!(flooding);
    loop {
        tokio::select! {
            () = &mut flooding => break,
            received = socket.recv(&mut buffer) => {
                let size = received.unwrap();
                types.push(Packet::decode(&buffer[..size]).unwrap().message_type);
            }
        }
    }
    types.extend(replies(socket).await);
    types
}

/// The most replies that a socket may send in `elapsed`.
fn at_most(elapsed: Duration) -> usize {
    1000 + (elapsed.as_secs_f64() * 1000.0).ceil() as usize + 1
}

#[tokio::test]
async fn a_peer_without_a_tunnel_gets_replies_within_a_rate() {
    let (endpoint, _received) = Endpoint::bind("127.0.0.60:0".parse().unwrap())
        .await
        .unwrap();
    endpoint
        .install(
            1,
            5,
            RemoteTunnel::new("127.0.0.61:2152".parse().unwrap(), 9),
            Some(9),
        )
        .unwrap();
    // The replies go to port 2152 of the sender, but Echo Responses.
    let peer = on_port_2152(|| UdpSocket::bind("127.0.0.61:2152")).await;
    let to = endpoint.local_addr().unwrap();
    let stats = || endpoint.stats();
    let start = Instant::now();
    let mut elapsed = Duration::ZERO;

    let replies = replies_during(&peer, async {
        // A header that must be understood and is not: a notification each.
        let mut unsupported = Packet::g_pdu(0x99, vec![0x45]);
        unsupported.extension_headers.push(ExtensionHeader::Other {
            kind: ExtensionHeaderType(0xc5),
            content: vec![0, 0],
        });
        flood(&peer, to, &unsupported, 1000, stats).await;
        // A TEID without a tunnel: an Error Indication each.
        flood(&peer, to, &Packet::g_pdu(0x99, vec![0x45]), 1000, stats).await;
        // An Echo Request, and one whose Length is wrong: an Echo Response
        // each, the second with a Cause.
        flood(&peer, to, &Packet::echo_request(1), 250, stats).await;
        let mut wrong = Packet::echo_request(2).encode().unwrap();
        wrong[3] += 1;
        flood_datagram(&peer, to, &wrong, 250, stats).await;
        // An Error Indication that names no tunnel, an End Marker of no
        // tunnel, and a message that an endpoint does not take.
        let unmatched = Packet::error_indication(0x77, "127.0.0.60".parse().unwrap());
        flood(&peer, to, &unmatched, 300, stats).await;
        flood(&peer, to, &Packet::end_marker(0x99), 300, stats).await;
        flood(&peer, to, &Packet::echo_response(3), 300, stats).await;
        elapsed = start.elapsed();
    })
    .await;
    assert!(
        (1000..=at_most(elapsed)).contains(&replies.len()),
        "{} replies in {elapsed:?}",
        replies.len()
    );
    // The burst goes to the notifications, which came first.
    assert_eq!(
        replies[..1000],
        [MessageType::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION; 1000]
    );
    let stats = endpoint.stats();
    assert_eq!(stats.received_datagrams, 3400);
    assert_eq!(stats.path_messages, 1250);
    assert_eq!(stats.malformed_datagrams, 250);
    assert_eq!(stats.unknown_teid_g_pdus, 1000);
    assert_eq!(stats.unmatched_error_indications, 300);
    assert_eq!(stats.ignored_messages, 600);
    assert_eq!(stats.suppressed_replies, 2500 - replies.len() as u64);
}

#[tokio::test]
async fn a_peer_without_a_session_gets_error_indications_of_the_test_upf_within_a_rate() {
    let (upf, _observed) = UpfSimulator::bind("127.0.0.62:0".parse().unwrap())
        .await
        .unwrap();
    let peer = on_port_2152(|| UdpSocket::bind("127.0.0.63:2152")).await;
    let to = upf.local_addr().unwrap();
    let stats = || upf.stats();
    let start = Instant::now();
    let mut elapsed = Duration::ZERO;
    let replies = replies_during(&peer, async {
        let unknown = Packet::uplink(0x1001, 9, vec![0x45]);
        flood(&peer, to, &unknown, 2000, stats).await;
        let indication = Packet::error_indication(0x2001, "127.0.0.62".parse().unwrap());
        flood(&peer, to, &indication, 300, stats).await;
        flood(&peer, to, &Packet::end_marker(0x1001), 300, stats).await;
        elapsed = start.elapsed();
    })
    .await;
    assert!(
        (1000..=at_most(elapsed)).contains(&replies.len()),
        "{} replies in {elapsed:?}",
        replies.len()
    );
    assert!(
        replies
            .iter()
            .all(|kind| *kind == MessageType::ERROR_INDICATION)
    );
    let stats = upf.stats();
    assert_eq!(stats.received_datagrams, 2600);
    assert_eq!(stats.unknown_teid_g_pdus, 2000);
    assert_eq!(stats.ignored_messages, 600);
    assert_eq!(stats.suppressed_replies, 2000 - replies.len() as u64);
}

/// The limit is the socket's: another endpoint answers its own peers.
#[tokio::test]
async fn each_socket_has_its_own_limit() {
    let mut sent = Vec::new();
    for (local, remote) in [("127.0.0.64", "127.0.0.65"), ("127.0.0.66", "127.0.0.67")] {
        let (endpoint, _received) = Endpoint::bind(format!("{local}:0").parse().unwrap())
            .await
            .unwrap();
        let peer = on_port_2152(|| UdpSocket::bind(format!("{remote}:{PORT}"))).await;
        let to = endpoint.local_addr().unwrap();
        flood(&peer, to, &Packet::g_pdu(0x99, vec![]), 100, || {
            endpoint.stats()
        })
        .await;
        sent.push(replies(&peer).await.len());
        assert_eq!(endpoint.stats().suppressed_replies, 0);
    }
    assert_eq!(sent, [100, 100]);
}
