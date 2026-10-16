//! What a peer without a tunnel can make an endpoint or the test UPF send
//! and log. Error Indications and Supported Extension Headers Notifications
//! go out within a rate, 100 a second after a burst of 100; a line that a
//! peer causes is logged once a second at most for each kind; and the
//! counters have every message. These tests take addresses 127.0.0.60 to
//! 127.0.0.69, which macOS does not have.
#![cfg(not(target_os = "macos"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oxirush_gtp_u::upf_sim::UpfSimulator;
use oxirush_gtp_u::{Endpoint, PORT};
use oxirush_gtp_u::{
    ExtensionHeader, ExtensionHeaderType, MessageType, Packet, ReceiveStats, RemoteTunnel,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// The events of each level that a test's thread logs.
#[derive(Default)]
struct Lines {
    warn: AtomicUsize,
    debug: AtomicUsize,
}

struct Counting(Arc<Lines>);

impl Subscriber for Counting {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        match *event.metadata().level() {
            Level::WARN => self.0.warn.fetch_add(1, Ordering::Relaxed),
            Level::DEBUG => self.0.debug.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// Run `test` on a runtime of this thread, whose events `Lines` counts.
fn logged<F: Future<Output = ()>>(test: impl FnOnce(Arc<Lines>) -> F) {
    let lines = Arc::new(Lines::default());
    let dispatch = tracing::Dispatch::new(Counting(lines.clone()));
    tracing::dispatcher::with_default(&dispatch, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(test(lines));
    });
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
    let datagram = packet.encode().unwrap();
    let start = stats().received_datagrams;
    for sent in 1..=count {
        peer.send_to(&datagram, to).await.unwrap();
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

/// The most replies that a socket may send in `elapsed`.
fn at_most(elapsed: Duration) -> usize {
    100 + (elapsed.as_secs_f64() * 100.0).ceil() as usize + 1
}

/// The most lines of one kind in `elapsed`.
fn lines_at_most(elapsed: Duration) -> usize {
    1 + elapsed.as_secs() as usize
}

#[test]
fn a_peer_without_a_tunnel_gets_replies_within_a_rate_and_few_lines() {
    logged(|lines| async move {
        let (endpoint, _received) = Endpoint::bind("127.0.0.60:2152".parse().unwrap())
            .await
            .unwrap();
        endpoint
            .install(
                1,
                5,
                RemoteTunnel::new("127.0.0.61:2152".parse().unwrap(), 9),
                9,
            )
            .unwrap();
        // The replies go to port 2152 of the sender.
        let peer = UdpSocket::bind("127.0.0.61:2152").await.unwrap();
        let to = endpoint.local_addr().unwrap();
        let stats = || endpoint.stats();
        let start = Instant::now();

        // A header that must be understood and is not: a notification each.
        let mut unsupported = Packet::g_pdu(0x99, vec![0x45]);
        unsupported.extension_headers.push(ExtensionHeader::Other {
            kind: ExtensionHeaderType(0xc5),
            content: vec![0, 0],
        });
        flood(&peer, to, &unsupported, 1000, stats).await;
        // A TEID without a tunnel: an Error Indication each.
        flood(&peer, to, &Packet::g_pdu(0x99, vec![0x45]), 1000, stats).await;
        // An Error Indication that names no tunnel, an End Marker of no
        // tunnel, and a message that an endpoint does not take.
        let unmatched = Packet::error_indication(0x77, "127.0.0.60".parse().unwrap());
        flood(&peer, to, &unmatched, 300, stats).await;
        flood(&peer, to, &Packet::end_marker(0x99), 300, stats).await;
        flood(&peer, to, &Packet::echo_response(3), 300, stats).await;
        let elapsed = start.elapsed();

        let replies = replies(&peer).await;
        assert!(
            (100..=at_most(elapsed)).contains(&replies.len()),
            "{} replies in {elapsed:?}",
            replies.len()
        );
        // The burst goes to the notifications, which came first.
        assert_eq!(
            replies[..100],
            [MessageType::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION; 100]
        );
        let stats = endpoint.stats();
        assert_eq!(stats.received_datagrams, 2900);
        assert_eq!(stats.path_messages, 1000);
        assert_eq!(stats.unknown_teid_g_pdus, 1000);
        assert_eq!(stats.unmatched_error_indications, 300);
        assert_eq!(stats.ignored_messages, 600);
        assert_eq!(stats.suppressed_replies, 2000 - replies.len() as u64);
        // A line for the dropped messages, and one for each kind of the
        // others: unknown TEID, Error Indication, ignored.
        let elapsed = start.elapsed();
        let warn = lines.warn.load(Ordering::Relaxed);
        let debug = lines.debug.load(Ordering::Relaxed);
        assert!(
            (1..=lines_at_most(elapsed)).contains(&warn),
            "{warn} WARN lines in {elapsed:?}"
        );
        assert!(
            (3..=3 * lines_at_most(elapsed)).contains(&debug),
            "{debug} DEBUG lines in {elapsed:?}"
        );
    });
}

#[test]
fn a_peer_without_a_session_gets_error_indications_of_the_test_upf_within_a_rate() {
    logged(|lines| async move {
        let (upf, _observed) = UpfSimulator::bind("127.0.0.62:2152".parse().unwrap())
            .await
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.63:2152").await.unwrap();
        let to = upf.local_addr().unwrap();
        let stats = || upf.stats();
        let start = Instant::now();
        flood(
            &peer,
            to,
            &Packet::uplink(0x1001, 9, vec![0x45]),
            1000,
            stats,
        )
        .await;
        let indication = Packet::error_indication(0x2001, "127.0.0.62".parse().unwrap());
        flood(&peer, to, &indication, 300, stats).await;
        flood(&peer, to, &Packet::end_marker(0x1001), 300, stats).await;
        let elapsed = start.elapsed();

        let replies = replies(&peer).await;
        assert!(
            (100..=at_most(elapsed)).contains(&replies.len()),
            "{} replies in {elapsed:?}",
            replies.len()
        );
        assert!(
            replies
                .iter()
                .all(|kind| *kind == MessageType::ERROR_INDICATION)
        );
        let stats = upf.stats();
        assert_eq!(stats.received_datagrams, 1600);
        assert_eq!(stats.unknown_teid_g_pdus, 1000);
        assert_eq!(stats.ignored_messages, 600);
        assert_eq!(stats.suppressed_replies, 1000 - replies.len() as u64);
        let elapsed = start.elapsed();
        let debug = lines.debug.load(Ordering::Relaxed);
        assert!(
            (3..=3 * lines_at_most(elapsed)).contains(&debug),
            "{debug} DEBUG lines in {elapsed:?}"
        );
    });
}

/// The limit is the socket's: another endpoint answers its own peers.
#[tokio::test]
async fn each_socket_has_its_own_limit() {
    let mut sent = Vec::new();
    for (local, remote) in [("127.0.0.64", "127.0.0.65"), ("127.0.0.66", "127.0.0.67")] {
        let (endpoint, _received) = Endpoint::bind(format!("{local}:{PORT}").parse().unwrap())
            .await
            .unwrap();
        let peer = UdpSocket::bind(format!("{remote}:{PORT}")).await.unwrap();
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
