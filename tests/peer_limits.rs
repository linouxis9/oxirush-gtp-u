//! What a peer without a tunnel can make an endpoint or the test UPF send
//! and log. Error Indications and Supported Extension Headers Notifications
//! go out within a rate, 100 a second to an address after a burst of 100
//! and 1000 a second from a socket after a burst of 1000; Echo Responses
//! 10 a second to an address after a burst of 10; a line that a peer causes
//! is logged once a second at most for each kind; and the counters have
//! every message. These tests take addresses 127.0.0.60 to 127.0.0.69 and
//! 127.0.1.1 to 127.0.1.59, which macOS does not have.
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

/// The most replies that a socket may send to one address in `elapsed`.
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
        let mut elapsed = Duration::ZERO;
        let replies = replies_during(&peer, async {
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
            elapsed = start.elapsed();
        })
        .await;
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

/// A flood from one address uses the replies of that address: the peers of
/// removed tunnels, at other addresses, still get an Error Indication for
/// each of their G-PDUs.
///
/// The limit of an address is one of 1024 cells, under a key of the socket's
/// own, and a peer whose address falls into the attacker's cell shares its
/// limit. Both peers fall into it in one run of a million.
#[tokio::test]
async fn a_flood_from_one_address_leaves_their_error_indications_to_the_others() {
    let (endpoint, _received) = Endpoint::bind("127.0.1.1:2152".parse().unwrap())
        .await
        .unwrap();
    let attacker = UdpSocket::bind("127.0.1.2:2152").await.unwrap();
    let peers = [
        UdpSocket::bind("127.0.1.3:2152").await.unwrap(),
        UdpSocket::bind("127.0.1.8:2152").await.unwrap(),
    ];
    let to = endpoint.local_addr().unwrap();
    let mut removed = Vec::new();
    for (ran, peer) in (1..).zip(&peers) {
        let remote = RemoteTunnel::new(peer.local_addr().unwrap(), 9);
        removed.push(endpoint.install(ran, 5, remote, 9).unwrap());
        endpoint.remove(ran, 5);
    }
    let stats = || endpoint.stats();
    let unknown = Packet::g_pdu(0x99, vec![0x45]);
    let start = Instant::now();
    flood(&attacker, to, &unknown, 300, stats).await;
    for _ in 0..20 {
        for (peer, teid) in peers.iter().zip(&removed) {
            flood(peer, to, &Packet::g_pdu(*teid, vec![0x45]), 1, stats).await;
        }
        flood(&attacker, to, &unknown, 20, stats).await;
    }
    let elapsed = start.elapsed();

    // The replies that the peers did not get are those of a peer in the
    // attacker's cell.
    let mut whole = 0;
    let mut missing = 0;
    for peer in &peers {
        let indications = replies(peer).await;
        assert!(indications.len() <= 20);
        assert!(
            indications
                .iter()
                .all(|kind| *kind == MessageType::ERROR_INDICATION)
        );
        whole += usize::from(indications.len() == 20);
        missing += 20 - indications.len() as u64;
    }
    assert!(whole >= 1, "every peer lost Error Indications");
    // The attacker sent 700 G-PDUs: its address gets its burst, and what the
    // rate gives it in `elapsed`, however long the flood took.
    let suppressed = endpoint.stats().suppressed_replies - missing;
    let least = 700_u64.saturating_sub(at_most(elapsed) as u64);
    assert!(
        (least..=600).contains(&suppressed),
        "{suppressed} replies to the attacker suppressed in {elapsed:?}"
    );
}

/// Echo Responses to one address have a limit: whoever sends Echo Requests
/// with the address of another cannot have the socket flood it. Another
/// address is still answered.
#[tokio::test]
async fn echo_responses_to_one_address_have_a_limit() {
    let (endpoint, _received) = Endpoint::bind("127.0.1.4:2152".parse().unwrap())
        .await
        .unwrap();
    let flooder = UdpSocket::bind("127.0.1.5:0").await.unwrap();
    let peer = UdpSocket::bind("127.0.1.6:0").await.unwrap();
    let to = endpoint.local_addr().unwrap();
    let stats = || endpoint.stats();
    let start = Instant::now();
    let mut elapsed = Duration::ZERO;
    let answered = replies_during(&flooder, async {
        flood(&flooder, to, &Packet::echo_request(1), 500, stats).await;
        // An Echo Request whose Length is wrong gets an Echo Response with a
        // Cause: within the same limit.
        let mut wrong = Packet::echo_request(2).encode().unwrap();
        wrong[3] += 1;
        flood_datagram(&flooder, to, &wrong, 100, stats).await;
        elapsed = start.elapsed();
    })
    .await
    .len();
    let at_most = 10 + (elapsed.as_secs_f64() * 10.0).ceil() as usize + 1;
    assert!(
        (10..=at_most).contains(&answered),
        "{answered} Echo Responses in {elapsed:?}"
    );
    flood(&peer, to, &Packet::echo_request(3), 5, stats).await;
    assert_eq!(replies(&peer).await, [MessageType::ECHO_RESPONSE; 5]);
    let stats = endpoint.stats();
    assert_eq!(stats.suppressed_echo_responses, 600 - answered as u64);
    assert_eq!(stats.suppressed_replies, 0);
}

/// What a socket sends to all the addresses together has a limit too.
#[tokio::test]
async fn a_socket_sends_a_thousand_replies_a_second_at_most() {
    let (endpoint, _received) = Endpoint::bind("127.0.1.7:2152".parse().unwrap())
        .await
        .unwrap();
    let to = endpoint.local_addr().unwrap();
    let mut peers = Vec::new();
    for host in 10..35 {
        peers.push(
            UdpSocket::bind(format!("127.0.1.{host}:2152"))
                .await
                .unwrap(),
        );
    }
    let start = Instant::now();
    for peer in &peers {
        flood(peer, to, &Packet::g_pdu(0x99, vec![0x45]), 100, || {
            endpoint.stats()
        })
        .await;
    }
    let elapsed = start.elapsed();
    let mut sent = 0;
    for peer in &peers {
        sent += replies(peer).await.len();
    }
    let at_most = 1000 + (elapsed.as_secs_f64() * 1000.0).ceil() as usize + 1;
    assert!(
        (1000..=at_most).contains(&sent),
        "{sent} replies in {elapsed:?}"
    );
    // A flood that took less than 1.5 s goes past the limit, and one that
    // took longer need not: a slow machine sends every reply.
    let suppressed = endpoint.stats().suppressed_replies;
    assert_eq!(suppressed, 2500 - sent as u64);
    assert!(
        suppressed >= 2500_u64.saturating_sub(at_most as u64),
        "{suppressed} replies suppressed in {elapsed:?}"
    );
}
