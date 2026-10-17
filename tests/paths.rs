//! The paths of an endpoint: its Echo Requests and their responses, the
//! supervision of a path, Tunnel Status, and its peers' Supported Extension
//! Headers Notifications (TS 29.281 §7.2, §7.3.3, §11; TS 23.007 §20.3.1).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oxirush_gtp_u::upf_sim::UpfSimulator;
use oxirush_gtp_u::{
    Endpoint, ExtensionHeader, ExtensionHeaderType, InformationElement, InformationElementType,
    MessageType, Packet, PathEvent, PathTimers, RemoteTunnel,
};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);

/// A peer that answers the Echo Requests from the `answer_from`-th on, and
/// none while `silent`, and keeps their sequence numbers.
struct Peer {
    address: SocketAddr,
    socket: Arc<UdpSocket>,
    silent: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<u16>>>,
}

async fn peer(answer_from: usize) -> Peer {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let silent = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let (socket, silent, requests) = (socket.clone(), silent.clone(), requests.clone());
        async move {
            let mut buffer = [0; 2048];
            while let Ok((size, from)) = socket.recv_from(&mut buffer).await {
                let Ok(packet) = Packet::decode(&buffer[..size]) else {
                    continue;
                };
                if packet.message_type != MessageType::ECHO_REQUEST {
                    continue;
                }
                let sequence = packet.sequence.unwrap();
                requests.lock().unwrap().push(sequence);
                if seen.fetch_add(1, Ordering::Relaxed) >= answer_from
                    && !silent.load(Ordering::Relaxed)
                {
                    let response = Packet::echo_response(sequence).encode().unwrap();
                    socket.send_to(&response, from).await.unwrap();
                }
            }
        }
    });
    Peer {
        address: socket.local_addr().unwrap(),
        socket,
        silent,
        requests,
    }
}

/// Timers of tens of milliseconds, for tests.
fn fast(t3_response: u64, n3_requests: u32, interval: u64) -> PathTimers {
    let mut timers = PathTimers::default();
    timers.t3_response = Duration::from_millis(t3_response);
    timers.n3_requests = n3_requests;
    timers.interval = Duration::from_millis(interval);
    timers
}

async fn event(events: &mut broadcast::Receiver<PathEvent>) -> PathEvent {
    timeout(WAIT, events.recv())
        .await
        .expect("no path event")
        .unwrap()
}

#[tokio::test]
async fn echo_gives_the_round_trip_and_the_response() {
    let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let mut events = gnb.path_events();
    let round_trip = gnb.echo(upf.local_addr().unwrap()).await.unwrap();
    assert!(round_trip < WAIT);
    match event(&mut events).await {
        PathEvent::EchoResponse {
            from,
            round_trip: of_event,
            packet,
            ..
        } => {
            assert_eq!(from, upf.local_addr().unwrap());
            assert_eq!(of_event, round_trip);
            assert_eq!(
                packet.information_elements().unwrap(),
                [InformationElement::Recovery(0)]
            );
        }
        other => panic!("{other:?}"),
    }
}

/// An Echo Request goes again each T3-RESPONSE, with its sequence number,
/// N3-REQUESTS times in all.
#[tokio::test]
async fn echo_sends_its_request_again_and_times_out() {
    let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    gnb.set_path_timers(fast(50, 3, 1000)).unwrap();
    let silent = peer(usize::MAX).await;
    let start = Instant::now();
    let error = gnb.echo(silent.address).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() >= Duration::from_millis(150));
    assert!(error.to_string().contains("3 Echo Requests"), "{error}");
    let requests = silent.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|sequence| *sequence == requests[0]));

    // A peer that answers the second time.
    let late = peer(1).await;
    gnb.echo(late.address).await.unwrap();
    assert_eq!(late.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_supervised_path_goes_down_and_comes_back() {
    let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    gnb.set_path_timers(fast(30, 2, 100)).unwrap();
    let upf = peer(0).await;
    let mut events = gnb.path_events();
    gnb.supervise(upf.address).unwrap();
    assert!(matches!(
        event(&mut events).await,
        PathEvent::EchoResponse { .. }
    ));
    let state = gnb.path_state(upf.address).unwrap();
    assert!(state.up && state.unanswered == 0 && state.round_trip.is_some());

    // Two expiries of a request do not exceed N3-REQUESTS; the first of
    // the next does.
    upf.silent.store(true, Ordering::Relaxed);
    assert_eq!(
        event(&mut events).await,
        PathEvent::Down { peer: upf.address }
    );
    let state = gnb.path_state(upf.address).unwrap();
    assert!(!state.up && state.unanswered >= 3, "{state:?}");

    upf.silent.store(false, Ordering::Relaxed);
    loop {
        match event(&mut events).await {
            PathEvent::Up { peer } => break assert_eq!(peer, upf.address),
            PathEvent::EchoResponse { .. } => {}
            other => panic!("{other:?}"),
        }
    }
    let state = gnb.path_state(upf.address).unwrap();
    assert!(state.up && state.unanswered == 0);

    gnb.end_supervision(upf.address);
    assert_eq!(gnb.path_state(upf.address), None);
    let sent = upf.requests.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(upf.requests.lock().unwrap().len(), sent);
}

/// The reviewer's first attempt: an Echo Request through `send_to`.
#[tokio::test]
async fn the_response_to_an_echo_request_of_send_to_comes_on_the_path_events() {
    let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let mut events = gnb.path_events();
    gnb.send_to(&Packet::echo_request(42), upf.local_addr().unwrap())
        .await
        .unwrap();
    match event(&mut events).await {
        PathEvent::EchoResponse { sequence, from, .. } => {
            assert_eq!((sequence, from), (42, upf.local_addr().unwrap()));
        }
        other => panic!("{other:?}"),
    }
}

/// A response that answers no request is a duplicate (TS 29.281 §11).
#[tokio::test]
async fn an_echo_response_without_its_request_is_discarded() {
    let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let mut events = gnb.path_events();
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let response = Packet::echo_response(7).encode().unwrap();
    stranger
        .send_to(&response, gnb.local_addr().unwrap())
        .await
        .unwrap();
    // Answered twice: the second response is a duplicate.
    let upf = peer(0).await;
    gnb.echo(upf.address).await.unwrap();
    let sequence = upf.requests.lock().unwrap()[0];
    let duplicate = Packet::echo_response(sequence).encode().unwrap();
    upf.socket
        .send_to(&duplicate, gnb.local_addr().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        event(&mut events).await,
        PathEvent::EchoResponse { .. }
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(events.try_recv().is_err());
    assert_eq!(gnb.stats().ignored_messages, 2);
}

/// A peer's notification is delivered, and `send_to` does not send it again
/// an extension header that it must understand and does not support; the
/// tunnels go on.
#[tokio::test]
async fn a_peers_notification_is_delivered_and_honoured() {
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let upf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (to, address) = (gnb.local_addr().unwrap(), upf.local_addr().unwrap());
    gnb.install(1, 5, RemoteTunnel::new(address, 7), 9).unwrap();
    let mut events = gnb.path_events();
    let notification =
        Packet::supported_extension_headers_notification(&[ExtensionHeaderType::UDP_PORT]);
    upf.send_to(&notification.encode().unwrap(), to)
        .await
        .unwrap();
    assert_eq!(
        event(&mut events).await,
        PathEvent::SupportedExtensionHeaders {
            from: address,
            types: vec![ExtensionHeaderType::UDP_PORT]
        }
    );
    assert_eq!(
        gnb.supported_extension_headers(address.ip()),
        Some(vec![ExtensionHeaderType::UDP_PORT])
    );

    // A header that it must understand and does not support, and one that
    // it does.
    let mut unknown = Packet::g_pdu(7, vec![0x45]);
    unknown.extension_headers.push(ExtensionHeader::Other {
        kind: ExtensionHeaderType(0xc5),
        content: vec![0, 0],
    });
    let error = gnb.send_to(&unknown, address).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        "127.0.0.1 said that it does not support extension header 0xc5, which it must understand"
    );
    let uplink = Packet::uplink(7, 9, vec![0x45]);
    assert!(gnb.send_to(&uplink, address).await.is_err());
    let mut port = Packet::g_pdu(7, vec![0x45]);
    port.extension_headers.push(ExtensionHeader::UdpPort(2152));
    gnb.send_to(&port, address).await.unwrap();
    // The tunnel's G-PDUs keep their container.
    gnb.send(1, 5, vec![0x45]).await.unwrap();
    let mut buffer = [0; 256];
    for expected in [None, Some(9)] {
        let size = timeout(WAIT, upf.recv(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(Packet::decode(&buffer[..size]).unwrap().qfi(), expected);
    }

    // Tried again.
    gnb.forget_supported_extension_headers(address.ip());
    assert_eq!(gnb.supported_extension_headers(address.ip()), None);
    gnb.send_to(&uplink, address).await.unwrap();
    assert!(received.try_recv().is_err());
}

/// A Tunnel Status on a tunnel's TEID goes to the receiver with the
/// tunnel; on another TEID it is ignored (TS 29.281 §7.3.3).
#[tokio::test]
async fn a_tunnel_status_is_delivered_with_its_tunnel() {
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let upf = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let teid = gnb
        .install(1, 5, RemoteTunnel::new(upf.local_addr().unwrap(), 7), 9)
        .unwrap();
    let status = |teid| {
        let information = InformationElement::Other {
            kind: InformationElementType::GTP_U_TUNNEL_STATUS_INFORMATION,
            value: vec![1],
        };
        let elements = InformationElement::encode_all(&[information]).unwrap();
        Packet::new(MessageType::TUNNEL_STATUS, teid, elements)
            .encode()
            .unwrap()
    };
    let to = gnb.local_addr().unwrap();
    upf.send_to(&status(teid.wrapping_add(1).max(1)), to)
        .await
        .unwrap();
    upf.send_to(&status(teid), to).await.unwrap();
    let delivered = timeout(WAIT, received.recv()).await.unwrap().unwrap();
    assert_eq!((delivered.ran_id, delivered.session_id), (1, 5));
    assert_eq!(delivered.packet.message_type, MessageType::TUNNEL_STATUS);
    assert_eq!(gnb.stats().ignored_messages, 1);
}

#[test]
fn timers_that_send_nothing_are_refused() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        for timers in [fast(50, 0, 100), fast(0, 3, 100), fast(50, 3, 0)] {
            let error = gnb.set_path_timers(timers).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        assert_eq!(gnb.path_timers(), PathTimers::default());
    });
}
