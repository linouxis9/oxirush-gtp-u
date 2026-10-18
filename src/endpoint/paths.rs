//! The paths of an endpoint: its Echo Requests and their responses
//! (TS 29.281 §7.2, §11), the state of the paths it supervises (TS 23.007
//! §20.3.1), and what its peers said of the extension headers they support
//! (§7.2.3).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, oneshot};
use tokio::task::AbortHandle;
use tokio::time::Instant;

use crate::datagram::DatagramSocket;
use crate::path::lock;
use crate::{ExtensionHeaderType, InformationElement, Packet};

/// The events that a receiver of [`Endpoint::path_events`] can lag behind
/// by before it loses the oldest.
///
/// [`Endpoint::path_events`]: super::Endpoint::path_events
const EVENTS: usize = 64;

/// The Echo Requests that `send_to` sent and whose responses are awaited,
/// beside those of `echo` and of the supervised paths.
const SENT_REQUESTS: usize = 1024;

/// The peers whose Supported Extension Headers Notification is kept.
const NOTIFYING_PEERS: usize = 256;

/// The timers with which an endpoint sends Echo Requests (TS 29.281 §11,
/// §12) and supervises a path (§7.2.1, TS 23.007 §20.3.1).
///
/// ```
/// use std::time::Duration;
///
/// use oxirush_gtp_u::PathTimers;
///
/// let mut timers = PathTimers::default();
/// assert_eq!(timers.n3_requests, 5);
/// // A lab that wants to know within seconds that its UPF is gone.
/// timers.interval = Duration::from_secs(5);
/// timers.t3_response = Duration::from_millis(500);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathTimers {
    /// T3-RESPONSE: how long an Echo Request waits for its response before
    /// it is sent again, with the same sequence number. 3 s by default: the
    /// specification leaves the value to the operator.
    pub t3_response: Duration,
    /// N3-REQUESTS: how many times an Echo Request is sent at most, 5 by
    /// default, the value that TS 29.281 §12.3 recommends.
    pub n3_requests: u32,
    /// How often a supervised path gets a new Echo Request: 60 s by
    /// default, the shortest interval that TS 29.281 §7.2.1 allows. A lab
    /// may want less, which a peer that holds to §7.2.1 does not expect.
    pub interval: Duration,
}

impl Default for PathTimers {
    fn default() -> Self {
        Self {
            t3_response: Duration::from_secs(3),
            n3_requests: 5,
            interval: Duration::from_secs(60),
        }
    }
}

/// The state of a path that an endpoint supervises
/// ([`Endpoint::supervise`](super::Endpoint::supervise)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathState {
    /// Whether the path is up. It is until its counter exceeds N3-REQUESTS,
    /// and again once an Echo Response comes (TS 23.007 §20.3.1).
    pub up: bool,
    /// The path counter: the times that T3-RESPONSE expired for an Echo
    /// Request on the path since its last Echo Response.
    pub unanswered: u32,
    /// The round trip of the last Echo Response on the path, from the last
    /// time its request was sent.
    pub round_trip: Option<Duration>,
}

/// What an endpoint learns of its paths, from the receiver of
/// [`Endpoint::path_events`](super::Endpoint::path_events).
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use oxirush_gtp_u::upf_sim::UpfSimulator;
/// use oxirush_gtp_u::{Endpoint, PathEvent};
///
/// let (upf, _observed) = UpfSimulator::bind("127.0.0.1:0".parse()?).await?;
/// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse()?).await?;
///
/// // The events of the paths, from now on
/// let mut events = gnb.path_events();
/// gnb.echo(upf.local_addr()?).await?;
/// match events.recv().await? {
///     PathEvent::EchoResponse { sequence, .. } => println!("Echo Response {sequence}"),
///     PathEvent::SupportedExtensionHeaders { from, types } => println!("{from}: {types:?}"),
///     PathEvent::Down { peer } => println!("the path to {peer} is down"),
///     PathEvent::Up { peer } => println!("the path to {peer} is up again"),
///     _ => {}
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathEvent {
    /// The Echo Response to an Echo Request of the endpoint: one of
    /// [`echo`](super::Endpoint::echo), of a supervised path, or one that
    /// [`send_to`](super::Endpoint::send_to) sent. A response that answers
    /// none of them is a duplicate, which TS 29.281 §11 discards.
    EchoResponse {
        /// The peer, IPv4 rather than IPv4-mapped.
        from: SocketAddr,
        /// Its sequence number, that of the request.
        sequence: u16,
        /// From the last time that the request was sent.
        round_trip: Duration,
        /// The response, with its information elements: the Recovery, and a
        /// Recovery Time Stamp or a Private Extension if it has them.
        packet: Packet,
    },
    /// A Supported Extension Headers Notification (TS 29.281 §7.2.3): the
    /// peer could not interpret an extension header that it had to, and
    /// lists those it supports. [`send_to`](super::Endpoint::send_to) then
    /// refuses to send it a message with another one that it must
    /// understand.
    SupportedExtensionHeaders {
        /// The peer, IPv4 rather than IPv4-mapped.
        from: SocketAddr,
        /// The types that it supports.
        types: Vec<ExtensionHeaderType>,
    },
    /// A supervised path is down: its counter exceeded N3-REQUESTS
    /// (TS 23.007 §20.3.1).
    Down {
        /// The peer of the path, as it was given to `supervise`.
        peer: SocketAddr,
    },
    /// A supervised path that was down is up again: an Echo Response came.
    Up {
        /// The peer of the path, as it was given to `supervise`.
        peer: SocketAddr,
    },
}

/// The paths of an endpoint, shared by its clones, its receive task and the
/// tasks that supervise paths.
pub(super) struct Paths {
    events: broadcast::Sender<PathEvent>,
    state: Mutex<State>,
    /// Whether a peer's notification is kept: `send_to` looks at them
    /// only then.
    notified: AtomicBool,
}

#[derive(Default)]
struct State {
    timers: PathTimers,
    /// The sequence number that the next Echo Request of the endpoint
    /// tries first.
    next_sequence: u16,
    /// The Echo Requests that await their response, by sequence number,
    /// which is unique among them (TS 29.281 §11).
    outstanding: HashMap<u16, Outstanding>,
    supervised: HashMap<SocketAddr, Supervised>,
    /// The types of the last Supported Extension Headers Notification of
    /// each peer that sent one.
    supported: HashMap<IpAddr, Vec<ExtensionHeaderType>>,
}

struct Outstanding {
    /// The peer, IPv4 rather than IPv4-mapped.
    peer: IpAddr,
    /// When the request was last sent.
    sent: Instant,
    /// The call that waits for the response, if one does: `echo` or a
    /// supervised path. One that `send_to` sent has none.
    waiter: Option<oneshot::Sender<Duration>>,
}

struct Supervised {
    state: PathState,
    task: AbortHandle,
}

impl Paths {
    pub(super) fn new() -> Self {
        Self {
            events: broadcast::channel(EVENTS).0,
            state: Mutex::default(),
            notified: AtomicBool::new(false),
        }
    }

    pub(super) fn events(&self) -> broadcast::Receiver<PathEvent> {
        self.events.subscribe()
    }

    pub(super) fn timers(&self) -> PathTimers {
        lock(&self.state).timers
    }

    pub(super) fn set_timers(&self, timers: PathTimers) -> io::Result<()> {
        if timers.n3_requests == 0 || timers.t3_response.is_zero() || timers.interval.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path timers that send no Echo Request or wait for none: {timers:?}"),
            ));
        }
        lock(&self.state).timers = timers;
        Ok(())
    }

    /// The state of the supervised path to `peer`.
    pub(super) fn path_state(&self, peer: SocketAddr) -> Option<PathState> {
        lock(&self.state)
            .supervised
            .get(&peer)
            .map(|path| path.state)
    }

    /// Supervise the path to `peer` with the task that `start` spawns,
    /// unless it is supervised.
    pub(super) fn supervise(&self, peer: SocketAddr, start: impl FnOnce() -> AbortHandle) {
        let mut state = lock(&self.state);
        state.supervised.entry(peer).or_insert_with(|| Supervised {
            state: PathState {
                up: true,
                unanswered: 0,
                round_trip: None,
            },
            task: start(),
        });
    }

    pub(super) fn end_supervision(&self, peer: SocketAddr) {
        if let Some(path) = lock(&self.state).supervised.remove(&peer) {
            path.task.abort();
        }
    }

    /// End the supervision of every path, when the endpoint stops.
    pub(super) fn end_supervisions(&self) {
        for (_, path) in lock(&self.state).supervised.drain() {
            path.task.abort();
        }
    }

    /// A sequence number for an Echo Request to `peer` that no outstanding
    /// request has, with the receiver of its response's round trip.
    fn register(&self, peer: IpAddr) -> io::Result<(u16, oneshot::Receiver<Duration>)> {
        let mut state = lock(&self.state);
        let (sender, receiver) = oneshot::channel();
        for _ in 0..=u16::MAX {
            let sequence = state.next_sequence;
            state.next_sequence = sequence.wrapping_add(1);
            if let std::collections::hash_map::Entry::Vacant(entry) =
                state.outstanding.entry(sequence)
            {
                entry.insert(Outstanding {
                    peer,
                    sent: Instant::now(),
                    waiter: Some(sender),
                });
                return Ok((sequence, receiver));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "every sequence number has an outstanding Echo Request",
        ))
    }

    /// The request with `sequence` is sent now.
    fn sent(&self, sequence: u16) {
        if let Some(request) = lock(&self.state).outstanding.get_mut(&sequence) {
            request.sent = Instant::now();
        }
    }

    fn unregister(&self, sequence: u16) {
        lock(&self.state).outstanding.remove(&sequence);
    }

    /// `send_to` sends an Echo Request with `sequence` to `peer`: its
    /// response is awaited, unless a request of the endpoint has that
    /// number. Those that waited longer than N3-REQUESTS times
    /// T3-RESPONSE are no longer awaited.
    pub(super) fn sent_request(&self, peer: IpAddr, sequence: u16) {
        let mut state = lock(&self.state);
        let unanswered = state.timers.t3_response * state.timers.n3_requests;
        if state.outstanding.len() >= SENT_REQUESTS {
            let now = Instant::now();
            state
                .outstanding
                .retain(|_, request| request.waiter.is_some() || now - request.sent < unanswered);
        }
        if state.outstanding.len() < SENT_REQUESTS {
            state.outstanding.entry(sequence).or_insert(Outstanding {
                peer,
                sent: Instant::now(),
                waiter: None,
            });
        }
    }

    /// T3-RESPONSE expired for an Echo Request to `peer`: the counter of
    /// the supervised paths to it, if any.
    fn expired(&self, peer: IpAddr) {
        let mut state = lock(&self.state);
        let n3_requests = state.timers.n3_requests;
        for (path, supervised) in &mut state.supervised {
            if path.ip().to_canonical() != peer {
                continue;
            }
            let path_state = &mut supervised.state;
            path_state.unanswered = path_state.unanswered.saturating_add(1);
            if path_state.up && path_state.unanswered > n3_requests {
                path_state.up = false;
                let _ = self.events.send(PathEvent::Down { peer: *path });
            }
        }
    }

    /// An Echo Response from `from`: false if it answers no outstanding
    /// request, a duplicate.
    pub(super) fn echo_response(&self, packet: &Packet<&[u8]>, from: SocketAddr) -> bool {
        let Some(sequence) = packet.sequence else {
            return false;
        };
        let peer = from.ip().to_canonical();
        let mut state = lock(&self.state);
        let Some(request) = state
            .outstanding
            .remove(&sequence)
            .filter(|request| request.peer == peer)
        else {
            return false;
        };
        let round_trip = request.sent.elapsed();
        if let Some(waiter) = request.waiter {
            let _ = waiter.send(round_trip);
        }
        // The path counter is reset each time that an Echo Response comes on
        // the path.
        for (path, supervised) in &mut state.supervised {
            if path.ip().to_canonical() != peer {
                continue;
            }
            let path_state = &mut supervised.state;
            path_state.unanswered = 0;
            path_state.round_trip = Some(round_trip);
            if !path_state.up {
                path_state.up = true;
                let _ = self.events.send(PathEvent::Up { peer: *path });
            }
        }
        drop(state);
        let _ = self.events.send(PathEvent::EchoResponse {
            from,
            sequence,
            round_trip,
            packet: packet.clone().into_owned(),
        });
        true
    }

    /// A Supported Extension Headers Notification from `from`: false if it
    /// has no Extension Header Type List.
    pub(super) fn notification(&self, packet: &Packet<&[u8]>, from: SocketAddr) -> bool {
        let types = packet.information_elements().ok().and_then(|elements| {
            elements.into_iter().find_map(|element| match element {
                InformationElement::ExtensionHeaderTypeList(types) => Some(types),
                _ => None,
            })
        });
        let Some(types) = types else {
            return false;
        };
        let peer = from.ip().to_canonical();
        {
            let mut state = lock(&self.state);
            if state.supported.len() >= NOTIFYING_PEERS && !state.supported.contains_key(&peer) {
                // Anyone can send one with the address of another: the
                // table keeps its size.
                if let Some(other) = state.supported.keys().next().copied() {
                    state.supported.remove(&other);
                }
            }
            state.supported.insert(peer, types.clone());
            self.notified.store(true, Ordering::Relaxed);
        }
        let _ = self
            .events
            .send(PathEvent::SupportedExtensionHeaders { from, types });
        true
    }

    pub(super) fn supported_extension_headers(
        &self,
        peer: IpAddr,
    ) -> Option<Vec<ExtensionHeaderType>> {
        lock(&self.state)
            .supported
            .get(&peer.to_canonical())
            .cloned()
    }

    pub(super) fn forget_supported_extension_headers(&self, peer: IpAddr) {
        let mut state = lock(&self.state);
        state.supported.remove(&peer.to_canonical());
        self.notified
            .store(!state.supported.is_empty(), Ordering::Relaxed);
    }

    /// The first extension header of `packet` that `to` must understand and
    /// said, in its last notification, that it does not support.
    pub(super) fn refused<P: AsRef<[u8]>>(
        &self,
        packet: &Packet<P>,
        to: IpAddr,
    ) -> Option<ExtensionHeaderType> {
        if !self.notified.load(Ordering::Relaxed) {
            return None;
        }
        let mut required = packet
            .extension_headers
            .iter()
            .filter(|header| header.comprehension_required())
            .peekable();
        required.peek()?;
        let state = lock(&self.state);
        let supported = state.supported.get(&to.to_canonical())?;
        required
            .map(|header| header.kind())
            .find(|kind| !supported.contains(kind))
    }
}

/// Send an Echo Request to `peer`, and again each T3-RESPONSE with the same
/// sequence number, N3-REQUESTS times at most: the round trip of its
/// response. A send that fails ends it with its error when `stop_on_error`,
/// and otherwise counts as a request whose response did not come.
pub(super) async fn exchange(
    socket: &DatagramSocket,
    paths: &Paths,
    peer: SocketAddr,
    stop_on_error: bool,
) -> io::Result<Duration> {
    let timers = paths.timers();
    let target = peer.ip().to_canonical();
    let (sequence, mut answer) = paths.register(target)?;
    // The request is no longer awaited when this ends, however it does.
    struct Registration<'a>(&'a Paths, u16);
    impl Drop for Registration<'_> {
        fn drop(&mut self) {
            self.0.unregister(self.1);
        }
    }
    let _registration = Registration(paths, sequence);
    let request = Packet::echo_request(sequence);
    for _ in 0..timers.n3_requests {
        paths.sent(sequence);
        if let Err(error) = socket.send(&request, peer).await
            && stop_on_error
        {
            return Err(error);
        }
        match tokio::time::timeout(timers.t3_response, &mut answer).await {
            Ok(Ok(round_trip)) => return Ok(round_trip),
            // The registration went with the endpoint.
            Ok(Err(_)) => return Err(io::ErrorKind::BrokenPipe.into()),
            Err(_) => paths.expired(target),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "no Echo Response from {peer} to {} Echo Requests {:?} apart",
            timers.n3_requests, timers.t3_response
        ),
    ))
}

/// Supervise the path to `peer`: an Echo Request each interval, until the
/// task is aborted.
pub(super) async fn supervise(socket: Arc<DatagramSocket>, paths: Arc<Paths>, peer: SocketAddr) {
    loop {
        let start = Instant::now();
        let _ = exchange(&socket, &paths, peer, false).await;
        tokio::time::sleep_until(start + paths.timers().interval).await;
    }
}
