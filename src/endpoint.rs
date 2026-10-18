//! The N3 endpoint of a gNB, or the S1-U endpoint of an eNB.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};
use tokio::task::{AbortHandle, JoinHandle};
#[cfg(all(target_os = "linux", feature = "tun"))]
use tracing::debug;
use tracing::trace;

use crate::ReceiveStats;
use crate::datagram::DatagramSocket;
use crate::limit::limited;
#[cfg(all(target_os = "linux", feature = "tun"))]
use crate::tun::{TunConfig, TunPort};
use crate::types::Teid;
use crate::{ExtensionHeaderType, MessageType, Packet};

mod paths;
use paths::Paths;
pub use paths::{PathEvent, PathState, PathTimers};
mod routes;
#[cfg(fast_path)]
use routes::N3FastPath;
use routes::RouteTable;
use routes::Shortcuts;
#[cfg(all(target_os = "linux", feature = "tun"))]
use routes::{SessionKey, TunAttachment};

/// Messages the receiver of [`Endpoint::bind`] can lag behind by before
/// newer ones are dropped.
const QUEUE: usize = 256;

/// The far end of a tunnel: the peer's GTP-U address and the TEID it
/// assigned (an F-TEID). `Debug` prints the TEID in hexadecimal.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoteTunnel {
    /// The peer's address, normally on port [`PORT`](crate::PORT).
    pub address: SocketAddr,
    /// The TEID the peer receives the tunnel's packets on.
    pub teid: u32,
}

impl RemoteTunnel {
    /// The tunnel that the peer at `address` receives on `teid`.
    ///
    /// ```
    /// use oxirush_gtp_u::RemoteTunnel;
    ///
    /// // The UPF's end of a PDU session, as NGAP gives it to the gNB
    /// let upf = RemoteTunnel::new("192.0.2.8:2152".parse().unwrap(), 0x1001);
    /// assert_eq!(format!("{upf:?}"), "RemoteTunnel { address: 192.0.2.8:2152, teid: 0x00001001 }");
    /// ```
    pub fn new(address: SocketAddr, teid: u32) -> Self {
        Self { address, teid }
    }
}

impl fmt::Debug for RemoteTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTunnel")
            .field("address", &self.address)
            .field("teid", &Teid(self.teid))
            .finish()
    }
}

/// A message for one of the endpoint's tunnels.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceivedPacket {
    /// The tunnel's RAN UE identifier.
    pub ran_id: u32,
    /// The tunnel's PDU session ID.
    pub session_id: u8,
    /// A G-PDU, an End Marker or a Tunnel Status on the tunnel's local
    /// TEID, or an Error Indication by which the peer reports that it no
    /// longer knows the tunnel's remote TEID.
    pub packet: Packet,
    /// The address it came from, IPv4 rather than IPv4-mapped. It need not
    /// be the tunnel's remote address: the TEID, or for an Error
    /// Indication its information elements, identify the tunnel.
    pub from: SocketAddr,
}

/// One UDP socket carrying a gNB's N3 tunnels, each identified by a RAN UE
/// identifier (such as the RAN UE NGAP ID) and a PDU session ID, or an
/// eNB's S1-U tunnels, identified by the eNB UE S1AP ID and E-RAB ID.
///
/// A task answers Echo Requests, sends an Error Indication for a G-PDU on
/// an unknown TEID and a Supported Extension Headers Notification for an
/// unsupported comprehension-required extension header, and delivers the
/// tunnels' messages, with every extension header that
/// [`ExtensionHeader`](crate::ExtensionHeader) has a variant for: those of
/// a handover and of the RAN protocols among them. It sends Echo Requests
/// and supervises paths when asked, and delivers what its peers send on
/// the paths. As in TS 29.281, the TEID alone identifies a tunnel: peers
/// may send from another address than their F-TEID's. GTP-U has no
/// authentication, so whoever reaches the socket can send on a tunnel or
/// report an Error Indication for it. Clones share the socket and tunnels;
/// the task stops when the last clone is dropped. Must be used within a
/// Tokio runtime.
///
/// ```
/// use oxirush_gtp_u::{Endpoint, RemoteTunnel};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> std::io::Result<()> {
/// let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
/// let (peer, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
/// // Each side assigns the TEID it receives on; the other sends to it.
/// let peer_teid = peer.install(1, 5, RemoteTunnel::new(gnb.local_addr()?, 0), 9)?;
/// let gnb_teid = gnb.install(1, 5, RemoteTunnel::new(peer.local_addr()?, peer_teid), 9)?;
/// peer.install(1, 5, RemoteTunnel::new(gnb.local_addr()?, gnb_teid), 9)?;
///
/// gnb.send(1, 5, b"an IP packet".to_vec()).await?;
/// let packet = received.recv().await.unwrap();
/// assert_eq!((packet.ran_id, packet.session_id), (1, 5));
/// assert_eq!(packet.packet.qfi(), Some(9));
/// # Ok(())
/// # }
/// ```
///
/// # Tunnels
///
/// [`bind`](Self::bind) opens the socket and returns the receiver of the
/// tunnels' messages: G-PDUs, End Markers, Tunnel Status messages and the
/// peer's Error Indications, each with its tunnel and source address. The
/// TEID alone identifies a tunnel, so a peer may send from another address
/// than its F-TEID's. An End Marker or a Tunnel Status on a TEID without a
/// tunnel is ignored (TS 29.281 §7.3.2.1, §7.3.3).
///
/// - [`install`](Self::install) sets up the tunnel of a RAN UE and PDU session
///   toward a remote TEID and returns the local TEID to give the peer; on an
///   existing tunnel it updates the remote end and the QFI. Local TEIDs are
///   drawn at random: one cannot be told from another. A QFI above 63 is
///   `InvalidInput`. [`install_s1u`](Self::install_s1u) does so for an eNB's
///   E-RAB, whose G-PDUs carry no PDU Session Container, and cannot fail.
///   [`install_with_teid`](Self::install_with_teid) takes a local TEID that
///   something else assigned.
/// - [`send`](Self::send) sends an IP packet in a tunnel.
///   [`send_to`](Self::send_to) sends any `Packet` from the endpoint's socket,
///   with its sequence number and extension headers.
/// - `attach_tun` gives a tunnel a TUN (Linux, `tun` feature) and carries its
///   packets both ways: the tunnel's G-PDUs then go to Linux and no longer to
///   the receiver. The TUN closes with its tunnel, on `remove`, `remove_ran`
///   and `shutdown`, and when the last clone of the endpoint is dropped.
/// - [`remove`](Self::remove) and [`remove_ran`](Self::remove_ran) remove
///   tunnels; [`local_teid`](Self::local_teid) looks one up.
///
/// # Path management
///
/// The endpoint sends by itself the replies that TS 29.281 §7 asks of every
/// GTP-U node: it answers Echo Requests, sends an Error Indication for a
/// G-PDU on an unknown TEID and a Supported Extension Headers Notification
/// for an extension header it must understand and does not. The last two go
/// to port 2152, as the specification requires. A slow receiver never
/// delays these replies: past 256 queued messages new ones are dropped and
/// counted, and a dropped receiver changes nothing else.
///
/// The rest is the program's to ask for:
///
/// - [`echo`](Self::echo) sends an Echo Request to a peer and waits for its
///   response, which it repeats each T3-RESPONSE, N3-REQUESTS times at most
///   (§11, [`PathTimers`]).
/// - [`supervise`](Self::supervise) sends one on a path each interval and
///   follows its state, which [`path_state`](Self::path_state) reads: the
///   path is down once more than N3-REQUESTS of its requests' timers expired
///   since its last response (TS 29.281 §9.2, TS 23.007 §20.3.1).
/// - [`path_events`](Self::path_events) gives the Echo Responses, the
///   peers' Supported Extension Headers Notifications and the changes of the
///   supervised paths. An Echo Response that answers no request of the
///   endpoint is a duplicate, which §11 discards.
/// - After a peer's notification, [`send_to`](Self::send_to) refuses to send
///   it a message with an extension header that it must understand and does
///   not support (§7.2.3), until
///   [`forget_supported_extension_headers`](Self::forget_supported_extension_headers).
///   The tunnels' own G-PDUs keep their PDU Session Container, which N3
///   needs: a notification, which anyone can send with the peer's address,
///   does not stop a tunnel.
///
/// A peer needs no tunnel to cause these replies, and GTP-U has no
/// authentication: whoever can send from an address can have them sent to
/// it. The socket sends an address 100 Error Indications and Supported
/// Extension Headers Notifications a second at most, after a burst of 100,
/// and all addresses together 1000 a second, after a burst of 1000; past
/// that a reply is not sent and is counted in
/// [`suppressed_replies`](ReceiveStats::suppressed_replies). A flood from
/// one address uses up the replies of that address: the peer of a removed
/// tunnel still gets an Error Indication for its next G-PDUs, which is what
/// TS 29.281 §7.3.1 has it for. The clause expects such a defence against
/// denial of service, for which it gives the Error Indication its UDP Port
/// header. An address gets 10 Echo Responses a second at most, after a
/// burst of 10, and the others are counted in
/// [`suppressed_echo_responses`](ReceiveStats::suppressed_echo_responses):
/// a peer sends an Echo Request on a path every 60 s at most (§7.2.1), and
/// an Echo Response, with its sequence number and Recovery, can be longer
/// than its request. The limit of an address is one of 1024 cells, chosen
/// by a hash of the address under a key of the socket's own; the addresses
/// of a cell share it. A line that a peer causes, such as for a G-PDU on an
/// unknown TEID, is logged once a second at most for each kind, with the
/// number of those that were not.
///
/// Bind a specific address: a wildcard is refused with `InvalidInput`, so that
/// replies leave from the address the request reached. Bind port 2152 to
/// receive the peer's Error Indications, which TS 29.281 §4.4.2.4 sends there
/// whatever port the G-PDUs came from.
///
/// [`stats`](Self::stats) has the receive and drop counters and
/// [`is_running`](Self::is_running) the state of the background task.
/// [`shutdown`](Self::shutdown) stops it for all clones and waits for it; the
/// port stays bound until the last clone is dropped.
#[derive(Clone)]
pub struct Endpoint {
    shared: Arc<Shared>,
}

struct Shared {
    socket: Arc<DatagramSocket>,
    routes: Arc<RouteTable>,
    paths: Arc<Paths>,
    worker: AbortHandle,
    completion: tokio::sync::Mutex<Option<JoinHandle<io::Result<()>>>>,
    stopped: AtomicBool,
    /// Owned here, so that it goes with the last clone of the endpoint, and
    /// not with the tasks that hold the tunnels.
    #[cfg(fast_path)]
    fast_path: std::sync::OnceLock<N3FastPath>,
}

impl Shared {
    #[cfg(fast_path)]
    fn shortcuts(&self) -> Shortcuts<'_> {
        self.fast_path.get()
    }

    #[cfg(not(fast_path))]
    fn shortcuts(&self) -> Shortcuts<'_> {
        Shortcuts::default()
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.worker.abort();
        self.paths.end_supervisions();
        #[cfg(fast_path)]
        self.routes.end_shortcuts(self.shortcuts());
        // The TUNs' readers hold the routes, which hold them.
        self.routes.close_tuns();
    }
}

impl Endpoint {
    /// Bind the N3 socket to `address`. The receiver gets the tunnels'
    /// messages; when it lags more than 256 messages behind, newer ones are
    /// dropped, as a full socket buffer would, so that Echo Requests are
    /// still answered. The endpoint keeps working if the receiver is
    /// dropped.
    ///
    /// Bind port 2152 ([`PORT`](crate::PORT)) to receive the peer's Error
    /// Indications: TS 29.281 §4.4.2.4 sends them there, whatever port the
    /// G-PDUs came from. Several endpoints thus need an address each.
    ///
    /// The address must be specific, so replies leave from the address
    /// the request reached (TS 29.281 §4.4.3). Wildcard addresses return
    /// [`InvalidInput`](io::ErrorKind::InvalidInput).
    pub async fn bind(address: SocketAddr) -> io::Result<(Self, mpsc::Receiver<ReceivedPacket>)> {
        let socket = Arc::new(DatagramSocket::bind(address).await?);
        let routes = Arc::new(RouteTable::default());
        let paths = Arc::new(Paths::new());
        let (tx, rx) = mpsc::channel(QUEUE);
        let completion = tokio::spawn(receive(socket.clone(), routes.clone(), paths.clone(), tx));
        let worker = completion.abort_handle();
        let shared = Shared {
            socket,
            routes,
            paths,
            worker,
            completion: tokio::sync::Mutex::new(Some(completion)),
            stopped: AtomicBool::new(false),
            #[cfg(fast_path)]
            fast_path: std::sync::OnceLock::new(),
        };
        Ok((
            Self {
                shared: Arc::new(shared),
            },
            rx,
        ))
    }

    /// The socket's local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }

    /// Receive counters, including overload drops. Clones share the counters.
    pub fn stats(&self) -> ReceiveStats {
        self.shared.socket.stats()
    }

    /// Whether the background receiver is still running and has not been shut down.
    pub fn is_running(&self) -> bool {
        !self.shared.stopped.load(Ordering::Relaxed) && !self.shared.worker.is_finished()
    }

    /// Stop automatic replies and delivery for all clones and await the receiver.
    /// Repeated calls are safe; cancelling this future retains its completion handle.
    /// The UDP port remains bound until the final clone is dropped. Provisioning
    /// methods may still update the registry, but sending then returns `BrokenPipe`.
    /// The tunnels' TUNs close.
    pub async fn shutdown(&self) -> io::Result<()> {
        self.shared.stopped.store(true, Ordering::Relaxed);
        self.shared.worker.abort();
        self.shared.paths.end_supervisions();
        #[cfg(fast_path)]
        self.shared.routes.end_shortcuts(self.shared.shortcuts());
        self.shared.routes.close_tuns();
        let mut completion = self.shared.completion.lock().await;
        let result = match completion.as_mut() {
            Some(worker) => match worker.await {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(io::Error::other(error)),
            },
            None => Ok(()),
        };
        completion.take();
        result
    }

    /// Send a custom message from this endpoint's bound socket. This preserves
    /// its sequence number and extension headers and does not require a route.
    ///
    /// The response to an Echo Request with a sequence number comes on
    /// [`path_events`](Self::path_events), unless one of the endpoint's
    /// Echo Requests has that number.
    ///
    /// # Errors
    ///
    /// [`Unsupported`](io::ErrorKind::Unsupported) for a message with an
    /// extension header that `to` must understand and that, in its last
    /// Supported Extension Headers Notification, it said it does not
    /// support: TS 29.281 §7.2.3 asks to avoid such repeated attempts.
    /// [`forget_supported_extension_headers`](Self::forget_supported_extension_headers)
    /// tries the peer again. [`BrokenPipe`](io::ErrorKind::BrokenPipe) once
    /// the endpoint is shut down.
    pub async fn send_to<P: AsRef<[u8]>>(
        &self,
        packet: &Packet<P>,
        to: SocketAddr,
    ) -> io::Result<()> {
        if let Some(kind) = self.shared.paths.refused(packet, to.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{} said that it does not support extension header {kind}, \
                     which it must understand",
                    to.ip().to_canonical()
                ),
            ));
        }
        if packet.message_type == MessageType::ECHO_REQUEST
            && let Some(sequence) = packet.sequence
        {
            self.shared
                .paths
                .sent_request(to.ip().to_canonical(), sequence);
        }
        self.send_packet(packet, to).await
    }

    async fn send_packet<P: AsRef<[u8]>>(
        &self,
        packet: &Packet<P>,
        to: SocketAddr,
    ) -> io::Result<()> {
        if !self.is_running() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.shared.socket.send(packet, to).await
    }

    /// Send an Echo Request to `peer`, and again each T3-RESPONSE with the
    /// same sequence number until its Echo Response comes, N3-REQUESTS times
    /// at most ([`path_timers`](Self::path_timers), TS 29.281 §11): the
    /// round trip from the last time that it was sent. The response also
    /// comes on [`path_events`](Self::path_events).
    ///
    /// ```
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> std::io::Result<()> {
    /// use oxirush_gtp_u::upf_sim::UpfSimulator;
    /// use oxirush_gtp_u::{Endpoint, PathEvent};
    ///
    /// let (upf, _observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
    /// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
    ///
    /// // Whether the UPF answers, and the response among the events of the paths
    /// let mut events = gnb.path_events();
    /// let round_trip = gnb.echo(upf.local_addr()?).await?;
    /// let Ok(PathEvent::EchoResponse { from, .. }) = events.recv().await else { unreachable!() };
    /// assert_eq!(from, upf.local_addr()?);
    /// assert!(round_trip < std::time::Duration::from_secs(3));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`TimedOut`](io::ErrorKind::TimedOut) if no response came,
    /// [`BrokenPipe`](io::ErrorKind::BrokenPipe) once the endpoint is shut
    /// down, and the error of a send that failed.
    pub async fn echo(&self, peer: SocketAddr) -> io::Result<Duration> {
        if !self.is_running() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        paths::exchange(&self.shared.socket, &self.shared.paths, peer, true).await
    }

    /// Supervise the path to `peer`, as TS 23.007 §20.3.1 has it: an Echo
    /// Request each interval of [`path_timers`](Self::path_timers), sent
    /// again each T3-RESPONSE until its response comes, N3-REQUESTS times at
    /// most. The path counter counts the times that T3-RESPONSE expired
    /// since the last Echo Response from the peer, and the path is down
    /// once it exceeds N3-REQUESTS: with the default timers, from the first
    /// expiry of the second request that is not answered, 63 s after the
    /// first. An Echo Response brings it up again.
    /// [`path_state`](Self::path_state) has the state, and
    /// [`path_events`](Self::path_events) its changes. Nothing more happens
    /// to the tunnels: TS 23.007 leaves it to the node.
    ///
    /// A path is supervised until
    /// [`end_supervision`](Self::end_supervision), the endpoint's
    /// [`shutdown`](Self::shutdown) or its last clone. Supervising it again
    /// changes nothing.
    ///
    /// ```
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> std::io::Result<()> {
    /// use oxirush_gtp_u::Endpoint;
    /// use oxirush_gtp_u::upf_sim::UpfSimulator;
    ///
    /// let (upf, _observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
    /// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
    ///
    /// // The path to the UPF, supervised: up until Echo Requests go unanswered
    /// gnb.supervise(upf.local_addr()?)?;
    /// let state = gnb.path_state(upf.local_addr()?).unwrap();
    /// assert!(state.up);
    /// assert_eq!(state.unanswered, 0);
    ///
    /// // A path that is not supervised has no state
    /// assert!(gnb.path_state("127.0.0.1:9".parse().unwrap()).is_none());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`BrokenPipe`](io::ErrorKind::BrokenPipe) once the endpoint is shut
    /// down.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub fn supervise(&self, peer: SocketAddr) -> io::Result<()> {
        if !self.is_running() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let (socket, paths) = (self.shared.socket.clone(), self.shared.paths.clone());
        self.shared.paths.supervise(peer, || {
            tokio::spawn(paths::supervise(socket, paths, peer)).abort_handle()
        });
        Ok(())
    }

    /// Stop supervising the path to `peer`.
    pub fn end_supervision(&self, peer: SocketAddr) {
        self.shared.paths.end_supervision(peer);
    }

    /// The state of the supervised path to `peer`, as it was given to
    /// [`supervise`](Self::supervise).
    pub fn path_state(&self, peer: SocketAddr) -> Option<PathState> {
        self.shared.paths.path_state(peer)
    }

    /// The timers of the endpoint's Echo Requests.
    pub fn path_timers(&self) -> PathTimers {
        self.shared.paths.timers()
    }

    /// Set the timers of the endpoint's Echo Requests, for the requests that
    /// it sends from now on.
    ///
    /// # Errors
    ///
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) for N3-REQUESTS 0, or
    /// a T3-RESPONSE or an interval of 0.
    pub fn set_path_timers(&self, timers: PathTimers) -> io::Result<()> {
        self.shared.paths.set_timers(timers)
    }

    /// The events of the endpoint's paths: the Echo Responses to its
    /// requests, its peers' Supported Extension Headers Notifications, and
    /// the changes of the paths that it supervises. A receiver gets those
    /// that come after it is made; one that lags 64 events behind loses the
    /// oldest, and its `recv` says how many.
    pub fn path_events(&self) -> broadcast::Receiver<PathEvent> {
        self.shared.paths.events()
    }

    /// The extension header types that `peer` said it supports, in the
    /// last Supported Extension Headers Notification that it sent. The
    /// endpoint keeps those of 256 peers at most.
    pub fn supported_extension_headers(&self, peer: IpAddr) -> Option<Vec<ExtensionHeaderType>> {
        self.shared.paths.supported_extension_headers(peer)
    }

    /// Forget what `peer` said of the extension headers it supports:
    /// [`send_to`](Self::send_to) sends it every one again, as TS 29.281
    /// §7.2.3 allows to find out whether it was upgraded.
    pub fn forget_supported_extension_headers(&self, peer: IpAddr) {
        self.shared.paths.forget_supported_extension_headers(peer);
    }

    /// Provision an explicitly assigned, nonzero local TEID. `qfi=None` selects
    /// S1-U framing. A TEID owned by another session is rejected; validation
    /// errors leave the existing route unchanged. A local TEID of 0 and a QFI
    /// above 63 are [`InvalidInput`](io::ErrorKind::InvalidInput), the
    /// second as for [`install`](Self::install).
    pub fn install_with_teid(
        &self,
        ran_id: u32,
        session_id: u8,
        local_teid: u32,
        remote: RemoteTunnel,
        qfi: Option<u8>,
    ) -> io::Result<()> {
        self.shared.routes.install_with_teid(
            (ran_id, session_id),
            local_teid,
            remote,
            qfi,
            self.shared.shortcuts(),
        )
    }

    /// Give the endpoint, bound to an IPv4 address and the GTP-U port, its
    /// fast path: it then carries in the kernel the tunnels that
    /// [`attach_tun`](Self::attach_tun) or [`shortcut`](Self::shortcut)
    /// gives a TUN from now on, until they are removed or the endpoint is
    /// shut down.
    #[cfg(fast_path)]
    #[cfg_attr(docsrs, doc(cfg(all(target_os = "linux", feature = "ebpf"))))]
    pub fn set_fast_path(&self, fast_path: crate::ebpf::FastPath) -> io::Result<()> {
        let local = match self.local_addr()? {
            SocketAddr::V4(local) if local.port() == crate::PORT => *local.ip(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the fast path needs an IPv4 N3 address and the GTP-U port",
                ));
            }
        };
        self.shared.fast_path.set((fast_path, local)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the endpoint has its fast path",
            )
        })
    }

    /// Carry a tunnel's packets in the kernel, between TUN interface `tun`
    /// ([`TunPort::index`](crate::tun::TunPort::index)), which
    /// [`FastPath::add_tun`](crate::ebpf::FastPath::add_tun) put on the fast
    /// path, and the peer. This lasts until the tunnel is removed, `tun`
    /// gets another tunnel, or
    /// [`FastPath::end_shortcut`](crate::ebpf::FastPath::end_shortcut) or
    /// [`remove_tun`](crate::ebpf::FastPath::remove_tun); later changes of
    /// the tunnel's remote end and QFI apply to it. It asks Linux for the
    /// route to the peer and writes two map entries.
    ///
    /// This is for a TUN the caller made: [`attach_tun`](Self::attach_tun)
    /// short-cuts the tunnel of the TUN it makes.
    ///
    /// # Errors
    ///
    /// On an error the tunnel stays in userspace, and `tun` loses the
    /// short-cut it had.
    ///
    /// - [`WouldBlock`](io::ErrorKind::WouldBlock): the N3 interface is
    ///   still getting its program, attached off the caller's task when a
    ///   first tunnel through it was installed. Ask again later, such as
    ///   with the next packet.
    /// - [`NotFound`](io::ErrorKind::NotFound): the endpoint has no such
    ///   tunnel, or `tun` is not on the fast path.
    /// - [`Unsupported`](io::ErrorKind::Unsupported): the endpoint has no
    ///   fast path, or the peer is not IPv4 on the GTP-U port.
    /// - Another error: the route lookup or a map write failed, or the N3
    ///   interface could not get its program, which is not tried again.
    #[cfg(fast_path)]
    #[cfg_attr(docsrs, doc(cfg(all(target_os = "linux", feature = "ebpf"))))]
    pub fn shortcut(&self, ran_id: u32, session_id: u8, tun: u32) -> io::Result<()> {
        let fast_path = self.shared.fast_path.get().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "the endpoint has no fast path")
        })?;
        shortcut(&self.shared.routes, fast_path, (ran_id, session_id), tun)
    }

    /// Set up the tunnel of RAN UE `ran_id` and PDU session `session_id`
    /// toward `remote`, with uplink QoS flow `qfi` (0..=63), and return its
    /// local TEID. For an existing tunnel this updates the remote end and
    /// QFI and keeps the TEID.
    ///
    /// ```
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> std::io::Result<()> {
    /// use oxirush_gtp_u::{Endpoint, RemoteTunnel};
    ///
    /// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
    /// let upf = "127.0.0.1:2152".parse().unwrap();
    ///
    /// // RAN UE 1, PDU session 5: the uplink goes to TEID 0x1001 of the UPF, in QoS
    /// // flow 9, and the downlink comes on the TEID that the endpoint chose
    /// let teid = gnb.install(1, 5, RemoteTunnel::new(upf, 0x1001), 9)?;
    ///
    /// // The UPF moves the session to another TEID: the local one stays
    /// assert_eq!(gnb.install(1, 5, RemoteTunnel::new(upf, 0x2002), 9)?, teid);
    ///
    /// // A QFI has six bits
    /// let refused = gnb.install(1, 5, RemoteTunnel::new(upf, 0x2002), 64).unwrap_err();
    /// assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) if `qfi` is above 63:
    /// the tunnel then stays as it was. The error holds the codec's
    /// [`Error::OutOfRange`](crate::Error::OutOfRange) for the QFI, which
    /// is what encoding a G-PDU with it returns.
    pub fn install(
        &self,
        ran_id: u32,
        session_id: u8,
        remote: RemoteTunnel,
        qfi: u8,
    ) -> io::Result<u32> {
        crate::path::qfi(qfi)?;
        Ok(self.install_route(ran_id, session_id, remote, Some(qfi)))
    }

    /// Set up the S1-U tunnel of eNB UE `ran_id` and E-RAB `erab_id`
    /// toward `remote`, and return its local TEID. Its uplink G-PDUs carry
    /// no PDU Session Container. For an existing tunnel this updates the
    /// remote end and keeps the TEID.
    pub fn install_s1u(&self, ran_id: u32, erab_id: u8, remote: RemoteTunnel) -> u32 {
        self.install_route(ran_id, erab_id, remote, None)
    }

    fn install_route(
        &self,
        ran_id: u32,
        session_id: u8,
        remote: RemoteTunnel,
        qfi: Option<u8>,
    ) -> u32 {
        self.shared
            .routes
            .install((ran_id, session_id), remote, qfi, self.shared.shortcuts())
    }

    /// Give a tunnel a Linux TUN, made as `config` says: what Linux routes
    /// into the TUN goes into the tunnel, and the IP packets of the
    /// tunnel's G-PDUs go to Linux. The receiver of [`bind`](Self::bind)
    /// no longer gets these G-PDUs; it still gets the tunnel's End Markers
    /// and Error Indications, and a G-PDU that has no packet, only its
    /// extension headers.
    ///
    /// The TUN closes with its tunnel: on [`remove`](Self::remove),
    /// [`remove_ran`](Self::remove_ran) and [`shutdown`](Self::shutdown),
    /// and when the last clone of the endpoint is dropped. Installing the
    /// tunnel again, to change its remote end or QFI, keeps the TUN.
    ///
    /// On an endpoint that has a fast path
    /// ([`set_fast_path`](Self::set_fast_path)) the TUN is on it and the
    /// kernel carries the tunnel's packets. The endpoint asks for the
    /// tunnel's short-cut at once, and again when it carried a packet from
    /// the TUN and the tunnel has no short-cut: each millisecond at most
    /// while the tunnel's N3 interface is getting its program, and a second
    /// after another failure. It carries the packets that come meanwhile,
    /// and those the programs leave.
    ///
    /// # Errors
    ///
    /// On an error nothing of the TUN is left.
    ///
    /// - [`NotFound`](io::ErrorKind::NotFound): the endpoint has no such
    ///   tunnel.
    /// - [`AlreadyExists`](io::ErrorKind::AlreadyExists): the tunnel has a
    ///   TUN, or an interface has the TUN's name.
    /// - [`BrokenPipe`](io::ErrorKind::BrokenPipe): the endpoint is not
    ///   running.
    /// - Another error: the TUN or its routing could not be set up, as in
    ///   [`TunPort::create`], or the TUN could not be put on the fast path.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub fn attach_tun(&self, ran_id: u32, session_id: u8, config: TunConfig) -> io::Result<()> {
        if !self.is_running() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let key = (ran_id, session_id);
        self.shared.routes.tun_slot(key)?;
        let port = TunPort::create(config)?;
        #[cfg(fast_path)]
        let fast_path = self.shared.fast_path.get().cloned();
        #[cfg(fast_path)]
        if let Some((fast_path, _)) = &fast_path {
            fast_path.add_tun(port.index())?;
        }
        let reader = tokio::spawn(forward_tun(
            port.clone(),
            self.shared.socket.clone(),
            self.shared.routes.clone(),
            key,
            #[cfg(fast_path)]
            fast_path.clone(),
        ));
        let attachment = TunAttachment {
            port,
            reader,
            #[cfg(fast_path)]
            fast_path: fast_path.map(|(fast_path, _)| fast_path),
        };
        // Unless the tunnel went away or got a TUN meanwhile.
        self.shared.routes.attach_tun(key, attachment)
    }

    /// The local TEID of a tunnel.
    pub fn local_teid(&self, ran_id: u32, session_id: u8) -> Option<u32> {
        self.shared
            .routes
            .route((ran_id, session_id))
            .map(|route| route.local_teid)
    }

    /// Remove a tunnel, and close its TUN if it has one. Its G-PDUs then
    /// get an Error Indication.
    pub fn remove(&self, ran_id: u32, session_id: u8) {
        self.shared
            .routes
            .remove((ran_id, session_id), self.shared.shortcuts());
    }

    /// Remove every tunnel of RAN UE `ran_id`, as [`remove`](Self::remove)
    /// does.
    pub fn remove_ran(&self, ran_id: u32) {
        self.shared
            .routes
            .remove_ran(ran_id, self.shared.shortcuts());
    }

    /// Send an owned or borrowed IP packet as an uplink G-PDU in a tunnel.
    ///
    /// ```
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> std::io::Result<()> {
    /// use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    /// use oxirush_gtp_u::{Endpoint, RemoteTunnel, ipv4_udp};
    ///
    /// let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
    /// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
    /// let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    /// upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;
    ///
    /// // An IP packet of the UE in the tunnel of RAN UE 1, PDU session 5
    /// let (ue, server) = ("10.45.0.2:4000".parse().unwrap(), "192.0.2.1:7".parse().unwrap());
    /// gnb.send(1, 5, ipv4_udp(ue, server, b"hello")?).await?;
    /// let uplink = observed.recv().await.unwrap();
    /// assert_eq!((uplink.uplink_teid, uplink.packet.qfi()), (0x1001, Some(9)));
    ///
    /// // A session without a tunnel
    /// let missing = gnb.send(2, 1, ipv4_udp(ue, server, b"hello")?).await.unwrap_err();
    /// assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send<P: AsRef<[u8]>>(
        &self,
        ran_id: u32,
        session_id: u8,
        payload: P,
    ) -> io::Result<()> {
        let key = (ran_id, session_id);
        let route = self
            .shared
            .routes
            .route(key)
            .ok_or_else(|| routes::no_tunnel(key))?;
        self.send_packet(&route.uplink(payload), route.remote.address)
            .await
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("local_addr", &self.local_addr().ok())
            .field("tunnels", &self.shared.routes.len())
            .finish()
    }
}

async fn receive(
    socket: Arc<DatagramSocket>,
    routes: Arc<RouteTable>,
    paths: Arc<Paths>,
    tx: mpsc::Sender<ReceivedPacket>,
) -> io::Result<()> {
    let mut buffer = vec![0; 65536];
    loop {
        let Some((packet, from)) = socket.receive(&mut buffer).await? else {
            continue;
        };
        trace!(
            "N3 received {} TEID {:#010x} ({} bytes) from {from}",
            packet.message_type,
            packet.teid,
            packet.payload.len()
        );
        let (notices, counters) = (socket.notices(), socket.counters());
        let key = match packet.message_type {
            MessageType::G_PDU | MessageType::END_MARKER | MessageType::TUNNEL_STATUS => {
                let found = routes.session(packet.teid);
                match found {
                    Some(key) => key,
                    None if packet.message_type == MessageType::G_PDU => {
                        limited!(
                            DEBUG,
                            notices,
                            unknown_teid,
                            "N3 G-PDU for unknown TEID {:#010x} from {from}",
                            packet.teid
                        );
                        socket.unknown_teid(packet.teid, from).await;
                        continue;
                    }
                    // TS 29.281 §7.3.2.1 and §7.3.3: ignored.
                    None => {
                        counters.ignored_messages.fetch_add(1, Ordering::Relaxed);
                        limited!(
                            DEBUG,
                            notices,
                            ignored,
                            "N3 {} for unknown TEID {:#010x} from {from}",
                            packet.message_type,
                            packet.teid
                        );
                        continue;
                    }
                }
            }
            MessageType::ERROR_INDICATION => match routes.error_indication_session(&packet) {
                Some(key) => key,
                None => {
                    counters
                        .unmatched_error_indications
                        .fetch_add(1, Ordering::Relaxed);
                    limited!(
                        DEBUG,
                        notices,
                        error_indication,
                        "N3 Error Indication from {from} matches no tunnel"
                    );
                    continue;
                }
            },
            MessageType::ECHO_RESPONSE if paths.echo_response(&packet, from) => continue,
            MessageType::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION
                if paths.notification(&packet, from) =>
            {
                continue;
            }
            // An Echo Response that answers no request is a duplicate,
            // which TS 29.281 §11 discards.
            message_type => {
                counters.ignored_messages.fetch_add(1, Ordering::Relaxed);
                limited!(
                    DEBUG,
                    notices,
                    ignored,
                    "N3 ignored message type {message_type} from {from}"
                );
                continue;
            }
        };
        // A tunnel's IP packets go to its TUN, if it has one. A G-PDU
        // without a T-PDU has only its extension headers to give, such as
        // a frame of a RAN protocol: it goes to the receiver.
        #[cfg(all(target_os = "linux", feature = "tun"))]
        let tun = match packet.message_type {
            MessageType::G_PDU if !packet.payload.is_empty() => routes.tun(key),
            _ => None,
        };
        #[cfg(all(target_os = "linux", feature = "tun"))]
        if let Some(port) = tun {
            if let Err(error) = port.send(packet.payload).await {
                limited!(
                    DEBUG,
                    socket.notices(),
                    tun,
                    "N3 TUN {} write failed: {error}",
                    port.name()
                );
            }
            continue;
        }
        let (ran_id, session_id) = key;
        socket.observe(&tx, || ReceivedPacket {
            ran_id,
            session_id,
            packet: packet.into_owned(),
            from,
        });
    }
}

/// Send what Linux routes into a tunnel's TUN as the tunnel's uplink
/// G-PDUs, until the TUN closes.
#[cfg(all(target_os = "linux", feature = "tun"))]
async fn forward_tun(
    port: TunPort,
    socket: Arc<DatagramSocket>,
    routes: Arc<RouteTable>,
    key: SessionKey,
    #[cfg(fast_path)] fast_path: Option<N3FastPath>,
) {
    let mut packet = vec![0; 65535];
    #[cfg(fast_path)]
    let mut asking = Asking::default();
    loop {
        // At first, and when userspace carries a packet of a tunnel that
        // has no short-cut: have the kernel carry the next ones.
        #[cfg(fast_path)]
        if let Some(fast_path) = &fast_path {
            let now = std::time::Instant::now();
            if asking.due(now) && !fast_path.0.has_shortcut(port.index()) {
                let asked = shortcut(&routes, fast_path, key, port.index());
                if let Err(error) = &asked {
                    trace!("N3 TUN {} stays in userspace: {error}", port.name());
                }
                asking.answered(now, &asked);
            }
        }
        let Ok(length) = port.recv(&mut packet).await else {
            return;
        };
        let Some(route) = routes.route(key) else {
            return;
        };
        let uplink = route.uplink(&packet[..length]);
        if let Err(error) = socket.send(&uplink, route.remote.address).await {
            debug!("N3 TUN {} uplink failed: {error}", port.name());
        }
    }
}

/// When the reader of a TUN asks for the short-cut of its tunnel, which
/// has none: a route lookup under the lock of the tunnels. Not before an
/// interval after a failure: a millisecond while the tunnel's N3 interface
/// is getting its program, a second after another error, such as a tunnel
/// whose peer the fast path cannot reach. Once the tunnel has its
/// short-cut, the packets that userspace still carries, too long for N3 or
/// not IPv4, ask nothing.
#[cfg(fast_path)]
#[derive(Debug, Default)]
struct Asking {
    not_before: Option<std::time::Instant>,
}

#[cfg(fast_path)]
impl Asking {
    const ATTACHING: std::time::Duration = std::time::Duration::from_millis(1);
    const FAILED: std::time::Duration = std::time::Duration::from_secs(1);

    fn due(&self, now: std::time::Instant) -> bool {
        self.not_before.is_none_or(|not_before| now >= not_before)
    }

    fn answered(&mut self, now: std::time::Instant, answer: &io::Result<()>) {
        self.not_before = match answer {
            Ok(()) => None,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Some(now + Self::ATTACHING),
            Err(_) => Some(now + Self::FAILED),
        };
    }
}

/// Short-cut tunnel `key` through TUN interface `tun`, on a route that
/// cannot change or go away meanwhile.
#[cfg(fast_path)]
fn shortcut(
    routes: &RouteTable,
    (fast_path, local): &N3FastPath,
    key: SessionKey,
    tun: u32,
) -> io::Result<()> {
    routes
        .with_route(key, |route| {
            fast_path.shortcut(tun, *local, route.local_teid, route.remote, route.qfi)
        })
        .unwrap_or_else(|| Err(routes::no_tunnel(key)))
}

#[cfg(all(test, fast_path))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A TUN whose tunnel cannot be short-cut asks once a second, and not
    /// with each of its packets.
    #[test]
    fn a_tun_asks_for_its_short_cut_again_after_an_interval() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut asking = Asking::default();
        assert!(asking.due(start));
        // The N3 interface is getting its program.
        asking.answered(at(0), &Err(io::ErrorKind::WouldBlock.into()));
        assert!(!asking.due(at(0)));
        assert!(asking.due(at(1)));
        // The peer is not on the GTP-U port, or has no route.
        asking.answered(at(1), &Err(io::ErrorKind::Unsupported.into()));
        assert!(!asking.due(at(2)));
        assert!(!asking.due(at(1000)));
        assert!(asking.due(at(1001)));
        asking.answered(at(1001), &Ok(()));
        assert!(asking.due(at(1001)));
    }
}
