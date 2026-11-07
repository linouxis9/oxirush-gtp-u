//! The N3 endpoint of a gNB, or the S1-U endpoint of an eNB.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};
use tokio::task::{AbortHandle, JoinHandle};
use tracing::{debug, trace};

use crate::ReceiveStats;
use crate::datagram::DatagramSocket;
#[cfg(all(target_os = "linux", feature = "tun"))]
use crate::tun::{TunConfig, TunPort};
use crate::types::Teid;
use crate::{MessageType, Packet};

mod paths;
use paths::Paths;
pub use paths::{PathEvent, PathState, PathTimers};
mod routes;
use routes::RouteTable;
#[cfg(all(target_os = "linux", feature = "tun"))]
use routes::{SessionKey, TunAttachment};

/// Messages the receiver of [`Endpoint::bind`] can lag behind by before
/// newer ones are dropped.
const QUEUE: usize = 256;

/// The far end of a tunnel: the peer's GTP-U address and the TEID it
/// assigned (an F-TEID). `Debug` prints the TEID in hexadecimal.
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use oxirush_gtp_u::{Endpoint, RemoteTunnel};
///
/// // The UPF's end of PDU session 5 of RAN UE 1: the address and the TEID of
/// // the UL NG-U UP TNL Information that NGAP carries
/// let upf = RemoteTunnel::new("192.0.2.8:2152".parse()?, 0x1001);
///
/// // The gNB sends the session's uplink there, and receives its downlink on
/// // the TEID that it assigns
/// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse()?).await?;
/// let teid = gnb.install(1, 5, upf, Some(9))?;
/// assert_eq!(gnb.local_teid(1, 5), Some(teid));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use oxirush_gtp_u::{Endpoint, RemoteTunnel};
///
/// // Two endpoints with a tunnel between them
/// let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse()?).await?;
/// let (peer, mut received) = Endpoint::bind("127.0.0.1:0".parse()?).await?;
/// let peer_teid = peer.install(1, 5, RemoteTunnel::new(gnb.local_addr()?, 0), Some(9))?;
/// gnb.install(1, 5, RemoteTunnel::new(peer.local_addr()?, peer_teid), Some(9))?;
///
/// // A G-PDU comes with the tunnel that it was sent on
/// gnb.send(1, 5, b"an IP packet".as_slice()).await?;
/// let message = received.recv().await.expect("the endpoint is running");
/// assert_eq!((message.ran_id, message.session_id), (1, 5));
/// assert_eq!(message.packet.qfi(), Some(9));
/// assert_eq!(message.packet.payload, b"an IP packet");
/// assert_eq!(message.from, gnb.local_addr()?);
/// # Ok(())
/// # }
/// ```
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
/// eNB's S1-U tunnels, identified by the eNB UE S1AP ID and E-RAB ID. Clones
/// share the socket and tunnels; its task stops when the last clone is
/// dropped, or at [`shutdown`](Self::shutdown). Must be used within a Tokio
/// runtime.
///
/// ```
/// use oxirush_gtp_u::{Endpoint, RemoteTunnel};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> std::io::Result<()> {
/// let (gnb, _) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
/// let (peer, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
/// // Each side assigns the TEID it receives on; the other sends to it.
/// let peer_teid = peer.install(1, 5, RemoteTunnel::new(gnb.local_addr()?, 0), Some(9))?;
/// let gnb_teid = gnb.install(1, 5, RemoteTunnel::new(peer.local_addr()?, peer_teid), Some(9))?;
/// peer.install(1, 5, RemoteTunnel::new(gnb.local_addr()?, gnb_teid), Some(9))?;
///
/// gnb.send(1, 5, b"an IP packet".to_vec()).await?;
/// let packet = received.recv().await.unwrap();
/// assert_eq!((packet.ran_id, packet.session_id), (1, 5));
/// assert_eq!(packet.packet.qfi(), Some(9));
/// # Ok(())
/// # }
/// ```
///
/// - [`install`](Self::install) and [`install_with_teid`](Self::install_with_teid)
///   set up a tunnel, [`remove`](Self::remove) and
///   [`remove_ran`](Self::remove_ran) remove tunnels.
/// - [`send`](Self::send) sends an IP packet in a tunnel, and
///   [`send_to`](Self::send_to) any message; the receiver of
///   [`bind`](Self::bind) gets the tunnels' messages.
/// - `attach_tun` gives a tunnel a TUN, on Linux with the `tun` feature.
/// - [`echo`](Self::echo), [`supervise`](Self::supervise) and
///   [`path_events`](Self::path_events) follow the paths to the peers
///   (TS 29.281 §7.2, §11, TS 23.007 §20.3.1).
///
/// The task sends by itself the replies that TS 29.281 §7 asks of every
/// GTP-U node: it answers Echo Requests, sends an Error Indication for a
/// G-PDU on an unknown TEID, and a Supported Extension Headers Notification
/// for an extension header that it must understand and does not, the last
/// two to port 2152. A slow receiver never delays them. As in TS 29.281, the
/// TEID alone identifies a tunnel, and GTP-U has no authentication: whoever
/// reaches the socket can send on a tunnel, or cause these replies from any
/// address. The socket sends 1,000 of them a second at most, after a burst
/// of 1,000; past that a reply is not sent and is counted in
/// [`suppressed_replies`](ReceiveStats::suppressed_replies), and one flooding
/// peer can use up the replies owed to the others. What a peer causes is
/// logged at the `debug` level.
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
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.worker.abort();
        self.paths.end_supervisions();
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
    ///
    /// ```
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use oxirush_gtp_u::Endpoint;
    ///
    /// // A specific address: a gNB binds port 2152 of its N3 address
    /// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse()?).await?;
    /// assert!(gnb.is_running());
    ///
    /// // A wildcard address is refused
    /// let wildcard = Endpoint::bind("0.0.0.0:0".parse()?).await;
    /// let kind = wildcard.err().map(|error| error.kind());
    /// assert_eq!(kind, Some(std::io::ErrorKind::InvalidInput));
    /// # Ok(())
    /// # }
    /// ```
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

    /// Send any message from this endpoint's socket, with its sequence number
    /// and extension headers, without a tunnel. The response to an Echo
    /// Request that it sends is not awaited: [`echo`](Self::echo) sends one
    /// and waits for its response.
    ///
    /// # Errors
    ///
    /// [`BrokenPipe`](io::ErrorKind::BrokenPipe) once the endpoint is shut
    /// down.
    pub async fn send_to<P: AsRef<[u8]>>(
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

    /// Set up a tunnel as [`install`](Self::install) does, with a nonzero
    /// local TEID that something else assigned. A TEID owned by another
    /// session is rejected; validation errors leave the existing route
    /// unchanged. A local TEID of 0 and a QFI
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
        self.shared
            .routes
            .install_with_teid((ran_id, session_id), local_teid, remote, qfi)
    }

    /// Set up the tunnel of RAN UE `ran_id` and PDU session `session_id`
    /// toward `remote`, with uplink QoS flow `qfi` (0..=63), and return its
    /// local TEID. For an existing tunnel this updates the remote end and
    /// QFI and keeps the TEID. The S1-U tunnel of an eNB UE and E-RAB has no
    /// QFI: its uplink G-PDUs carry no PDU Session Container.
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
    /// let teid = gnb.install(1, 5, RemoteTunnel::new(upf, 0x1001), Some(9))?;
    ///
    /// // The UPF moves the session to another TEID: the local one stays
    /// assert_eq!(gnb.install(1, 5, RemoteTunnel::new(upf, 0x2002), Some(9))?, teid);
    ///
    /// // A QFI has six bits
    /// let refused = gnb.install(1, 5, RemoteTunnel::new(upf, 0x2002), Some(64)).unwrap_err();
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
        qfi: Option<u8>,
    ) -> io::Result<u32> {
        if let Some(qfi) = qfi {
            crate::path::qfi(qfi)?;
        }
        Ok(self
            .shared
            .routes
            .install((ran_id, session_id), remote, qfi))
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
    /// It returns the TUN's interface index, which
    /// [`FastPath`](crate::ebpf::FastPath) takes to carry the tunnel in the
    /// kernel.
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
    ///   [`TunPort::create`].
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub fn attach_tun(&self, ran_id: u32, session_id: u8, config: TunConfig) -> io::Result<u32> {
        if !self.is_running() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let key = (ran_id, session_id);
        self.shared.routes.tun_slot(key)?;
        let port = TunPort::create(config)?;
        let index = port.index();
        let reader = tokio::spawn(forward_tun(
            port.clone(),
            self.shared.socket.clone(),
            self.shared.routes.clone(),
            key,
        ));
        // Unless the tunnel went away or got a TUN meanwhile.
        self.shared
            .routes
            .attach_tun(key, TunAttachment { port, reader })?;
        Ok(index)
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
        self.shared.routes.remove((ran_id, session_id));
    }

    /// Remove every tunnel of RAN UE `ran_id`, as [`remove`](Self::remove)
    /// does.
    pub fn remove_ran(&self, ran_id: u32) {
        self.shared.routes.remove_ran(ran_id);
    }

    /// Send an owned or borrowed IP packet as an uplink G-PDU in a tunnel.
    ///
    /// ```
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> std::io::Result<()> {
    /// use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    /// use oxirush_gtp_u::{Endpoint, RemoteTunnel, ip};
    ///
    /// let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
    /// let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;
    /// let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), Some(9))?;
    /// upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;
    ///
    /// // An IP packet of the UE in the tunnel of RAN UE 1, PDU session 5
    /// let (ue, server) = ("10.45.0.2:4000".parse().unwrap(), "192.0.2.1:7".parse().unwrap());
    /// gnb.send(1, 5, ip::udp(ue, server, b"hello")?).await?;
    /// let uplink = observed.recv().await.unwrap();
    /// assert_eq!((uplink.uplink_teid, uplink.packet.qfi()), (0x1001, Some(9)));
    ///
    /// // A session without a tunnel
    /// let missing = gnb.send(2, 1, ip::udp(ue, server, b"hello")?).await.unwrap_err();
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
        self.send_to(&route.uplink(payload), route.remote.address)
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
        let counters = socket.counters();
        let key = match packet.message_type {
            MessageType::G_PDU | MessageType::END_MARKER | MessageType::TUNNEL_STATUS => {
                let found = routes.session(packet.teid);
                match found {
                    Some(key) => key,
                    None if packet.message_type == MessageType::G_PDU => {
                        debug!(
                            "N3 G-PDU for unknown TEID {:#010x} from {from}",
                            packet.teid
                        );
                        socket.unknown_teid(packet.teid, from).await;
                        continue;
                    }
                    // TS 29.281 §7.3.2.1 and §7.3.3: ignored.
                    None => {
                        counters.ignored_messages.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            "N3 {} for unknown TEID {:#010x} from {from}",
                            packet.message_type, packet.teid
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
                    debug!("N3 Error Indication from {from} matches no tunnel");
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
                debug!("N3 ignored message type {message_type} from {from}");
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
                debug!("N3 TUN {} write failed: {error}", port.name());
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
) {
    let mut packet = vec![0; 65535];
    loop {
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
