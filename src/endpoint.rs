//! The N3 endpoint of a gNB, or the S1-U endpoint of an eNB.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle};
use tracing::{debug, trace};

use crate::ReceiveStats;
use crate::datagram::DatagramSocket;
use crate::{END_MARKER, ERROR_INDICATION, G_PDU, Packet};

mod routes;
use routes::RouteTable;

/// Messages the receiver of [`Endpoint::bind`] can lag behind by before
/// newer ones are dropped.
const QUEUE: usize = 256;

/// The far end of a tunnel: the peer's GTP-U address and the TEID it
/// assigned (an F-TEID).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoteTunnel {
    /// The peer's address, normally on port [`PORT`](crate::PORT).
    pub address: SocketAddr,
    /// The TEID the peer receives the tunnel's packets on.
    pub teid: u32,
}

impl RemoteTunnel {
    /// The tunnel that the peer at `address` receives on `teid`.
    pub fn new(address: SocketAddr, teid: u32) -> Self {
        Self { address, teid }
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
    /// A G-PDU or End Marker on the tunnel's local TEID, or an Error
    /// Indication by which the peer reports that it no longer knows the
    /// tunnel's remote TEID.
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
/// tunnels' messages. As in TS 29.281, the TEID alone identifies a tunnel:
/// peers may send from another address than their F-TEID's. GTP-U has no
/// authentication, so whoever reaches the socket can send on a tunnel or
/// report an Error Indication for it. Clones share
/// the socket and tunnels; the task stops when the last clone is dropped.
/// Must be used within a Tokio runtime.
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
#[derive(Clone)]
pub struct Endpoint {
    shared: Arc<Shared>,
}

struct Shared {
    socket: Arc<DatagramSocket>,
    routes: Arc<RouteTable>,
    worker: AbortHandle,
    completion: tokio::sync::Mutex<Option<JoinHandle<io::Result<()>>>>,
    stopped: AtomicBool,
    /// With the N3 address.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fast_path: std::sync::OnceLock<(crate::ebpf::FastPath, std::net::Ipv4Addr)>,
}

impl Shared {
    /// Apply a tunnel's change, or its removal, to its short-cut.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn sync(&self, local_teid: u32, route: Option<(RemoteTunnel, Option<u8>)>) {
        if let Some((fast_path, local)) = self.fast_path.get() {
            fast_path.refresh(*local, local_teid, route);
        }
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    fn sync(&self, _local_teid: u32, _route: Option<(RemoteTunnel, Option<u8>)>) {}
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.worker.abort();
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        for local_teid in self.routes.local_teids() {
            self.sync(local_teid, None);
        }
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
        let (tx, rx) = mpsc::channel(QUEUE);
        let completion = tokio::spawn(receive(socket.clone(), routes.clone(), tx));
        let worker = completion.abort_handle();
        let shared = Shared {
            socket,
            routes,
            worker,
            completion: tokio::sync::Mutex::new(Some(completion)),
            stopped: AtomicBool::new(false),
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
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
    pub async fn shutdown(&self) -> io::Result<()> {
        self.shared.stopped.store(true, Ordering::Relaxed);
        self.shared.worker.abort();
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        for local_teid in self.shared.routes.local_teids() {
            self.shared.sync(local_teid, None);
        }
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

    /// Provision an explicitly assigned, nonzero local TEID. `qfi=None` selects
    /// S1-U framing. A TEID owned by another session is rejected; validation
    /// errors leave the existing route unchanged.
    pub fn install_with_teid(
        &self,
        ran_id: u32,
        session_id: u8,
        local_teid: u32,
        remote: RemoteTunnel,
        qfi: Option<u8>,
    ) -> io::Result<()> {
        let replaced = self.local_teid(ran_id, session_id);
        self.shared
            .routes
            .install_with_teid((ran_id, session_id), local_teid, remote, qfi)?;
        if let Some(replaced) = replaced.filter(|replaced| *replaced != local_teid) {
            self.shared.sync(replaced, None);
        }
        self.shared.sync(local_teid, Some((remote, qfi)));
        Ok(())
    }

    /// Give the endpoint, bound to an IPv4 address and the GTP-U port, its
    /// fast path: it then carries in the kernel the tunnels that
    /// [`shortcut`](Self::shortcut) gives a TUN, until they are removed or
    /// the endpoint is shut down.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
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
    /// [`FastPath::open`](crate::ebpf::FastPath::open) put on the fast path,
    /// and the peer. This lasts until the tunnel is removed, `tun` gets
    /// another tunnel, or [`FastPath::detach`](crate::ebpf::FastPath::detach)
    /// or [`close`](crate::ebpf::FastPath::close); later changes of the
    /// tunnel's remote end and QFI apply to it. It asks Linux for the route
    /// to the peer and writes two map entries.
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
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn shortcut(&self, ran_id: u32, session_id: u8, tun: u32) -> io::Result<()> {
        let (fast_path, local) = self.shared.fast_path.get().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "the endpoint has no fast path")
        })?;
        self.shared
            .routes
            .with_route((ran_id, session_id), |route| {
                fast_path.attach(tun, *local, route.local_teid, route.remote, route.qfi)
            })
            .unwrap_or_else(|| {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no tunnel for RAN UE {ran_id} session {session_id}"),
                ))
            })
    }

    /// Set up the tunnel of RAN UE `ran_id` and PDU session `session_id`
    /// toward `remote`, with uplink QoS flow `qfi` (0..=63), and return its
    /// local TEID. For an existing tunnel this updates the remote end and
    /// QFI and keeps the TEID.
    ///
    /// # Errors
    ///
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) if `qfi` is above 63:
    /// the tunnel then stays as it was.
    pub fn install(
        &self,
        ran_id: u32,
        session_id: u8,
        remote: RemoteTunnel,
        qfi: u8,
    ) -> io::Result<u32> {
        if qfi > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("QFI {qfi} is outside 0..=63"),
            ));
        }
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
        let local_teid = self
            .shared
            .routes
            .install((ran_id, session_id), remote, qfi);
        self.shared.sync(local_teid, Some((remote, qfi)));
        local_teid
    }

    /// The local TEID of a tunnel.
    pub fn local_teid(&self, ran_id: u32, session_id: u8) -> Option<u32> {
        self.shared
            .routes
            .route((ran_id, session_id))
            .map(|route| route.local_teid)
    }

    /// Remove a tunnel. Its G-PDUs then get an Error Indication.
    pub fn remove(&self, ran_id: u32, session_id: u8) {
        if let Some(local_teid) = self.shared.routes.remove((ran_id, session_id)) {
            self.shared.sync(local_teid, None);
        }
    }

    /// Remove every tunnel of RAN UE `ran_id`.
    pub fn remove_ran(&self, ran_id: u32) {
        for local_teid in self.shared.routes.remove_ran(ran_id) {
            self.shared.sync(local_teid, None);
        }
    }

    /// Send an owned or borrowed IP packet as an uplink G-PDU in a tunnel.
    pub async fn send<P: AsRef<[u8]>>(
        &self,
        ran_id: u32,
        session_id: u8,
        payload: P,
    ) -> io::Result<()> {
        let route = self
            .shared
            .routes
            .route((ran_id, session_id))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no tunnel for RAN UE {ran_id} session {session_id}"),
                )
            })?;
        let packet = match route.qfi {
            Some(qfi) => Packet::uplink(route.remote.teid, qfi, payload),
            None => Packet::g_pdu(route.remote.teid, payload),
        };
        self.send_to(&packet, route.remote.address).await
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
    tx: mpsc::Sender<ReceivedPacket>,
) -> io::Result<()> {
    let mut buffer = vec![0; 65536];
    loop {
        let Some((packet, from)) = socket.receive(&mut buffer).await? else {
            continue;
        };
        trace!(
            "N3 received type {} TEID {} ({} bytes) from {from}",
            packet.message_type,
            packet.teid,
            packet.payload.len()
        );
        let key = match packet.message_type {
            G_PDU | END_MARKER => {
                let found = routes.session(packet.teid);
                match found {
                    Some(key) => key,
                    None if packet.message_type == G_PDU => {
                        debug!("N3 G-PDU for unknown TEID {} from {from}", packet.teid);
                        socket.error_indication(packet.teid, from).await;
                        continue;
                    }
                    None => continue,
                }
            }
            ERROR_INDICATION => match routes.error_indication_session(&packet) {
                Some(key) => key,
                None => {
                    debug!("N3 Error Indication from {from} matches no tunnel");
                    continue;
                }
            },
            message_type => {
                debug!("N3 ignored message type {message_type} from {from}");
                continue;
            }
        };
        let (ran_id, session_id) = key;
        socket.observe(&tx, || ReceivedPacket {
            ran_id,
            session_id,
            packet: packet.into_owned(),
            from,
        });
    }
}
