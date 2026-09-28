//! The N3 endpoint of a gNB, or the S1-U endpoint of an eNB.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::AbortHandle;
use tracing::{debug, trace, warn};

use crate::path::{self, lock, same_ip};
use crate::{END_MARKER, ERROR_INDICATION, G_PDU, InformationElement, Packet};

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
/// let tunnel = |address, teid| RemoteTunnel { address, teid };
/// let peer_teid = peer.install(1, 5, tunnel(gnb.local_addr()?, 0), 9);
/// let gnb_teid = gnb.install(1, 5, tunnel(peer.local_addr()?, peer_teid), 9);
/// peer.install(1, 5, tunnel(gnb.local_addr()?, gnb_teid), 9);
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
    socket: Arc<UdpSocket>,
    routes: Arc<Mutex<Routes>>,
    ipv6: bool,
    worker: AbortHandle,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

#[derive(Clone, Copy)]
struct Route {
    local_teid: u32,
    remote: RemoteTunnel,
    /// The uplink QoS flow of an N3 tunnel; S1-U tunnels have none.
    qfi: Option<u8>,
}

#[derive(Default)]
struct Routes {
    by_session: HashMap<(u32, u8), Route>,
    by_teid: HashMap<u32, (u32, u8)>,
    last_teid: u32,
}

impl Routes {
    /// The next TEID after the last one that is neither 0 nor in use.
    fn allocate_teid(&mut self) -> u32 {
        loop {
            self.last_teid = self.last_teid.wrapping_add(1);
            if self.last_teid != 0 && !self.by_teid.contains_key(&self.last_teid) {
                return self.last_teid;
            }
        }
    }

    fn remove(&mut self, key: (u32, u8)) {
        if let Some(route) = self.by_session.remove(&key) {
            self.by_teid.remove(&route.local_teid);
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
    /// On `[::]` the socket also serves IPv4 peers where IPv6 sockets are
    /// dual-stack, as on Linux, but not on Windows.
    ///
    /// Bind a specific address rather than a wildcard one: TS 29.281 §4.4.3
    /// has replies leave from the address the request reached, but from a
    /// wildcard socket they leave from the address the kernel picks, which
    /// an Error Indication also names.
    pub async fn bind(address: SocketAddr) -> io::Result<(Self, mpsc::Receiver<ReceivedPacket>)> {
        let socket = Arc::new(UdpSocket::bind(address).await?);
        let ipv6 = socket.local_addr()?.is_ipv6();
        let routes = Arc::new(Mutex::new(Routes::default()));
        let (tx, rx) = mpsc::channel(QUEUE);
        let worker = tokio::spawn(receive(socket.clone(), routes.clone(), tx)).abort_handle();
        let shared = Shared {
            socket,
            routes,
            ipv6,
            worker,
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

    /// Set up the tunnel of RAN UE `ran_id` and PDU session `session_id`
    /// toward `remote`, with uplink QoS flow `qfi` (0..=63), and return its
    /// local TEID. For an existing tunnel this updates the remote end and
    /// QFI and keeps the TEID.
    ///
    /// # Panics
    ///
    /// If `qfi` is above 63.
    pub fn install(&self, ran_id: u32, session_id: u8, remote: RemoteTunnel, qfi: u8) -> u32 {
        assert!(qfi <= 63, "QFI {qfi} is outside 0..=63");
        self.install_route(ran_id, session_id, remote, Some(qfi))
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
        let mut routes = lock(&self.shared.routes);
        if let Some(route) = routes.by_session.get_mut(&(ran_id, session_id)) {
            route.remote = remote;
            route.qfi = qfi;
            return route.local_teid;
        }
        let local_teid = routes.allocate_teid();
        routes.by_session.insert(
            (ran_id, session_id),
            Route {
                local_teid,
                remote,
                qfi,
            },
        );
        routes.by_teid.insert(local_teid, (ran_id, session_id));
        local_teid
    }

    /// The local TEID of a tunnel.
    pub fn local_teid(&self, ran_id: u32, session_id: u8) -> Option<u32> {
        lock(&self.shared.routes)
            .by_session
            .get(&(ran_id, session_id))
            .map(|route| route.local_teid)
    }

    /// Remove a tunnel. Its G-PDUs then get an Error Indication.
    pub fn remove(&self, ran_id: u32, session_id: u8) {
        lock(&self.shared.routes).remove((ran_id, session_id));
    }

    /// Remove every tunnel of RAN UE `ran_id`.
    pub fn remove_ran(&self, ran_id: u32) {
        let mut routes = lock(&self.shared.routes);
        let keys: Vec<_> = routes
            .by_session
            .keys()
            .filter(|(ran, _)| *ran == ran_id)
            .copied()
            .collect();
        for key in keys {
            routes.remove(key);
        }
    }

    /// Send `payload`, an IP packet, as an uplink G-PDU in a tunnel.
    pub async fn send(&self, ran_id: u32, session_id: u8, payload: Vec<u8>) -> io::Result<()> {
        let route = lock(&self.shared.routes)
            .by_session
            .get(&(ran_id, session_id))
            .copied()
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
        let bytes = packet
            .encode()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let to = path::destination(self.shared.ipv6, route.remote.address);
        self.shared.socket.send_to(&bytes, to).await?;
        Ok(())
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("local_addr", &self.local_addr().ok())
            .field("tunnels", &lock(&self.shared.routes).by_session.len())
            .finish()
    }
}

async fn receive(
    socket: Arc<UdpSocket>,
    routes: Arc<Mutex<Routes>>,
    tx: mpsc::Sender<ReceivedPacket>,
) {
    let mut buffer = vec![0; 65536];
    loop {
        let (size, from) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) if path::transient(&error) => continue,
            Err(error) => {
                warn!("N3 endpoint stopped receiving: {error}");
                return;
            }
        };
        let packet = match Packet::decode(&buffer[..size]) {
            Ok(packet) => packet,
            Err(error) => {
                debug!("N3 dropped a malformed message from {from}: {error}");
                continue;
            }
        };
        trace!(
            "N3 received type {} TEID {} ({} bytes) from {from}",
            packet.message_type,
            packet.teid,
            packet.payload.len()
        );
        if path::answer(&socket, &packet, from).await {
            continue;
        }
        let key = match packet.message_type {
            G_PDU | END_MARKER => {
                let found = lock(&routes).by_teid.get(&packet.teid).copied();
                match found {
                    Some(key) => key,
                    None if packet.message_type == G_PDU => {
                        debug!("N3 G-PDU for unknown TEID {} from {from}", packet.teid);
                        path::error_indication(&socket, packet.teid, from).await;
                        continue;
                    }
                    None => continue,
                }
            }
            ERROR_INDICATION => match error_indication_tunnel(&routes, &packet) {
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
        let received = ReceivedPacket {
            ran_id,
            session_id,
            packet,
            from: path::canonical(from),
        };
        if let Err(TrySendError::Full(_)) = tx.try_send(received) {
            debug!(
                "N3 receiver lagging: dropped a message of RAN UE {ran_id} session {session_id}"
            );
        }
    }
}

/// The tunnel whose remote end an Error Indication names.
fn error_indication_tunnel(routes: &Mutex<Routes>, packet: &Packet) -> Option<(u32, u8)> {
    let elements = packet.information_elements().ok()?;
    let teid = elements.iter().find_map(|element| match element {
        InformationElement::TeidDataI(teid) => Some(*teid),
        _ => None,
    })?;
    let peer = elements.iter().find_map(|element| match element {
        InformationElement::GtpUPeerAddress(address) => Some(*address),
        _ => None,
    })?;
    lock(routes)
        .by_session
        .iter()
        .find(|(_, route)| route.remote.teid == teid && same_ip(route.remote.address.ip(), peer))
        .map(|(key, _)| *key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teid_allocation_skips_zero_and_live_teids() {
        let mut routes = Routes {
            last_teid: u32::MAX - 2,
            ..Routes::default()
        };
        routes.by_teid.insert(u32::MAX, (1, 1));
        routes.by_teid.insert(1, (1, 2));
        assert_eq!(routes.allocate_teid(), u32::MAX - 1);
        assert_eq!(routes.allocate_teid(), 2);
    }
}
