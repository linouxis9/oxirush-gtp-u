//! A test UPF: an N3 peer whose sessions are provisioned directly, without
//! PFCP. Its N6 is a built-in echo service, or a Linux TUN per session.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tracing::{debug, warn};

use crate::path::{self, lock};
#[cfg(all(target_os = "linux", feature = "tun"))]
use crate::tun::{TunConfig, TunPort};
use crate::{ERROR_INDICATION, G_PDU, Packet, ipv4_icmp_echo_reply, ipv4_udp, parse_ipv4_udp};

/// The tunnels of one PDU session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Session {
    /// The TEID the UPF receives uplink G-PDUs on.
    pub uplink_teid: u32,
    /// The TEID the gNB receives downlink G-PDUs on.
    pub downlink_teid: u32,
    /// The gNB's N3 address.
    pub gnb_address: SocketAddr,
    /// The QoS flow of downlink G-PDUs, 0..=63.
    pub qfi: u8,
}

impl Session {
    /// A session with these tunnels.
    ///
    /// # Panics
    ///
    /// If `qfi` is above 63.
    pub fn new(uplink_teid: u32, downlink_teid: u32, gnb_address: SocketAddr, qfi: u8) -> Self {
        assert!(qfi <= 63, "QFI {qfi} is outside 0..=63");
        Self {
            uplink_teid,
            downlink_teid,
            gnb_address,
            qfi,
        }
    }
}

/// An uplink G-PDU of a session, as the UPF received it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UplinkPacket {
    /// The session's uplink TEID.
    pub uplink_teid: u32,
    /// The gNB address it came from, IPv4 rather than IPv4-mapped.
    pub from: SocketAddr,
    /// The G-PDU: its payload is the UE's IP packet.
    pub packet: Packet,
}

/// A test UPF on one N3 socket.
///
/// A task answers Echo Requests, sends an Error Indication for a G-PDU on
/// an unknown uplink TEID, and passes a session's uplink T-PDUs to N6: its
/// TUN if it has one, else the echo service, which reflects IPv4 UDP and
/// ICMP Echo Request packets. The TEID alone identifies a session, whatever
/// address the gNB sends from. Clones share the socket and sessions; the
/// task stops and the TUNs close when the last clone is dropped. Must be
/// used within a Tokio runtime.
#[derive(Clone)]
pub struct UpfSimulator {
    shared: Arc<Shared>,
}

struct Shared {
    socket: Arc<UdpSocket>,
    state: Arc<State>,
    ipv6: bool,
    worker: AbortHandle,
}

/// What the tasks share with the handles.
#[derive(Default)]
struct State {
    sessions: Mutex<HashMap<u32, Session>>,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    tuns: Mutex<HashMap<u32, TunAttachment>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.worker.abort();
        #[cfg(all(target_os = "linux", feature = "tun"))]
        drop(std::mem::take(&mut *lock(&self.state.tuns)));
    }
}

#[cfg(all(target_os = "linux", feature = "tun"))]
struct TunAttachment {
    port: Arc<TunPort>,
    task: AbortHandle,
}

#[cfg(all(target_os = "linux", feature = "tun"))]
impl Drop for TunAttachment {
    fn drop(&mut self) {
        self.task.abort();
        self.port.close();
    }
}

impl UpfSimulator {
    /// Bind the N3 socket to `address`. The receiver observes the sessions'
    /// uplink G-PDUs; it is best effort and never delays forwarding.
    ///
    /// Bind a specific address rather than a wildcard one: TS 29.281 §4.4.3
    /// has replies leave from the address the request reached, but from a
    /// wildcard socket they leave from the address the kernel picks, which
    /// an Error Indication also names.
    pub async fn bind(address: SocketAddr) -> io::Result<(Self, mpsc::Receiver<UplinkPacket>)> {
        let socket = Arc::new(UdpSocket::bind(address).await?);
        let ipv6 = socket.local_addr()?.is_ipv6();
        let state = Arc::new(State::default());
        let (tx, rx) = mpsc::channel(256);
        let worker = tokio::spawn(receive(socket.clone(), state.clone(), ipv6, tx)).abort_handle();
        let shared = Shared {
            socket,
            state,
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

    /// Add a session, or replace the one with the same uplink TEID.
    pub fn set_session(&self, session: Session) {
        lock(&self.shared.state.sessions).insert(session.uplink_teid, session);
    }

    /// Move a session's downlink to `downlink_teid` at `gnb_address`, as
    /// after a handover, and send an End Marker on the old path (TS 23.502
    /// §4.9.1.2.2).
    pub async fn switch_downlink(
        &self,
        uplink_teid: u32,
        gnb_address: SocketAddr,
        downlink_teid: u32,
    ) -> io::Result<()> {
        let old = {
            let mut sessions = lock(&self.shared.state.sessions);
            let session = sessions
                .get_mut(&uplink_teid)
                .ok_or_else(|| unknown_session(uplink_teid))?;
            let old = *session;
            session.gnb_address = gnb_address;
            session.downlink_teid = downlink_teid;
            old
        };
        let old_path = (path::canonical(old.gnb_address), old.downlink_teid);
        if old_path == (path::canonical(gnb_address), downlink_teid) {
            return Ok(());
        }
        let marker = Packet::end_marker(old.downlink_teid)
            .encode()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let to = path::destination(self.shared.ipv6, old.gnb_address);
        self.shared.socket.send_to(&marker, to).await?;
        Ok(())
    }

    /// Remove a session and close its TUN.
    pub fn remove_session(&self, uplink_teid: u32) {
        lock(&self.shared.state.sessions).remove(&uplink_teid);
        #[cfg(all(target_os = "linux", feature = "tun"))]
        {
            // Closed here, after the lock is released.
            let _attachment = lock(&self.shared.state.tuns).remove(&uplink_teid);
        }
    }

    /// Give a session a Linux TUN as N6: its uplink T-PDUs go to Linux, and
    /// what Linux routes to the TUN comes back as downlink G-PDUs.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub fn attach_tun(&self, uplink_teid: u32, config: TunConfig) -> io::Result<()> {
        if !lock(&self.shared.state.sessions).contains_key(&uplink_teid) {
            return Err(unknown_session(uplink_teid));
        }
        let already_attached = || {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("a TUN is already attached to uplink TEID {uplink_teid}"),
            )
        };
        if lock(&self.shared.state.tuns).contains_key(&uplink_teid) {
            return Err(already_attached());
        }
        let port = Arc::new(TunPort::create(config)?);
        let task = tokio::spawn(forward_tun_downlink(
            port.clone(),
            self.shared.socket.clone(),
            self.shared.state.clone(),
            self.shared.ipv6,
            uplink_teid,
        ))
        .abort_handle();
        let attachment = TunAttachment { port, task };
        let mut tuns = lock(&self.shared.state.tuns);
        if tuns.contains_key(&uplink_teid) {
            drop(tuns);
            drop(attachment);
            return Err(already_attached());
        }
        tuns.insert(uplink_teid, attachment);
        Ok(())
    }

    /// Send `packet`, an IP packet, to a session's UE as a downlink G-PDU.
    pub async fn send_downlink(&self, uplink_teid: u32, packet: Vec<u8>) -> io::Result<()> {
        let session = lock(&self.shared.state.sessions)
            .get(&uplink_teid)
            .copied()
            .ok_or_else(|| unknown_session(uplink_teid))?;
        send_downlink(&self.shared.socket, self.shared.ipv6, &session, packet).await
    }
}

impl fmt::Debug for UpfSimulator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpfSimulator")
            .field("local_addr", &self.local_addr().ok())
            .field("sessions", &lock(&self.shared.state.sessions).len())
            .finish()
    }
}

fn unknown_session(uplink_teid: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no session with uplink TEID {uplink_teid}"),
    )
}

async fn send_downlink(
    socket: &UdpSocket,
    ipv6: bool,
    session: &Session,
    packet: Vec<u8>,
) -> io::Result<()> {
    let bytes = Packet::downlink(session.downlink_teid, session.qfi, packet)
        .encode()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    socket
        .send_to(&bytes, path::destination(ipv6, session.gnb_address))
        .await?;
    Ok(())
}

/// The echo service's reply to an uplink T-PDU, if it answers it.
fn echo_service(packet: &[u8]) -> Option<Vec<u8>> {
    if let Ok((source, destination, payload)) = parse_ipv4_udp(packet) {
        return ipv4_udp(destination, source, payload).ok();
    }
    ipv4_icmp_echo_reply(packet).ok()
}

async fn receive(
    socket: Arc<UdpSocket>,
    state: Arc<State>,
    ipv6: bool,
    tx: mpsc::Sender<UplinkPacket>,
) {
    let mut buffer = vec![0; 65536];
    loop {
        let (size, from) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) if path::transient(&error) => continue,
            Err(error) => {
                warn!("UPF simulator stopped receiving: {error}");
                return;
            }
        };
        let packet = match Packet::decode(&buffer[..size]) {
            Ok(packet) => packet,
            Err(error) => {
                debug!("UPF dropped a malformed message from {from}: {error}");
                continue;
            }
        };
        if path::answer(&socket, &packet, from).await {
            continue;
        }
        match packet.message_type {
            G_PDU => {}
            ERROR_INDICATION => {
                debug!(
                    "UPF got an Error Indication from {from}: {:?}",
                    packet.information_elements()
                );
                continue;
            }
            message_type => {
                debug!("UPF ignored message type {message_type} from {from}");
                continue;
            }
        }
        let session = lock(&state.sessions).get(&packet.teid).copied();
        let Some(session) = session else {
            debug!("UPF G-PDU for unknown TEID {} from {from}", packet.teid);
            path::error_indication(&socket, packet.teid, from).await;
            continue;
        };
        if !write_to_tun(&state, packet.teid, &packet.payload).await {
            if let Some(reply) = echo_service(&packet.payload) {
                if let Err(error) = send_downlink(&socket, ipv6, &session, reply).await {
                    debug!("UPF echo reply to {} failed: {error}", session.gnb_address);
                }
            }
        }
        let _ = tx.try_send(UplinkPacket {
            uplink_teid: packet.teid,
            from: path::canonical(from),
            packet,
        });
    }
}

/// Write an uplink T-PDU to its session's TUN; false if it has none.
#[cfg(all(target_os = "linux", feature = "tun"))]
async fn write_to_tun(state: &State, uplink_teid: u32, packet: &[u8]) -> bool {
    let port = lock(&state.tuns)
        .get(&uplink_teid)
        .map(|attachment| attachment.port.clone());
    let Some(port) = port else {
        return false;
    };
    if let Err(error) = port.send(packet).await {
        warn!("UPF TUN {} write failed: {error}", port.name());
    }
    true
}

#[cfg(not(all(target_os = "linux", feature = "tun")))]
async fn write_to_tun(_state: &State, _uplink_teid: u32, _packet: &[u8]) -> bool {
    false
}

/// Send what Linux routes to a session's TUN as downlink G-PDUs.
#[cfg(all(target_os = "linux", feature = "tun"))]
async fn forward_tun_downlink(
    port: Arc<TunPort>,
    socket: Arc<UdpSocket>,
    state: Arc<State>,
    ipv6: bool,
    uplink_teid: u32,
) {
    let mut buffer = vec![0; 65536];
    loop {
        let size = match port.recv(&mut buffer).await {
            Ok(size) => size,
            Err(error) => {
                warn!("UPF TUN {} read failed: {error}", port.name());
                return;
            }
        };
        let session = lock(&state.sessions).get(&uplink_teid).copied();
        let Some(session) = session else {
            return;
        };
        if let Err(error) = send_downlink(&socket, ipv6, &session, buffer[..size].to_vec()).await {
            warn!("UPF TUN {} downlink failed: {error}", port.name());
        }
    }
}
