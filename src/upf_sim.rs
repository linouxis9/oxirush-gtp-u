//! A test UPF: an N3 peer whose sessions are provisioned directly, without
//! PFCP. Its N6 is a built-in echo service, or a Linux TUN per session.
//! [`UpfSimulator`] is an N3 peer whose sessions are set with
//! [`set_session`](UpfSimulator::set_session). Uplink packets go to the echo
//! service, which reflects IPv4 UDP and answers ICMP Echo Requests, or to the
//! TUN that `attach_tun` gives the session.
//! [`set_echo_service`](UpfSimulator::set_echo_service) turns the echo
//! service off, for a program that answers the UE itself.
//! [`send_downlink`](UpfSimulator::send_downlink) sends a packet to the UE.
//! The receiver of [`bind`](UpfSimulator::bind) observes the uplink G-PDUs.
//!
//! [`switch_downlink`](UpfSimulator::switch_downlink) moves a session's
//! downlink to another gNB address and TEID and sends an End Marker on the old
//! path.
//!
//! The `oxirush-upf-sim` program, of the `cli` feature, serves one session
//! until Ctrl-C or SIGTERM. Its arguments are the UPF's N3 address, the
//! gNB's N3 address, the uplink TEID, the downlink TEID, decimal or
//! hexadecimal after `0x`, and the QFI, then
//! `--tun <name> <UE address>` for a TUN as N6 in the place of the echo
//! service.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle};
use tracing::{debug, warn};

use crate::datagram::DatagramSocket;
use crate::path::{self, lock};
#[cfg(all(target_os = "linux", feature = "tun"))]
use crate::tun::{TunConfig, TunPort};
use crate::types::Teid;
use crate::{MessageType, Packet, ReceiveStats, icmp, ip};

/// The tunnels of one PDU session. `Debug` prints the TEIDs in hexadecimal.
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> std::io::Result<()> {
/// use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
///
/// let (upf, _observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
///
/// // The UPF receives the uplink on TEID 0x1001, and sends the downlink to the
/// // gNB at its N3 address on TEID 0x2002, in QoS flow 9
/// let gnb = "127.0.0.1:2152".parse().unwrap();
/// let session = Session::new(0x1001, 0x2002, gnb, 9);
/// upf.set_session(session)?;
/// assert_eq!(
///     format!("{session:?}"),
///     "Session { uplink_teid: 0x00001001, downlink_teid: 0x00002002, \
///      gnb_address: 127.0.0.1:2152, qfi: 9 }"
/// );
///
/// // A QFI has six bits
/// assert!(upf.set_session(Session::new(0x1001, 0x2002, gnb, 64)).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
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
    /// A session with these tunnels. A QFI above 63 is refused where the
    /// session is given to a UPF,
    /// [`set_session`](UpfSimulator::set_session).
    pub fn new(uplink_teid: u32, downlink_teid: u32, gnb_address: SocketAddr, qfi: u8) -> Self {
        Self {
            uplink_teid,
            downlink_teid,
            gnb_address,
            qfi,
        }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("uplink_teid", &Teid(self.uplink_teid))
            .field("downlink_teid", &Teid(self.downlink_teid))
            .field("gnb_address", &self.gnb_address)
            .field("qfi", &self.qfi)
            .finish()
    }
}

/// An uplink G-PDU of a session, as the UPF received it.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UplinkPacket {
    /// The session's uplink TEID.
    pub uplink_teid: u32,
    /// The gNB address it came from, IPv4 rather than IPv4-mapped.
    pub from: SocketAddr,
    /// The G-PDU: its payload is the UE's IP packet.
    pub packet: Packet,
}

impl fmt::Debug for UplinkPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UplinkPacket")
            .field("uplink_teid", &Teid(self.uplink_teid))
            .field("from", &self.from)
            .field("packet", &self.packet)
            .finish()
    }
}

/// A test UPF on one N3 socket.
///
/// A task answers Echo Requests, sends an Error Indication for a G-PDU on
/// an unknown uplink TEID, within the limit of replies of an
/// [`Endpoint`](crate::Endpoint), and passes a session's uplink T-PDUs to
/// N6: its TUN if it has one, else the echo service, which reflects IPv4
/// UDP and ICMP Echo Request packets, unless
/// [`set_echo_service`](Self::set_echo_service) turned it off. The TEID
/// alone identifies a session, whatever address the gNB sends from. Clones
/// share the socket and sessions; the task stops and the TUNs close when the
/// last clone is dropped. Must be used within a Tokio runtime.
///
/// Downlink sends and path switches of a session are not ordered with each
/// other: a program that needs a send to come before or after an End Marker
/// waits for one call before it makes the other.
///
/// ```
/// use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
/// use oxirush_gtp_u::{Packet, ip};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> std::io::Result<()> {
/// let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
/// // The gNB under test: here a socket that sends and receives G-PDUs.
/// let gnb = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
/// upf.set_session(Session::new(0x1001, 0x2001, gnb.local_addr()?, 9))?;
///
/// let (ue, server) = ("10.45.0.2:4000".parse().unwrap(), "192.0.2.1:7".parse().unwrap());
/// let uplink = Packet::uplink(0x1001, 9, ip::udp(ue, server, b"hello")?);
/// gnb.send_to(&uplink.encode()?, upf.local_addr()?).await?;
/// assert_eq!(observed.recv().await.unwrap().packet, uplink);
///
/// // The echo service answers on the session's downlink tunnel.
/// let mut datagram = [0; 128];
/// let length = gnb.recv(&mut datagram).await?;
/// let downlink = Packet::decode(&datagram[..length])?;
/// assert_eq!((downlink.teid, downlink.qfi()), (0x2001, Some(9)));
/// assert_eq!(ip::parse_udp(&downlink.payload)?, (server, ue, b"hello".as_slice()));
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct UpfSimulator {
    shared: Arc<Shared>,
}

struct Shared {
    socket: Arc<DatagramSocket>,
    sessions: Arc<Sessions>,
    worker: AbortHandle,
    receiver: tokio::sync::Mutex<Option<JoinHandle<io::Result<()>>>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.sessions.stop();
        self.worker.abort();
    }
}

/// The sessions by uplink TEID, with their TUNs.
#[derive(Default)]
struct Sessions {
    entries: Mutex<HashMap<u32, Entry>>,
    stopped: AtomicBool,
    /// Whether a session without a TUN has no echo service.
    no_echo: AtomicBool,
}

struct Entry {
    session: Session,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    tun: Option<TunAttachment>,
}

/// A session's TUN and the task that reads it. Dropping it closes the TUN.
#[cfg(all(target_os = "linux", feature = "tun"))]
struct TunAttachment {
    port: TunPort,
    task: JoinHandle<()>,
}

#[cfg(all(target_os = "linux", feature = "tun"))]
impl Drop for TunAttachment {
    fn drop(&mut self) {
        self.task.abort();
        if let Err(error) = self.port.close() {
            tracing::warn!("{error}");
        }
    }
}

impl Sessions {
    /// Stop, and close the TUNs: they go once the lock is released, as
    /// closing one is netlink I/O.
    fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        let _entries = std::mem::take(&mut *lock(&self.entries));
    }

    fn get(&self, uplink_teid: u32) -> io::Result<Session> {
        if self.stopped.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        lock(&self.entries)
            .get(&uplink_teid)
            .map(|entry| entry.session)
            .ok_or_else(|| unknown_session(uplink_teid))
    }

    /// The TUN of session `uplink_teid`, if it has one.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    fn tun(&self, uplink_teid: u32) -> Option<TunPort> {
        lock(&self.entries)
            .get(&uplink_teid)?
            .tun
            .as_ref()
            .map(|tun| tun.port.clone())
    }
}

fn unknown_session(uplink_teid: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no session with uplink TEID {uplink_teid:#010x}"),
    )
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "UPF simulator has stopped")
}

impl UpfSimulator {
    /// Bind the N3 socket to `address`. The receiver observes the sessions'
    /// uplink G-PDUs; it is best effort and never delays forwarding.
    ///
    /// The address must be specific, so replies leave from the address
    /// the request reached (TS 29.281 §4.4.3). Wildcard addresses return
    /// [`InvalidInput`](io::ErrorKind::InvalidInput).
    pub async fn bind(address: SocketAddr) -> io::Result<(Self, mpsc::Receiver<UplinkPacket>)> {
        let socket = Arc::new(DatagramSocket::bind(address).await?);
        let sessions = Arc::new(Sessions::default());
        let (tx, rx) = mpsc::channel(256);
        let task = tokio::spawn(receive(socket.clone(), sessions.clone(), tx));
        let shared = Shared {
            socket,
            sessions,
            worker: task.abort_handle(),
            receiver: tokio::sync::Mutex::new(Some(task)),
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

    /// Whether the receive task is running and shutdown has not been requested.
    pub fn is_running(&self) -> bool {
        !self.shared.sessions.stopped.load(Ordering::Relaxed) && !self.shared.worker.is_finished()
    }

    /// A snapshot of receive and observer queue counters shared by all clones.
    pub fn stats(&self) -> ReceiveStats {
        self.shared.socket.stats()
    }

    /// Stop the receive task for all clones, close the TUNs as best it can,
    /// logging what it could not remove, and wait for the task. The UDP
    /// socket stays bound until the last clone is dropped.
    pub async fn shutdown(&self) -> io::Result<()> {
        self.shared.sessions.stop();
        self.shared.worker.abort();
        let Some(task) = self.shared.receiver.lock().await.take() else {
            return Ok(());
        };
        match task.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(io::Error::other(error)),
        }
    }

    /// Provision a session, replacing one with the same uplink TEID and
    /// closing its TUN. Use [`switch_downlink`](Self::switch_downlink) for a
    /// handover that keeps the session's TUN.
    ///
    /// # Errors
    ///
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) if `session.qfi` is
    /// above 63, as [`Endpoint::install`](crate::Endpoint::install)
    /// returns: the session that the uplink TEID had, if any, then stays
    /// as it was. The error holds the codec's
    /// [`Error::OutOfRange`](crate::Error::OutOfRange) for the QFI, which
    /// is what encoding a G-PDU with it returns.
    pub fn set_session(&self, session: Session) -> io::Result<()> {
        path::qfi(session.qfi)?;
        let entry = Entry {
            session,
            #[cfg(all(target_os = "linux", feature = "tun"))]
            tun: None,
        };
        // The TUN of the session it replaces closes once the lock is released.
        let _replaced = lock(&self.shared.sessions.entries).insert(session.uplink_teid, entry);
        Ok(())
    }

    /// The session of `uplink_teid`, with its current downlink path.
    pub fn session(&self, uplink_teid: u32) -> Option<Session> {
        self.shared.sessions.get(uplink_teid).ok()
    }

    /// Move a session's downlink to `downlink_teid` at `gnb_address`, as
    /// after a handover, and send an End Marker on the old path (TS 23.502
    /// §4.9.1.2.2). The session is switched before the marker is sent, and
    /// stays switched when the send fails, whose error is returned. Switching
    /// to the path that the session has sends nothing.
    pub async fn switch_downlink(
        &self,
        uplink_teid: u32,
        gnb_address: SocketAddr,
        downlink_teid: u32,
    ) -> io::Result<()> {
        if !self.is_running() {
            return Err(stopped());
        }
        let old = {
            let mut entries = lock(&self.shared.sessions.entries);
            let entry = entries
                .get_mut(&uplink_teid)
                .ok_or_else(|| unknown_session(uplink_teid))?;
            let old = entry.session;
            entry.session.gnb_address = gnb_address;
            entry.session.downlink_teid = downlink_teid;
            old
        };
        let new = (path::canonical(gnb_address), downlink_teid);
        if (path::canonical(old.gnb_address), old.downlink_teid) == new {
            return Ok(());
        }
        let marker = Packet::end_marker(old.downlink_teid);
        self.shared.socket.send(&marker, old.gnb_address).await
    }

    /// Whether the echo service answers the uplink T-PDUs of the sessions
    /// that have no TUN: it does unless
    /// [`set_echo_service`](Self::set_echo_service) turned it off.
    pub fn echo_service(&self) -> bool {
        !self.shared.sessions.no_echo.load(Ordering::Relaxed)
    }

    /// Turn the echo service on or off. A program that answers the UE
    /// itself, with [`send_downlink`](Self::send_downlink) after reading
    /// the receiver of [`bind`](Self::bind), turns it off: otherwise the UE
    /// gets the echo of its packet too. The receiver still gets every
    /// uplink G-PDU.
    pub fn set_echo_service(&self, on: bool) {
        self.shared.sessions.no_echo.store(!on, Ordering::Relaxed);
    }

    /// Remove a session and close its TUN.
    pub fn remove_session(&self, uplink_teid: u32) {
        // As in `set_session`, the TUN closes once the lock is released.
        let _removed = lock(&self.shared.sessions.entries).remove(&uplink_teid);
    }

    /// Give a session a Linux TUN as N6: its uplink T-PDUs go to Linux, and
    /// what Linux routes to the TUN comes back as downlink G-PDUs.
    ///
    /// # Errors
    ///
    /// [`NotFound`](io::ErrorKind::NotFound) for a session that does not
    /// exist, [`AlreadyExists`](io::ErrorKind::AlreadyExists) for one that
    /// has a TUN, [`BrokenPipe`](io::ErrorKind::BrokenPipe) once the UPF is
    /// shut down, and the errors of [`TunPort::create`]. On an error nothing
    /// of the TUN is left.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub fn attach_tun(&self, uplink_teid: u32, config: TunConfig) -> io::Result<()> {
        if !self.is_running() {
            return Err(stopped());
        }
        let sessions = &self.shared.sessions;
        tun_slot(&mut lock(&sessions.entries), uplink_teid)?;
        let port = TunPort::create(config)?;
        let task = tokio::spawn(forward_tun_downlink(
            port.clone(),
            self.shared.socket.clone(),
            sessions.clone(),
            uplink_teid,
        ));
        let attachment = TunAttachment { port, task };
        // Unless the UPF stopped, or the session went away or got a TUN
        // meanwhile: the attachment then closes once the lock is released.
        let mut entries = lock(&sessions.entries);
        if sessions.stopped.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        *tun_slot(&mut entries, uplink_teid)? = Some(attachment);
        Ok(())
    }

    /// Send an owned or borrowed IP packet to a session's UE as a downlink G-PDU.
    pub async fn send_downlink<P: AsRef<[u8]>>(
        &self,
        uplink_teid: u32,
        packet: P,
    ) -> io::Result<()> {
        send_downlink(
            &self.shared.socket,
            &self.shared.sessions,
            uplink_teid,
            packet,
        )
        .await
    }
}

/// The TUN of session `uplink_teid`, which has none.
#[cfg(all(target_os = "linux", feature = "tun"))]
fn tun_slot(
    entries: &mut HashMap<u32, Entry>,
    uplink_teid: u32,
) -> io::Result<&mut Option<TunAttachment>> {
    let entry = entries
        .get_mut(&uplink_teid)
        .ok_or_else(|| unknown_session(uplink_teid))?;
    match entry.tun {
        Some(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("a TUN is already attached to uplink TEID {uplink_teid:#010x}"),
        )),
        None => Ok(&mut entry.tun),
    }
}

impl fmt::Debug for UpfSimulator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpfSimulator")
            .field("local_addr", &self.local_addr().ok())
            .field("sessions", &lock(&self.shared.sessions.entries).len())
            .finish()
    }
}

/// Send `packet` on the downlink of session `uplink_teid`.
async fn send_downlink<P: AsRef<[u8]>>(
    socket: &DatagramSocket,
    sessions: &Sessions,
    uplink_teid: u32,
    packet: P,
) -> io::Result<()> {
    let session = sessions.get(uplink_teid)?;
    let downlink = Packet::downlink(session.downlink_teid, session.qfi, packet);
    socket.send(&downlink, session.gnb_address).await
}

/// The echo service's reply to an uplink T-PDU, if it answers it.
fn echo_service(packet: &[u8]) -> Option<Vec<u8>> {
    if let Ok((source, destination, payload)) = ip::parse_udp(packet) {
        return ip::udp(destination, source, payload).ok();
    }
    icmp::echo_reply(packet)
}

async fn receive(
    socket: Arc<DatagramSocket>,
    sessions: Arc<Sessions>,
    tx: mpsc::Sender<UplinkPacket>,
) -> io::Result<()> {
    let mut buffer = vec![0; 65536];
    loop {
        let (packet, from) = match socket.receive(&mut buffer).await {
            Ok(Some(received)) => received,
            Ok(None) => continue,
            Err(error) => {
                sessions.stop();
                warn!("UPF simulator stopped receiving: {error}");
                return Err(error);
            }
        };
        let counters = socket.counters();
        match packet.message_type {
            MessageType::G_PDU => {}
            MessageType::ERROR_INDICATION => {
                counters.ignored_messages.fetch_add(1, Ordering::Relaxed);
                debug!(
                    "UPF got an Error Indication from {from}: {:?}",
                    packet.information_elements()
                );
                continue;
            }
            message_type => {
                counters.ignored_messages.fetch_add(1, Ordering::Relaxed);
                debug!("UPF ignored message type {message_type} from {from}");
                continue;
            }
        }
        if sessions.get(packet.teid).is_err() {
            debug!(
                "UPF G-PDU for unknown TEID {:#010x} from {from}",
                packet.teid
            );
            socket.unknown_teid(packet.teid, from).await;
            continue;
        }
        if !write_to_tun(&sessions, packet.teid, packet.payload).await
            && !sessions.no_echo.load(Ordering::Relaxed)
            && let Some(reply) = echo_service(packet.payload)
            && let Err(error) = send_downlink(&socket, &sessions, packet.teid, reply).await
        {
            debug!(
                "UPF echo reply on uplink TEID {:#010x} failed: {error}",
                packet.teid
            );
        }
        socket.observe(&tx, || UplinkPacket {
            uplink_teid: packet.teid,
            from,
            packet: packet.into_owned(),
        });
    }
}

/// Write an uplink T-PDU to its session's TUN; false if it has none.
#[cfg(all(target_os = "linux", feature = "tun"))]
async fn write_to_tun(sessions: &Sessions, uplink_teid: u32, packet: &[u8]) -> bool {
    let Some(port) = sessions.tun(uplink_teid) else {
        return false;
    };
    // A G-PDU without a T-PDU has nothing for Linux.
    if !packet.is_empty()
        && let Err(error) = port.send(packet).await
    {
        debug!("UPF TUN {} write failed: {error}", port.name());
    }
    true
}

#[cfg(not(all(target_os = "linux", feature = "tun")))]
async fn write_to_tun(_sessions: &Sessions, _uplink_teid: u32, _packet: &[u8]) -> bool {
    false
}

/// Send what Linux routes to a session's TUN as downlink G-PDUs.
#[cfg(all(target_os = "linux", feature = "tun"))]
async fn forward_tun_downlink(
    port: TunPort,
    socket: Arc<DatagramSocket>,
    sessions: Arc<Sessions>,
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
        if let Err(error) = send_downlink(&socket, &sessions, uplink_teid, &buffer[..size]).await {
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::BrokenPipe
            ) {
                return;
            }
            warn!("UPF TUN {} downlink failed: {error}", port.name());
        }
    }
}
