//! A test UPF: an N3 peer whose sessions are provisioned directly, without
//! PFCP. Its N6 is a built-in echo service, or a Linux TUN per session.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::{AbortHandle, JoinHandle};
use tracing::{debug, warn};

use crate::path::{self, lock};
use crate::stats::Counters;
#[cfg(all(target_os = "linux", feature = "tun"))]
use crate::tun::{TunConfig, TunPort};
use crate::{
    ERROR_INDICATION, G_PDU, Packet, ReceiveStats, RemoteTunnel, ipv4_icmp_echo_reply, ipv4_udp,
    parse_ipv4_udp,
};

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
    shutdown: AsyncMutex<Shutdown>,
}

struct Shutdown {
    receiver: Option<JoinHandle<io::Result<()>>>,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    attachments: Vec<TunAttachment>,
}

/// What the tasks share with the handles.
#[derive(Default)]
struct State {
    sessions: Mutex<HashMap<u32, SessionEntry>>,
    closed: AtomicBool,
    counters: Arc<Counters>,
}

struct SessionEntry {
    session: Session,
    /// Identifies this provisioning, even if the same TEID is reused.
    incarnation: Arc<Incarnation>,
    /// At most one old path awaits its End Marker send attempt.
    pending_marker: Option<Session>,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    attachment: Option<TunAttachment>,
}

#[derive(Default)]
struct Incarnation {
    /// Orders downlink sends and path switches for one provisioning.
    downlink: AsyncMutex<()>,
}

struct UplinkTarget {
    incarnation: Arc<Incarnation>,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    port: Option<Arc<TunPort>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Relaxed);
        self.worker.abort();
        // TUN tasks hold the state, so drain their owning attachments to
        // break the cycle. Their cleanup must run outside the registry lock.
        let sessions = std::mem::take(&mut *lock(&self.state.sessions));
        drop(sessions);
    }
}

#[cfg(all(target_os = "linux", feature = "tun"))]
struct TunAttachment {
    port: Arc<TunPort>,
    task: Option<JoinHandle<()>>,
}

#[cfg(all(target_os = "linux", feature = "tun"))]
impl Drop for TunAttachment {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        self.port.close();
    }
}

impl UpfSimulator {
    /// Bind the N3 socket to `address`. The receiver observes the sessions'
    /// uplink G-PDUs; it is best effort and never delays forwarding.
    ///
    /// The address must be specific, so replies leave from the address
    /// the request reached (TS 29.281 §4.4.3). Wildcard addresses return
    /// [`InvalidInput`](io::ErrorKind::InvalidInput).
    pub async fn bind(address: SocketAddr) -> io::Result<(Self, mpsc::Receiver<UplinkPacket>)> {
        if address.ip().to_canonical().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GTP-U requires a specific bind address",
            ));
        }
        let socket = Arc::new(UdpSocket::bind(address).await?);
        let ipv6 = socket.local_addr()?.is_ipv6();
        let state = Arc::new(State::default());
        let (tx, rx) = mpsc::channel(256);
        let task = tokio::spawn(receive(socket.clone(), state.clone(), ipv6, tx));
        let worker = task.abort_handle();
        let shared = Shared {
            socket,
            state,
            ipv6,
            worker,
            shutdown: AsyncMutex::new(Shutdown {
                receiver: Some(task),
                #[cfg(all(target_os = "linux", feature = "tun"))]
                attachments: Vec::new(),
            }),
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
        !self.shared.state.closed.load(Ordering::Relaxed) && !self.shared.worker.is_finished()
    }

    /// A snapshot of receive and observer queue counters shared by all clones.
    pub fn stats(&self) -> ReceiveStats {
        self.shared.state.counters.snapshot()
    }

    /// Stop background processing, close the attached TUNs, and wait for the
    /// receive and TUN forwarding tasks to finish. Cleanup failures are
    /// returned and their TUNs remain owned so a later call can retry. All
    /// clones observe shutdown. The UDP socket
    /// stays bound until the last clone is dropped. Cancelling this call does
    /// not prevent a later call from waiting for the task to finish.
    pub async fn shutdown(&self) -> io::Result<()> {
        self.shared.state.closed.store(true, Ordering::Relaxed);
        self.shared.worker.abort();
        let mut shutdown = self.shared.shutdown.lock().await;
        let sessions = std::mem::take(&mut *lock(&self.shared.state.sessions));
        #[cfg(all(target_os = "linux", feature = "tun"))]
        for entry in sessions.into_values() {
            if let Some(attachment) = entry.attachment {
                if let Some(task) = &attachment.task {
                    task.abort();
                }
                shutdown.attachments.push(attachment);
            }
        }
        #[cfg(not(all(target_os = "linux", feature = "tun")))]
        drop(sessions);
        let result = match shutdown.receiver.as_mut() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(io::Error::other(error)),
            },
            None => Ok(()),
        };
        shutdown.receiver.take();
        #[cfg(all(target_os = "linux", feature = "tun"))]
        {
            let mut result = result;
            let mut index = 0;
            while index < shutdown.attachments.len() {
                let attachment = &mut shutdown.attachments[index];
                if let Some(task) = attachment.task.as_mut() {
                    if let Err(error) = task.await {
                        if !error.is_cancelled() && result.is_ok() {
                            result = Err(io::Error::other(error));
                        }
                    }
                    attachment.task.take();
                }
                match attachment.port.try_close() {
                    Ok(()) => {
                        shutdown.attachments.swap_remove(index);
                    }
                    Err(error) => {
                        if result.is_ok() {
                            result = Err(error);
                        }
                        index += 1;
                    }
                }
            }
            result
        }
        #[cfg(not(all(target_os = "linux", feature = "tun")))]
        {
            result
        }
    }

    fn ensure_running(&self) -> io::Result<()> {
        if self.is_running() {
            Ok(())
        } else {
            Err(stopped())
        }
    }

    /// Provision a session, replacing one with the same uplink TEID and
    /// closing its previous TUN. Use [`switch_downlink`](Self::switch_downlink)
    /// for a handover that retains the session's N6 attachment.
    ///
    /// # Panics
    ///
    /// If `session.qfi` is above 63, including when the public field was
    /// changed after constructing the session.
    pub fn set_session(&self, session: Session) {
        assert!(session.qfi <= 63, "QFI {} is outside 0..=63", session.qfi);
        let old = lock(&self.shared.state.sessions).insert(
            session.uplink_teid,
            SessionEntry {
                session,
                incarnation: Arc::new(Incarnation::default()),
                pending_marker: None,
                #[cfg(all(target_os = "linux", feature = "tun"))]
                attachment: None,
            },
        );
        drop(old);
    }

    /// A snapshot of the current session, including the committed downlink path.
    /// Separate calls to this method and [`pending_end_marker`](Self::pending_end_marker)
    /// can observe different concurrent updates.
    pub fn session(&self, uplink_teid: u32) -> Option<Session> {
        lock(&self.shared.state.sessions)
            .get(&uplink_teid)
            .map(|entry| entry.session)
    }

    /// The old downlink path whose End Marker is pending after a failed or
    /// cancelled switch. This snapshot does not guarantee delivery or make
    /// separate status calls atomic with concurrent changes.
    pub fn pending_end_marker(&self, uplink_teid: u32) -> Option<RemoteTunnel> {
        lock(&self.shared.state.sessions)
            .get(&uplink_teid)
            .and_then(|entry| entry.pending_marker)
            .map(|session| RemoteTunnel {
                address: session.gnb_address,
                teid: session.downlink_teid,
            })
    }

    /// Move a session's downlink to `downlink_teid` at `gnb_address`, as
    /// after a handover, and send an End Marker on the old path (TS 23.502
    /// §4.9.1.2.2).
    ///
    /// The route changes before the marker is sent. A send error or
    /// cancellation leaves the new route installed and its old-path marker
    /// pending. Retrying, even with the same target, attempts that marker
    /// again. A further path change first completes the pending send attempt,
    /// keeping at most one pending marker per session. UDP send success does
    /// not guarantee delivery. Replacing or removing the session discards its
    /// pending marker. Downlink sends and switches are ordered per session.
    pub async fn switch_downlink(
        &self,
        uplink_teid: u32,
        gnb_address: SocketAddr,
        downlink_teid: u32,
    ) -> io::Result<()> {
        self.ensure_running()?;
        let incarnation = incarnation(&self.shared.state, uplink_teid)?;
        let _downlink = incarnation.downlink.lock().await;
        self.ensure_running()?;
        self.send_pending_marker(uplink_teid, &incarnation).await?;
        let changed = {
            let mut sessions = lock(&self.shared.state.sessions);
            let entry = current_entry(&mut sessions, uplink_teid, &incarnation)?;
            let old_path = (
                path::canonical(entry.session.gnb_address),
                entry.session.downlink_teid,
            );
            if old_path == (path::canonical(gnb_address), downlink_teid) {
                false
            } else {
                entry.pending_marker = Some(entry.session);
                entry.session.gnb_address = gnb_address;
                entry.session.downlink_teid = downlink_teid;
                true
            }
        };
        if changed {
            self.send_pending_marker(uplink_teid, &incarnation).await?;
        }
        Ok(())
    }

    async fn send_pending_marker(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
    ) -> io::Result<()> {
        self.ensure_running()?;
        let pending = {
            let mut sessions = lock(&self.shared.state.sessions);
            current_entry(&mut sessions, uplink_teid, incarnation)?.pending_marker
        };
        if let Some(old) = pending {
            let marker = Packet::end_marker(old.downlink_teid)
                .encode()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let to = path::destination(self.shared.ipv6, old.gnb_address);
            loop {
                self.shared.socket.writable().await?;
                let sent = {
                    let mut sessions = lock(&self.shared.state.sessions);
                    self.ensure_running()?;
                    let entry = current_entry(&mut sessions, uplink_teid, incarnation)?;
                    // Recheck after readiness, then commit the nonblocking
                    // syscall and marker state together before replacement.
                    let sent = self.shared.socket.try_send_to(&marker, to);
                    if sent.is_ok() {
                        entry.pending_marker = None;
                    }
                    sent
                };
                match sent {
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// Remove a session and close its TUN.
    pub fn remove_session(&self, uplink_teid: u32) {
        let old = lock(&self.shared.state.sessions).remove(&uplink_teid);
        // Close after the registry locks are released.
        drop(old);
    }

    /// Give a session a Linux TUN as N6: its uplink T-PDUs go to Linux, and
    /// what Linux routes to the TUN comes back as downlink G-PDUs.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub fn attach_tun(&self, uplink_teid: u32, config: TunConfig) -> io::Result<()> {
        self.ensure_running()?;
        let already_attached = || {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("a TUN is already attached to uplink TEID {uplink_teid}"),
            )
        };
        let incarnation = {
            let sessions = lock(&self.shared.state.sessions);
            let entry = sessions
                .get(&uplink_teid)
                .ok_or_else(|| unknown_session(uplink_teid))?;
            if entry.attachment.is_some() {
                return Err(already_attached());
            }
            entry.incarnation.clone()
        };
        let port = Arc::new(TunPort::create(config)?);
        let task = tokio::spawn(forward_tun_downlink(
            port.clone(),
            self.shared.socket.clone(),
            self.shared.state.clone(),
            self.shared.ipv6,
            uplink_teid,
            incarnation.clone(),
        ));
        let attachment = TunAttachment {
            port,
            task: Some(task),
        };
        // Keep removal/replacement from interleaving the recheck and the
        // insertion. Removing a session then either prevents attachment
        // or removes the attachment that was just inserted.
        let mut attachment = Some(attachment);
        let result = {
            let mut sessions = lock(&self.shared.state.sessions);
            if self.shared.state.closed.load(Ordering::Relaxed) || self.shared.worker.is_finished()
            {
                Err(stopped())
            } else {
                match current_entry(&mut sessions, uplink_teid, &incarnation) {
                    Err(error) => Err(error),
                    Ok(entry) if entry.attachment.is_some() => Err(already_attached()),
                    Ok(entry) => {
                        entry.attachment = attachment.take();
                        Ok(())
                    }
                }
            }
        };
        drop(attachment);
        result
    }

    /// Send `packet`, an IP packet, to a session's UE as a downlink G-PDU.
    pub async fn send_downlink(&self, uplink_teid: u32, packet: Vec<u8>) -> io::Result<()> {
        self.ensure_running()?;
        let incarnation = incarnation(&self.shared.state, uplink_teid)?;
        send_downlink(
            &self.shared.socket,
            &self.shared.state,
            self.shared.ipv6,
            uplink_teid,
            &incarnation,
            packet,
        )
        .await
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

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "UPF simulator has stopped")
}

fn incarnation(state: &State, uplink_teid: u32) -> io::Result<Arc<Incarnation>> {
    lock(&state.sessions)
        .get(&uplink_teid)
        .map(|entry| entry.incarnation.clone())
        .ok_or_else(|| unknown_session(uplink_teid))
}

fn current_entry<'a>(
    sessions: &'a mut HashMap<u32, SessionEntry>,
    uplink_teid: u32,
    incarnation: &Arc<Incarnation>,
) -> io::Result<&'a mut SessionEntry> {
    sessions
        .get_mut(&uplink_teid)
        .filter(|entry| Arc::ptr_eq(&entry.incarnation, incarnation))
        .ok_or_else(|| unknown_session(uplink_teid))
}

fn uplink_target(state: &State, uplink_teid: u32) -> Option<UplinkTarget> {
    lock(&state.sessions)
        .get(&uplink_teid)
        .map(|entry| UplinkTarget {
            incarnation: entry.incarnation.clone(),
            #[cfg(all(target_os = "linux", feature = "tun"))]
            port: entry
                .attachment
                .as_ref()
                .map(|attachment| attachment.port.clone()),
        })
}

async fn send_downlink(
    socket: &UdpSocket,
    state: &State,
    ipv6: bool,
    uplink_teid: u32,
    incarnation: &Arc<Incarnation>,
    packet: Vec<u8>,
) -> io::Result<()> {
    let _downlink = incarnation.downlink.lock().await;
    if state.closed.load(Ordering::Relaxed) {
        return Err(stopped());
    }
    let session = current_entry(&mut lock(&state.sessions), uplink_teid, incarnation)?.session;
    let bytes = Packet::downlink(session.downlink_teid, session.qfi, packet)
        .encode()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let to = path::destination(ipv6, session.gnb_address);
    loop {
        socket.writable().await?;
        let sent = {
            let mut sessions = lock(&state.sessions);
            if state.closed.load(Ordering::Relaxed) {
                return Err(stopped());
            }
            current_entry(&mut sessions, uplink_teid, incarnation)?;
            socket.try_send_to(&bytes, to)
        };
        match sent {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
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
) -> io::Result<()> {
    let mut buffer = vec![0; 65536];
    loop {
        let (size, from) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) if path::transient(&error) => continue,
            Err(error) => {
                state.closed.store(true, Ordering::Relaxed);
                warn!("UPF simulator stopped receiving: {error}");
                return Err(error);
            }
        };
        state
            .counters
            .received_datagrams
            .fetch_add(1, Ordering::Relaxed);
        let packet = match Packet::decode(&buffer[..size]) {
            Ok(packet) => packet,
            Err(error) => {
                state
                    .counters
                    .malformed_datagrams
                    .fetch_add(1, Ordering::Relaxed);
                debug!("UPF dropped a malformed message from {from}: {error}");
                path::answer_length_error(&socket, &buffer[..size], from).await;
                continue;
            }
        };
        if path::answer(&socket, &packet, from).await {
            state.counters.path_messages.fetch_add(1, Ordering::Relaxed);
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
        let Some(target) = uplink_target(&state, packet.teid) else {
            debug!("UPF G-PDU for unknown TEID {} from {from}", packet.teid);
            path::error_indication(&socket, packet.teid, from).await;
            continue;
        };
        if !write_to_tun(&target, &packet.payload).await {
            if let Some(reply) = echo_service(&packet.payload) {
                if let Err(error) = send_downlink(
                    &socket,
                    &state,
                    ipv6,
                    packet.teid,
                    &target.incarnation,
                    reply,
                )
                .await
                {
                    debug!(
                        "UPF echo reply on uplink TEID {} failed: {error}",
                        packet.teid
                    );
                }
            }
        }
        let observed = UplinkPacket {
            uplink_teid: packet.teid,
            from: path::canonical(from),
            packet,
        };
        match tx.try_send(observed) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                state
                    .counters
                    .queue_full_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Closed(_)) => {
                state
                    .counters
                    .receiver_closed_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Write an uplink T-PDU to its session's TUN; false if it has none.
#[cfg(all(target_os = "linux", feature = "tun"))]
async fn write_to_tun(target: &UplinkTarget, packet: &[u8]) -> bool {
    let Some(port) = &target.port else {
        return false;
    };
    if let Err(error) = port.send(packet).await {
        warn!("UPF TUN {} write failed: {error}", port.name());
    }
    true
}

#[cfg(not(all(target_os = "linux", feature = "tun")))]
async fn write_to_tun(_target: &UplinkTarget, _packet: &[u8]) -> bool {
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
    incarnation: Arc<Incarnation>,
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
        if let Err(error) = send_downlink(
            &socket,
            &state,
            ipv6,
            uplink_teid,
            &incarnation,
            buffer[..size].to_vec(),
        )
        .await
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn replacing_a_session_rejects_waiting_sends_and_stale_uplink_snapshots() {
        let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        upf.set_session(Session::new(1, 2, peer.local_addr().unwrap(), 9));
        let target = uplink_target(&upf.shared.state, 1).unwrap();
        let guard = target.incarnation.downlink.lock().await;
        let mut waiting = Box::pin(upf.send_downlink(1, vec![0x45]));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
        upf.set_session(Session::new(1, 3, peer.local_addr().unwrap(), 9));
        drop(guard);
        assert_eq!(waiting.await.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(
            send_downlink(
                &upf.shared.socket,
                &upf.shared.state,
                upf.shared.ipv6,
                1,
                &target.incarnation,
                vec![0x45]
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::NotFound
        );
        let mut buffer = [0; 128];
        assert!(
            timeout(Duration::from_millis(25), peer.recv_from(&mut buffer))
                .await
                .is_err()
        );
        upf.send_downlink(1, vec![0x45]).await.unwrap();
        let (size, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Packet::decode(&buffer[..size]).unwrap().teid, 3);
    }
}
