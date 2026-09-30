//! Session generations, path transitions and N6 attachment ownership.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;
#[cfg(all(target_os = "linux", feature = "tun"))]
use tokio::task::JoinHandle;

use crate::RemoteTunnel;
use crate::path::{self, lock};
#[cfg(all(target_os = "linux", feature = "tun"))]
use crate::tun::TunPort;

use super::Session;

#[derive(Default)]
pub(super) struct SessionRegistry {
    sessions: Mutex<HashMap<u32, SessionEntry>>,
    closed: AtomicBool,
}

struct SessionEntry {
    session: Session,
    incarnation: Arc<Incarnation>,
    pending_marker: Option<Session>,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    attachment: Option<TunAttachment>,
}

#[derive(Default)]
pub(super) struct Incarnation {
    /// Async ordering is per provisioning; the registry lock is never awaited.
    pub(super) downlink: AsyncMutex<()>,
}

pub(super) struct UplinkTarget {
    pub(super) incarnation: Arc<Incarnation>,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) port: Option<Arc<TunPort>>,
}

#[cfg(all(target_os = "linux", feature = "tun"))]
pub(super) struct TunAttachment {
    pub(super) port: Arc<TunPort>,
    pub(super) task: Option<JoinHandle<()>>,
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

impl SessionRegistry {
    pub(super) fn stop(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub(super) fn replace(&self, session: Session) {
        assert!(session.qfi <= 63, "QFI {} is outside 0..=63", session.qfi);
        let old = lock(&self.sessions).insert(
            session.uplink_teid,
            SessionEntry {
                session,
                incarnation: Arc::new(Incarnation::default()),
                pending_marker: None,
                #[cfg(all(target_os = "linux", feature = "tun"))]
                attachment: None,
            },
        );
        // Cleanup can perform netlink I/O and must run outside this lock.
        drop(old);
    }

    pub(super) fn remove(&self, uplink_teid: u32) {
        let old = lock(&self.sessions).remove(&uplink_teid);
        drop(old);
    }

    pub(super) fn clear(&self) {
        let entries = std::mem::take(&mut *lock(&self.sessions));
        drop(entries);
    }

    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn drain_attachments(&self) -> impl Iterator<Item = TunAttachment> + use<> {
        let entries = std::mem::take(&mut *lock(&self.sessions));
        entries.into_values().filter_map(|entry| entry.attachment)
    }

    pub(super) fn len(&self) -> usize {
        lock(&self.sessions).len()
    }

    pub(super) fn session(&self, uplink_teid: u32) -> Option<Session> {
        lock(&self.sessions)
            .get(&uplink_teid)
            .map(|entry| entry.session)
    }

    pub(super) fn pending_end_marker(&self, uplink_teid: u32) -> Option<RemoteTunnel> {
        lock(&self.sessions)
            .get(&uplink_teid)
            .and_then(|entry| entry.pending_marker)
            .map(|session| RemoteTunnel {
                address: session.gnb_address,
                teid: session.downlink_teid,
            })
    }

    pub(super) fn incarnation(&self, uplink_teid: u32) -> io::Result<Arc<Incarnation>> {
        lock(&self.sessions)
            .get(&uplink_teid)
            .map(|entry| entry.incarnation.clone())
            .ok_or_else(|| unknown_session(uplink_teid))
    }

    pub(super) fn uplink_target(&self, uplink_teid: u32) -> Option<UplinkTarget> {
        lock(&self.sessions)
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

    /// The caller owns this incarnation's downlink ordering guard.
    pub(super) fn switch_path(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
        address: SocketAddr,
        teid: u32,
    ) -> io::Result<bool> {
        self.with_current(uplink_teid, incarnation, |entry| {
            let old = (
                path::canonical(entry.session.gnb_address),
                entry.session.downlink_teid,
            );
            if old == (path::canonical(address), teid) {
                return Ok(false);
            }
            debug_assert!(entry.pending_marker.is_none());
            entry.pending_marker = Some(entry.session);
            entry.session.gnb_address = address;
            entry.session.downlink_teid = teid;
            Ok(true)
        })
    }

    pub(super) fn current_session(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
    ) -> io::Result<Session> {
        self.with_current(uplink_teid, incarnation, |entry| Ok(entry.session))
    }

    pub(super) fn pending_marker(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
    ) -> io::Result<Option<Session>> {
        self.with_current(uplink_teid, incarnation, |entry| Ok(entry.pending_marker))
    }

    /// Recheck the generation and commit the nonblocking syscall under one lock.
    /// This closure must never block or await.
    pub(super) fn send_downlink(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
        send: impl FnOnce() -> io::Result<usize>,
    ) -> io::Result<usize> {
        self.with_current(uplink_teid, incarnation, |_| send())
    }

    pub(super) fn send_marker(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
        send: impl FnOnce() -> io::Result<usize>,
    ) -> io::Result<usize> {
        self.with_current(uplink_teid, incarnation, |entry| {
            let sent = send()?;
            entry.pending_marker = None;
            Ok(sent)
        })
    }

    fn with_current<T>(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
        operation: impl FnOnce(&mut SessionEntry) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut sessions = lock(&self.sessions);
        if self.is_closed() {
            return Err(stopped());
        }
        let entry = sessions
            .get_mut(&uplink_teid)
            .filter(|entry| Arc::ptr_eq(&entry.incarnation, incarnation))
            .ok_or_else(|| unknown_session(uplink_teid))?;
        operation(entry)
    }

    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn prepare_attachment(&self, uplink_teid: u32) -> io::Result<Arc<Incarnation>> {
        let sessions = lock(&self.sessions);
        let entry = sessions
            .get(&uplink_teid)
            .ok_or_else(|| unknown_session(uplink_teid))?;
        if entry.attachment.is_some() {
            return Err(already_attached(uplink_teid));
        }
        Ok(entry.incarnation.clone())
    }

    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn attach(
        &self,
        uplink_teid: u32,
        incarnation: &Arc<Incarnation>,
        attachment: TunAttachment,
        receiver_running: bool,
    ) -> io::Result<()> {
        let mut attachment = Some(attachment);
        let result = self.with_current(uplink_teid, incarnation, |entry| {
            if !receiver_running {
                return Err(stopped());
            }
            if entry.attachment.is_some() {
                return Err(already_attached(uplink_teid));
            }
            entry.attachment = attachment.take();
            Ok(())
        });
        drop(attachment);
        result
    }
}

fn unknown_session(uplink_teid: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no session with uplink TEID {uplink_teid}"),
    )
}

pub(super) fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "UPF simulator has stopped")
}

#[cfg(all(target_os = "linux", feature = "tun"))]
fn already_attached(uplink_teid: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("a TUN is already attached to uplink TEID {uplink_teid}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_commit_preserves_failed_attempt_and_rejects_stale_generation() {
        let registry = SessionRegistry::default();
        let old: SocketAddr = "127.0.0.1:2152".parse().unwrap();
        let new: SocketAddr = "127.0.0.2:2152".parse().unwrap();
        registry.replace(Session::new(1, 2, old, 9));
        let generation = registry.incarnation(1).unwrap();
        assert!(registry.switch_path(1, &generation, new, 3).unwrap());
        assert!(
            registry
                .send_marker(1, &generation, || Err(io::ErrorKind::WouldBlock.into()))
                .is_err()
        );
        assert_eq!(
            registry.pending_end_marker(1),
            Some(RemoteTunnel {
                address: old,
                teid: 2
            })
        );
        registry.send_marker(1, &generation, || Ok(8)).unwrap();
        assert_eq!(registry.pending_end_marker(1), None);
        registry.replace(Session::new(1, 4, old, 9));
        let mut called = false;
        assert_eq!(
            registry
                .send_downlink(1, &generation, || {
                    called = true;
                    Ok(8)
                })
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(!called);
    }
}
