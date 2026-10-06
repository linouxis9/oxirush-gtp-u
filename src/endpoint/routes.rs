//! The two indexes of the endpoint's tunnel registry, and the tunnels' TUNs.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use crate::path::{lock, same_ip};
#[cfg(all(target_os = "linux", feature = "tun"))]
use crate::tun::TunPort;
use crate::{InformationElement, Packet};

use super::RemoteTunnel;

pub(super) type SessionKey = (u32, u8);

#[derive(Clone, Copy)]
pub(super) struct Route {
    pub(super) local_teid: u32,
    pub(super) remote: RemoteTunnel,
    pub(super) qfi: Option<u8>,
}

impl Route {
    /// An IP packet as the tunnel's uplink G-PDU.
    pub(super) fn uplink<P: AsRef<[u8]>>(&self, payload: P) -> Packet<P> {
        match self.qfi {
            Some(qfi) => Packet::uplink(self.remote.teid, qfi, payload),
            None => Packet::g_pdu(self.remote.teid, payload),
        }
    }
}

/// A tunnel's TUN and the task that reads it. Dropping it closes the TUN.
#[cfg(all(target_os = "linux", feature = "tun"))]
pub(super) struct TunAttachment {
    pub(super) port: TunPort,
    pub(super) reader: tokio::task::JoinHandle<()>,
    /// The fast path the TUN is on.
    #[cfg(feature = "ebpf")]
    pub(super) fast_path: Option<crate::ebpf::FastPath>,
}

#[cfg(all(target_os = "linux", feature = "tun"))]
impl Drop for TunAttachment {
    fn drop(&mut self) {
        self.reader.abort();
        // First: another interface may get the index of a closed TUN.
        #[cfg(feature = "ebpf")]
        if let Some(fast_path) = &self.fast_path {
            fast_path.remove_tun(self.port.index());
        }
        self.port.close();
    }
}

/// Without the `tun` feature no tunnel has a TUN.
#[cfg(not(all(target_os = "linux", feature = "tun")))]
pub(super) enum TunAttachment {}

#[derive(Default)]
pub(super) struct RouteTable(Mutex<Routes>);

#[derive(Default)]
struct Routes {
    by_session: HashMap<SessionKey, Route>,
    by_teid: HashMap<u32, SessionKey>,
    last_teid: u32,
    /// The TUNs of the tunnels that have one.
    tuns: HashMap<SessionKey, TunAttachment>,
}

impl Routes {
    fn allocate_teid(&mut self) -> u32 {
        loop {
            self.last_teid = self.last_teid.wrapping_add(1);
            if self.last_teid != 0 && !self.by_teid.contains_key(&self.last_teid) {
                return self.last_teid;
            }
        }
    }

    fn remove(&mut self, key: SessionKey) -> Option<Route> {
        let route = self.by_session.remove(&key)?;
        self.by_teid.remove(&route.local_teid);
        Some(route)
    }

    fn insert(&mut self, key: SessionKey, route: Route) {
        self.remove(key);
        self.by_session.insert(key, route);
        self.by_teid.insert(route.local_teid, key);
    }

    /// Whether tunnel `key` can get a TUN.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    fn tun_slot(&self, key: SessionKey) -> io::Result<()> {
        if !self.by_session.contains_key(&key) {
            return Err(no_tunnel(key));
        }
        if self.tuns.contains_key(&key) {
            let (ran_id, session_id) = key;
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("RAN UE {ran_id} session {session_id} has a TUN"),
            ));
        }
        Ok(())
    }
}

pub(super) fn no_tunnel((ran_id, session_id): SessionKey) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no tunnel for RAN UE {ran_id} session {session_id}"),
    )
}

impl RouteTable {
    pub(super) fn install(&self, key: SessionKey, remote: RemoteTunnel, qfi: Option<u8>) -> u32 {
        let mut routes = lock(&self.0);
        if let Some(route) = routes.by_session.get_mut(&key) {
            route.remote = remote;
            route.qfi = qfi;
            return route.local_teid;
        }
        let local_teid = routes.allocate_teid();
        routes.insert(
            key,
            Route {
                local_teid,
                remote,
                qfi,
            },
        );
        local_teid
    }

    pub(super) fn install_with_teid(
        &self,
        key: SessionKey,
        local_teid: u32,
        remote: RemoteTunnel,
        qfi: Option<u8>,
    ) -> io::Result<()> {
        if local_teid == 0 || qfi.is_some_and(|qfi| qfi > 63) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid local TEID or QFI",
            ));
        }
        let mut routes = lock(&self.0);
        if routes
            .by_teid
            .get(&local_teid)
            .is_some_and(|owner| *owner != key)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "local TEID belongs to another session",
            ));
        }
        routes.insert(
            key,
            Route {
                local_teid,
                remote,
                qfi,
            },
        );
        Ok(())
    }

    pub(super) fn route(&self, key: SessionKey) -> Option<Route> {
        lock(&self.0).by_session.get(&key).copied()
    }

    /// Run `f` on a route that cannot change or go away meanwhile.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(super) fn with_route<T>(&self, key: SessionKey, f: impl FnOnce(Route) -> T) -> Option<T> {
        lock(&self.0).by_session.get(&key).copied().map(f)
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(super) fn local_teids(&self) -> Vec<u32> {
        lock(&self.0).by_teid.keys().copied().collect()
    }

    pub(super) fn session(&self, local_teid: u32) -> Option<SessionKey> {
        lock(&self.0).by_teid.get(&local_teid).copied()
    }

    /// Returns the local TEID of the removed tunnel, whose TUN closes.
    pub(super) fn remove(&self, key: SessionKey) -> Option<u32> {
        // The TUN closes once the lock is released: that is netlink I/O.
        let (route, _tun) = {
            let mut routes = lock(&self.0);
            (routes.remove(key), routes.tuns.remove(&key))
        };
        route.map(|route| route.local_teid)
    }

    /// Returns the local TEIDs of the removed tunnels, whose TUNs close.
    pub(super) fn remove_ran(&self, ran_id: u32) -> Vec<u32> {
        let mut routes = lock(&self.0);
        let keys: Vec<_> = routes
            .by_session
            .keys()
            .filter(|(ran, _)| *ran == ran_id)
            .copied()
            .collect();
        let _tuns: Vec<_> = keys
            .iter()
            .filter_map(|key| routes.tuns.remove(key))
            .collect();
        let teids = keys
            .into_iter()
            .filter_map(|key| routes.remove(key))
            .map(|route| route.local_teid)
            .collect();
        // As above: the TUNs close after it.
        drop(routes);
        teids
    }

    /// Close every tunnel's TUN.
    pub(super) fn close_tuns(&self) {
        // As above: the lock is released at the end of this statement.
        let _tuns = std::mem::take(&mut lock(&self.0).tuns);
    }

    /// Whether tunnel `key` can get a TUN: it exists and has none.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn tun_slot(&self, key: SessionKey) -> io::Result<()> {
        lock(&self.0).tun_slot(key)
    }

    /// Give tunnel `key` its TUN, if it still can get one.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn attach_tun(&self, key: SessionKey, tun: TunAttachment) -> io::Result<()> {
        let mut routes = lock(&self.0);
        // On an error `tun` closes once the lock is released: a parameter
        // is dropped after the locals.
        routes.tun_slot(key)?;
        routes.tuns.insert(key, tun);
        Ok(())
    }

    /// The TUN of tunnel `key`.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn tun(&self, key: SessionKey) -> Option<TunPort> {
        lock(&self.0).tuns.get(&key).map(|tun| tun.port.clone())
    }

    pub(super) fn len(&self) -> usize {
        lock(&self.0).by_session.len()
    }

    /// Error Indications identify the peer's TEID and address, not our TEID.
    pub(super) fn error_indication_session<P: AsRef<[u8]>>(
        &self,
        packet: &Packet<P>,
    ) -> Option<SessionKey> {
        let elements = packet.information_elements().ok()?;
        let teid = elements.iter().find_map(|element| match element {
            InformationElement::TeidDataI(teid) => Some(*teid),
            _ => None,
        })?;
        let peer = elements.iter().find_map(|element| match element {
            InformationElement::GtpUPeerAddress(address) => Some(*address),
            _ => None,
        })?;
        lock(&self.0)
            .by_session
            .iter()
            .find(|(_, route)| {
                route.remote.teid == teid && same_ip(route.remote.address.ip(), peer)
            })
            .map(|(key, _)| *key)
    }
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

    #[test]
    fn replacement_and_removal_keep_both_indexes_consistent() {
        let table = RouteTable::default();
        let remote = RemoteTunnel {
            address: "127.0.0.1:2152".parse().unwrap(),
            teid: 42,
        };
        table.install_with_teid((1, 5), 7, remote, Some(9)).unwrap();
        table.install_with_teid((1, 5), 8, remote, None).unwrap();
        assert_eq!(table.session(7), None);
        assert_eq!(table.session(8), Some((1, 5)));
        assert_eq!(table.install((1, 5), remote, Some(10)), 8);
        assert_eq!(table.route((1, 5)).unwrap().qfi, Some(10));
        table.remove_ran(1);
        assert_eq!(table.session(8), None);
        assert_eq!(table.len(), 0);
    }
}
