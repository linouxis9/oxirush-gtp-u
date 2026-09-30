//! The two indexes of the endpoint's tunnel registry.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use crate::path::{lock, same_ip};
use crate::{InformationElement, Packet};

use super::RemoteTunnel;

pub(super) type SessionKey = (u32, u8);

#[derive(Clone, Copy)]
pub(super) struct Route {
    pub(super) local_teid: u32,
    pub(super) remote: RemoteTunnel,
    pub(super) qfi: Option<u8>,
}

#[derive(Default)]
pub(super) struct RouteTable(Mutex<Routes>);

#[derive(Default)]
struct Routes {
    by_session: HashMap<SessionKey, Route>,
    by_teid: HashMap<u32, SessionKey>,
    last_teid: u32,
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

    fn remove(&mut self, key: SessionKey) {
        if let Some(route) = self.by_session.remove(&key) {
            self.by_teid.remove(&route.local_teid);
        }
    }

    fn insert(&mut self, key: SessionKey, route: Route) {
        self.remove(key);
        self.by_session.insert(key, route);
        self.by_teid.insert(route.local_teid, key);
    }
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

    pub(super) fn session(&self, local_teid: u32) -> Option<SessionKey> {
        lock(&self.0).by_teid.get(&local_teid).copied()
    }

    pub(super) fn remove(&self, key: SessionKey) {
        lock(&self.0).remove(key);
    }

    pub(super) fn remove_ran(&self, ran_id: u32) {
        let mut routes = lock(&self.0);
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
