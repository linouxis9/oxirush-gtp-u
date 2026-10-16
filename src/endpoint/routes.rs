//! The indexes of the endpoint's tunnel registry, and the tunnels' TUNs.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::path::lock;
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

/// The far end of a tunnel as an Error Indication names it: the peer's TEID
/// and its address, IPv4 rather than IPv4-mapped.
type RemoteKey = (u32, IpAddr);

fn remote_key(remote: &RemoteTunnel) -> RemoteKey {
    (remote.teid, remote.address.ip().to_canonical())
}

#[derive(Default)]
struct Routes {
    by_session: HashMap<SessionKey, Route>,
    by_teid: HashMap<u32, SessionKey>,
    /// The tunnels by their far end. Anyone who reaches the socket can send
    /// an Error Indication: finding its tunnel, or that it has none, must
    /// not be a walk through every tunnel.
    by_remote: BTreeSet<(RemoteKey, SessionKey)>,
    /// The tunnels in the order of their RAN UE, to remove those of one.
    by_ran: BTreeSet<SessionKey>,
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
        self.by_remote.remove(&(remote_key(&route.remote), key));
        self.by_ran.remove(&key);
        Some(route)
    }

    fn insert(&mut self, key: SessionKey, route: Route) {
        self.remove(key);
        self.by_session.insert(key, route);
        self.by_teid.insert(route.local_teid, key);
        self.by_remote.insert((remote_key(&route.remote), key));
        self.by_ran.insert(key);
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
        let routes = &mut *lock(&self.0);
        if let Some(route) = routes.by_session.get_mut(&key) {
            let former = std::mem::replace(&mut route.remote, remote);
            route.qfi = qfi;
            routes.by_remote.remove(&(remote_key(&former), key));
            routes.by_remote.insert((remote_key(&remote), key));
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
        if local_teid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a local TEID is not 0",
            ));
        }
        if let Some(qfi) = qfi {
            crate::path::qfi(qfi)?;
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
            .by_ran
            .range((ran_id, u8::MIN)..=(ran_id, u8::MAX))
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
    /// Of several tunnels to that far end, it is the first by RAN UE and
    /// session.
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
        let remote = (teid, peer.to_canonical());
        lock(&self.0)
            .by_remote
            .range((remote, (u32::MIN, u8::MIN))..=(remote, (u32::MAX, u8::MAX)))
            .next()
            .map(|(_, key)| *key)
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

    fn remote(address: &str, teid: u32) -> RemoteTunnel {
        RemoteTunnel::new(address.parse().unwrap(), teid)
    }

    /// The tunnel of an Error Indication that names `teid` at `peer`.
    fn indicated(table: &RouteTable, teid: u32, peer: &str) -> Option<SessionKey> {
        let indication = Packet::error_indication(teid, peer.parse().unwrap());
        table.error_indication_session(&indication)
    }

    /// Every index has every tunnel, and nothing else.
    fn assert_indexed(table: &RouteTable, tunnels: usize) {
        let routes = lock(&table.0);
        assert_eq!(routes.by_session.len(), tunnels);
        assert_eq!(routes.by_teid.len(), tunnels);
        assert_eq!(routes.by_remote.len(), tunnels);
        assert_eq!(routes.by_ran.len(), tunnels);
        for (key, route) in &routes.by_session {
            assert_eq!(routes.by_teid.get(&route.local_teid), Some(key));
            assert!(
                routes
                    .by_remote
                    .contains(&(remote_key(&route.remote), *key))
            );
            assert!(routes.by_ran.contains(key));
        }
    }

    #[test]
    fn an_error_indication_finds_the_tunnel_to_the_far_end_it_names() {
        let table = RouteTable::default();
        table.install((1, 5), remote("192.0.2.1:2152", 44), Some(9));
        // A dual-stack socket reports an IPv4 peer as IPv4-mapped.
        table.install((2, 5), remote("[::ffff:192.0.2.2]:2152", 44), Some(9));
        table.install((3, 5), remote("[2001:db8::3]:2152", 44), None);
        assert_indexed(&table, 3);
        for (peer, key) in [
            ("192.0.2.1", (1, 5)),
            ("::ffff:192.0.2.1", (1, 5)),
            ("192.0.2.2", (2, 5)),
            ("::ffff:192.0.2.2", (2, 5)),
            ("2001:db8::3", (3, 5)),
        ] {
            assert_eq!(indicated(&table, 44, peer), Some(key), "{peer}");
            // Another TEID of that peer is another tunnel's, or nobody's.
            assert_eq!(indicated(&table, 45, peer), None, "{peer}");
        }
        assert_eq!(indicated(&table, 44, "192.0.2.3"), None);
        assert_eq!(indicated(&table, 44, "2001:db8::4"), None);
    }

    #[test]
    fn a_tunnel_is_found_by_its_current_far_end_only() {
        let table = RouteTable::default();
        let local_teid = table.install((1, 5), remote("192.0.2.1:2152", 44), Some(9));
        // The same call on an existing tunnel changes its far end in place.
        assert_eq!(
            table.install((1, 5), remote("192.0.2.1:2152", 45), Some(9)),
            local_teid
        );
        assert_eq!(indicated(&table, 44, "192.0.2.1"), None);
        assert_eq!(indicated(&table, 45, "192.0.2.1"), Some((1, 5)));
        assert_indexed(&table, 1);
        // Another address with the same TEID, then the same far end again.
        table.install((1, 5), remote("192.0.2.9:2152", 45), None);
        assert_eq!(indicated(&table, 45, "192.0.2.1"), None);
        assert_eq!(indicated(&table, 45, "192.0.2.9"), Some((1, 5)));
        table.install((1, 5), remote("192.0.2.9:2152", 45), None);
        assert_eq!(indicated(&table, 45, "192.0.2.9"), Some((1, 5)));
        assert_indexed(&table, 1);
        // A local TEID that something else assigned replaces the tunnel.
        table
            .install_with_teid((1, 5), 77, remote("192.0.2.9:2152", 46), None)
            .unwrap();
        assert_eq!(indicated(&table, 45, "192.0.2.9"), None);
        assert_eq!(indicated(&table, 46, "192.0.2.9"), Some((1, 5)));
        assert_indexed(&table, 1);
        // A refused one leaves it as it was.
        table.install((2, 5), remote("192.0.2.9:2152", 47), None);
        let local_teid = table.route((2, 5)).unwrap().local_teid;
        assert!(
            table
                .install_with_teid((1, 5), local_teid, remote("192.0.2.9:2152", 48), None)
                .is_err()
        );
        assert_eq!(indicated(&table, 46, "192.0.2.9"), Some((1, 5)));
        assert_eq!(indicated(&table, 48, "192.0.2.9"), None);
        assert_indexed(&table, 2);
        assert_eq!(table.remove((1, 5)), Some(77));
        assert_eq!(indicated(&table, 46, "192.0.2.9"), None);
        assert_eq!(table.remove((1, 5)), None);
        assert_indexed(&table, 1);
    }

    #[test]
    fn tunnels_to_one_far_end_are_found_one_after_the_other() {
        let table = RouteTable::default();
        // As while a peer has not said its TEID yet.
        for key in [(2, 1), (1, 9), (1, 5), (3, 0)] {
            table.install(key, remote("192.0.2.1:2152", 0), Some(9));
        }
        assert_indexed(&table, 4);
        for key in [(1, 5), (1, 9), (2, 1), (3, 0)] {
            assert_eq!(indicated(&table, 0, "192.0.2.1"), Some(key));
            table.remove(key);
        }
        assert_eq!(indicated(&table, 0, "192.0.2.1"), None);
        assert_indexed(&table, 0);
    }

    #[test]
    fn removing_a_ue_removes_its_tunnels_and_no_other() {
        let table = RouteTable::default();
        let mut teids = Vec::new();
        for session in [0, 5, 255] {
            teids.push(table.install((7, session), remote("192.0.2.1:2152", 44), Some(9)));
        }
        table.install((6, 255), remote("192.0.2.1:2152", 44), Some(9));
        table.install((8, 0), remote("192.0.2.1:2152", 44), Some(9));
        let mut removed = table.remove_ran(7);
        removed.sort_unstable();
        teids.sort_unstable();
        assert_eq!(removed, teids);
        assert_eq!(table.remove_ran(7), []);
        assert_indexed(&table, 2);
        assert!(table.route((6, 255)).is_some());
        assert!(table.route((8, 0)).is_some());
        assert_eq!(indicated(&table, 44, "192.0.2.1"), Some((6, 255)));
        assert_eq!(table.remove_ran(u32::MAX), []);
        assert_eq!(table.remove_ran(6).len(), 1);
        assert_eq!(table.remove_ran(8).len(), 1);
        assert_indexed(&table, 0);
    }

    /// Anyone who reaches the socket can send an Error Indication, and a UE
    /// that leaves has its tunnels removed: neither walks through the
    /// tunnels. With 100 000 of them, a walk for each of these 40 000 calls
    /// takes several seconds in an optimized build and a minute in this one.
    #[test]
    fn an_error_indication_and_the_removal_of_a_ue_do_not_walk_through_the_tunnels() {
        const TUNNELS: u32 = 100_000;
        const CALLS: u32 = 20_000;
        let table = RouteTable::default();
        for ran_id in 0..TUNNELS {
            let far_end = remote("192.0.2.1:2152", 0x1000_0000 + ran_id);
            table.install((ran_id, 5), far_end, Some(9));
        }
        let unmatched = Packet::error_indication(0x0bad_f00d, "192.0.2.1".parse().unwrap());
        let start = std::time::Instant::now();
        for _ in 0..CALLS {
            assert_eq!(table.error_indication_session(&unmatched), None);
        }
        for ran_id in 0..CALLS {
            assert_eq!(table.remove_ran(ran_id).len(), 1);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "{CALLS} Error Indications and {CALLS} removals took {elapsed:?}"
        );
        assert_indexed(&table, (TUNNELS - CALLS) as usize);
    }
}
