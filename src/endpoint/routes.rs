//! The indexes of the endpoint's tunnel registry, and the tunnels' TUNs.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;
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
    #[cfg(fast_path)]
    pub(super) fast_path: Option<crate::ebpf::FastPath>,
}

#[cfg(all(target_os = "linux", feature = "tun"))]
impl Drop for TunAttachment {
    fn drop(&mut self) {
        self.reader.abort();
        // First: another interface may get the index of a closed TUN.
        #[cfg(fast_path)]
        if let Some(fast_path) = &self.fast_path {
            fast_path.remove_tun(self.port.index());
        }
        self.port.close();
    }
}

/// Without the `tun` feature no tunnel has a TUN.
#[cfg(not(all(target_os = "linux", feature = "tun")))]
pub(super) enum TunAttachment {}

/// A fast path and the N3 address of the endpoint that has it.
#[cfg(fast_path)]
pub(super) type N3FastPath = (crate::ebpf::FastPath, std::net::Ipv4Addr);

/// The tunnels of an endpoint, and its fast path, to which each change of a
/// tunnel is applied with the tunnels locked: two changes of a tunnel that
/// come at once reach its short-cut in the order that they reached the
/// table.
#[derive(Default)]
pub(super) struct RouteTable {
    routes: Mutex<Routes>,
    #[cfg(fast_path)]
    fast_path: std::sync::OnceLock<N3FastPath>,
}

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
    teids: Teids,
    /// The TUNs of the tunnels that have one.
    tuns: HashMap<SessionKey, TunAttachment>,
}

/// Where local TEIDs come from. The TEID alone identifies a tunnel, so one
/// that a peer could guess from another, as 1, 2, 3 are, lets whoever
/// reaches the socket send on the tunnels of others: each TEID is a keyed
/// hash (SipHash) of a count, under a key of the endpoint's own, chosen at
/// random.
#[derive(Default)]
struct Teids {
    key: RandomState,
    drawn: u64,
}

impl Teids {
    fn next(&mut self) -> u32 {
        self.drawn += 1;
        // The low half of the hash.
        self.key.hash_one(self.drawn) as u32
    }
}

/// The first of `candidates` that a local TEID can be: not 0 and not
/// `live`.
fn first_free(mut candidates: impl FnMut() -> u32, live: impl Fn(u32) -> bool) -> u32 {
    loop {
        let teid = candidates();
        if teid != 0 && !live(teid) {
            return teid;
        }
    }
}

impl Routes {
    fn allocate_teid(&mut self) -> u32 {
        let by_teid = &self.by_teid;
        first_free(|| self.teids.next(), |teid| by_teid.contains_key(&teid))
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
    /// Give the table its fast path, unless it has one.
    #[cfg(fast_path)]
    pub(super) fn set_fast_path(&self, fast_path: N3FastPath) -> Result<(), N3FastPath> {
        self.fast_path.set(fast_path)
    }

    #[cfg(fast_path)]
    pub(super) fn fast_path(&self) -> Option<&N3FastPath> {
        self.fast_path.get()
    }

    /// Apply a tunnel's change, or its removal, to its short-cut. The
    /// caller holds the tunnels' lock.
    #[cfg(fast_path)]
    fn sync(&self, local_teid: u32, route: Option<(RemoteTunnel, Option<u8>)>) {
        if let Some((fast_path, local)) = self.fast_path.get() {
            fast_path.refresh(*local, local_teid, route);
        }
    }

    #[cfg(not(fast_path))]
    fn sync(&self, _local_teid: u32, _route: Option<(RemoteTunnel, Option<u8>)>) {}

    pub(super) fn install(&self, key: SessionKey, remote: RemoteTunnel, qfi: Option<u8>) -> u32 {
        let routes = &mut *lock(&self.routes);
        let local_teid = match routes.by_session.get_mut(&key) {
            Some(route) => {
                let former = std::mem::replace(&mut route.remote, remote);
                route.qfi = qfi;
                let local_teid = route.local_teid;
                routes.by_remote.remove(&(remote_key(&former), key));
                routes.by_remote.insert((remote_key(&remote), key));
                local_teid
            }
            None => {
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
        };
        self.sync(local_teid, Some((remote, qfi)));
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
        let mut routes = lock(&self.routes);
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
        let replaced = routes.by_session.get(&key).map(|route| route.local_teid);
        routes.insert(
            key,
            Route {
                local_teid,
                remote,
                qfi,
            },
        );
        if let Some(replaced) = replaced.filter(|replaced| *replaced != local_teid) {
            self.sync(replaced, None);
        }
        self.sync(local_teid, Some((remote, qfi)));
        Ok(())
    }

    pub(super) fn route(&self, key: SessionKey) -> Option<Route> {
        lock(&self.routes).by_session.get(&key).copied()
    }

    /// Run `f` on a route that cannot change or go away meanwhile.
    #[cfg(fast_path)]
    pub(super) fn with_route<T>(&self, key: SessionKey, f: impl FnOnce(Route) -> T) -> Option<T> {
        lock(&self.routes).by_session.get(&key).copied().map(f)
    }

    /// End the short-cut of every tunnel, when the endpoint stops.
    #[cfg(fast_path)]
    pub(super) fn end_shortcuts(&self) {
        let routes = lock(&self.routes);
        for local_teid in routes.by_teid.keys() {
            self.sync(*local_teid, None);
        }
    }

    pub(super) fn session(&self, local_teid: u32) -> Option<SessionKey> {
        lock(&self.routes).by_teid.get(&local_teid).copied()
    }

    /// Returns the local TEID of the removed tunnel, whose TUN closes.
    pub(super) fn remove(&self, key: SessionKey) -> Option<u32> {
        // The TUN closes once the lock is released: that is netlink I/O.
        let (route, _tun) = {
            let mut routes = lock(&self.routes);
            let route = routes.remove(key);
            if let Some(route) = &route {
                self.sync(route.local_teid, None);
            }
            (route, routes.tuns.remove(&key))
        };
        route.map(|route| route.local_teid)
    }

    /// Returns the local TEIDs of the removed tunnels, whose TUNs close.
    pub(super) fn remove_ran(&self, ran_id: u32) -> Vec<u32> {
        let mut routes = lock(&self.routes);
        let keys: Vec<_> = routes
            .by_ran
            .range((ran_id, u8::MIN)..=(ran_id, u8::MAX))
            .copied()
            .collect();
        let _tuns: Vec<_> = keys
            .iter()
            .filter_map(|key| routes.tuns.remove(key))
            .collect();
        let teids: Vec<u32> = keys
            .into_iter()
            .filter_map(|key| routes.remove(key))
            .map(|route| route.local_teid)
            .collect();
        for local_teid in &teids {
            self.sync(*local_teid, None);
        }
        // As above: the TUNs close after it.
        drop(routes);
        teids
    }

    /// Close every tunnel's TUN.
    pub(super) fn close_tuns(&self) {
        // As above: the lock is released at the end of this statement.
        let _tuns = std::mem::take(&mut lock(&self.routes).tuns);
    }

    /// Whether tunnel `key` can get a TUN: it exists and has none.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn tun_slot(&self, key: SessionKey) -> io::Result<()> {
        lock(&self.routes).tun_slot(key)
    }

    /// Give tunnel `key` its TUN, if it still can get one.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn attach_tun(&self, key: SessionKey, tun: TunAttachment) -> io::Result<()> {
        let mut routes = lock(&self.routes);
        // On an error `tun` closes once the lock is released: a parameter
        // is dropped after the locals.
        routes.tun_slot(key)?;
        routes.tuns.insert(key, tun);
        Ok(())
    }

    /// The TUN of tunnel `key`.
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(super) fn tun(&self, key: SessionKey) -> Option<TunPort> {
        lock(&self.routes)
            .tuns
            .get(&key)
            .map(|tun| tun.port.clone())
    }

    pub(super) fn len(&self) -> usize {
        lock(&self.routes).by_session.len()
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
        lock(&self.routes)
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
        let mut candidates = [0, 7, 9, 0, 9, 11].into_iter();
        let live = |teid| teid == 7;
        assert_eq!(first_free(|| candidates.next().unwrap(), live), 9);
        assert_eq!(first_free(|| candidates.next().unwrap(), live), 9);
        assert_eq!(first_free(|| candidates.next().unwrap(), live), 11);
        // The next TEIDs of a table, of which the first two are in use.
        let mut routes = Routes::default();
        let mut copy = Teids {
            key: routes.teids.key.clone(),
            drawn: 0,
        };
        let next: Vec<u32> = (0..3).map(|_| copy.next()).collect();
        routes.by_teid.insert(next[0], (1, 1));
        routes.by_teid.insert(next[1], (1, 2));
        assert_eq!(routes.allocate_teid(), next[2]);
    }

    /// Whoever knows a TEID of an endpoint cannot tell another from it.
    #[test]
    fn local_teids_cannot_be_told_from_one_another() {
        let teids = |table: &RouteTable| -> Vec<u32> {
            (0..100)
                .map(|session| table.install((1, session), remote("192.0.2.1:2152", 44), None))
                .collect()
        };
        let (first, second) = (teids(&RouteTable::default()), teids(&RouteTable::default()));
        assert_ne!(first[..3], [1, 2, 3]);
        // Neither one after the other, nor what another endpoint gives.
        let next = first
            .windows(2)
            .filter(|pair| pair[1] == pair[0].wrapping_add(1));
        assert_eq!(next.count(), 0, "{first:x?}");
        assert_ne!(first, second);
        let mut unique = first.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 100);
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
        let routes = lock(&table.routes);
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
