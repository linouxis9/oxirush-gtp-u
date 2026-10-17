//! The eBPF fast path of an [`Endpoint`](crate::Endpoint)'s tunnels.
//!
//! [`FastPath::load`] loads three TCX programs. Once an endpoint has the fast
//! path ([`Endpoint::set_fast_path`](crate::Endpoint::set_fast_path)), a TUN
//! is on it ([`FastPath::add_tun`]) and a tunnel has that TUN
//! ([`Endpoint::shortcut`](crate::Endpoint::shortcut)), they encapsulate
//! what Linux routes into the TUN and decapsulate what the N3 interface
//! receives for it. What they leave alone still goes through
//! userspace, the endpoint's socket and the TUN's reader: anything but
//! IPv4 in a G-PDU without extension header other than one PDU Session
//! Container, fragments, G-PDUs longer than the MTU of N3, and ICMP Echo
//! Replies, which whoever pings through the endpoint expects there.
//!
//! It needs Linux 6.6 (TCX), `CAP_BPF` and `CAP_NET_ADMIN`.
//!
//! [`Endpoint::attach_tun`](crate::Endpoint::attach_tun) puts the TUN it
//! makes on the endpoint's fast path and short-cuts its tunnel:
//!
//! ```no_run
//! use oxirush_gtp_u::ebpf::FastPath;
//! use oxirush_gtp_u::tun::{Routing, TunConfig};
//! use oxirush_gtp_u::{Endpoint, RemoteTunnel};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> std::io::Result<()> {
//! let (gnb, _received) = Endpoint::bind("192.0.2.1:2152".parse().unwrap()).await?;
//! let fast_path = FastPath::load()?;
//! gnb.set_fast_path(fast_path.clone())?;
//! gnb.install(1, 5, RemoteTunnel::new("192.0.2.2:2152".parse().unwrap(), 0x1001), 9)?;
//!
//! let routing = Routing::UePolicy {
//!     address: "10.45.0.2".parse().unwrap(),
//!     table: 100,
//!     priority: 100,
//! };
//! gnb.attach_tun(1, 5, TunConfig::new("ue0", routing))?;
//! # Ok(())
//! # }
//! ```
//!
//! A program that carries a TUN of its own does these steps itself:
//!
//! ```no_run
//! # use oxirush_gtp_u::ebpf::FastPath;
//! # use oxirush_gtp_u::tun::TunPort;
//! # use oxirush_gtp_u::Endpoint;
//! # fn steps(gnb: &Endpoint, fast_path: &FastPath, tun: &TunPort) -> std::io::Result<()> {
//! // Once, when the TUN is made:
//! fast_path.add_tun(tun.index())?;
//! // When userspace carried a packet of the tunnel from the TUN, and the
//! // TUN has no short-cut. On `WouldBlock`, ask with a later packet; on
//! // another error, after a while: each asking looks up a route.
//! if !fast_path.has_shortcut(tun.index()) {
//!     gnb.shortcut(1, 5, tun.index())?;
//! }
//! // Before the TUN is closed:
//! fast_path.remove_tun(tun.index());
//! # Ok(())
//! # }
//! ```
//! # The programs
//!
//! [`FastPath::load`] loads three TCX programs:
//!
//! - `uplink`, at the egress of a TUN, hands the IPv4 packets of a short-cut
//!   tunnel to the stage. The stage is a veth pair without checksum offload,
//!   so that Linux splits the large segments of the UE's TCP stack and
//!   completes their checksums before the encapsulation. It has the largest
//!   MTU: whatever a TUN lets through crosses it.
//! - `encap`, at the far end of the stage, writes the IPv4, UDP and GTP-U
//!   headers, with the PDU Session Container of an N3 tunnel, and sends the
//!   G-PDU out of the N3 interface. The G-PDU is the one the codec encodes.
//!   Its IPv4 header has DSCP 0, a TTL of 64, Don't Fragment and an
//!   identification of 0, and its UDP header port 2152 at both ends, as
//!   what the endpoint's socket sends but for the identification; its mark
//!   is 0 as theirs, whatever the inner packet's. Its UDP checksum is 0,
//!   where the socket's has one: IPv4 allows it, and TS 29.281 §4.4.2.0
//!   asks for a checksum over IPv6 only.
//! - `decap`, at the ingress of the N3 interface, delivers the G-PDUs of
//!   short-cut tunnels to their TUN. It checks their IPv4 header as Linux
//!   does before it delivers a datagram, its checksum and its total length,
//!   and leaves to Linux one that Linux drops. It does not check the UDP
//!   checksum, which a TCX program cannot: it is not told whether Linux or
//!   the network card checked it, and that of a G-PDU from a socket of the
//!   same host, on loopback or a veth, is still to be completed there. The
//!   inner packet's own checksums are checked where it is delivered.
//!
//! The N3 interface of a tunnel is the one Linux routes it through, from the
//! endpoint's address to the peer's: the loopback interface for a peer on the
//! same host. It gets `decap` when a first tunnel through it is installed, on
//! a blocking thread of the Tokio runtime, so that the task that installs the
//! tunnel does not wait for it (outside a runtime the caller attaches it).
//! Until it is there the tunnel stays in userspace.
//!
//! `Endpoint::attach_tun` does the rest for the TUN it makes. A program that
//! carries a TUN of its own does it in three calls. [`FastPath::add_tun`] puts
//! the TUN on the fast path, once: it attaches `uplink` in the caller's
//! thread. `Endpoint::shortcut` gives the TUN its tunnel, when the TUN's
//! reader carried a packet and the TUN has no short-cut
//! ([`FastPath::has_shortcut`]): it fails with `WouldBlock` while the N3
//! interface is getting its program, and a later packet asks again.
//! `attach_tun` asks each millisecond at most then, and a second after
//! another failure. And [`FastPath::remove_tun`] takes the TUN off the fast
//! path, before it is closed.
//!
//! # Short-cuts
//!
//! A short-cut follows its tunnel. `install` on the tunnel updates it;
//! `remove` and the endpoint's `shutdown` end it, and so does giving the TUN
//! another tunnel or the tunnel another TUN. Each change reaches it with the
//! endpoint's tunnels locked, so that two changes that come at once reach it
//! in the order that they reached the endpoint. [`FastPath::end_shortcut`] leaves
//! a TUN's tunnel to userspace until the next `shortcut`, as when its UE moves
//! to another endpoint. When `shortcut` fails the tunnel stays in userspace.
//!
//! The programs leave to userspace, which keeps working underneath: other
//! messages than G-PDUs, unknown TEIDs, extension headers other than one PDU
//! Session Container, fragments, inner packets that are not IPv4, G-PDUs
//! longer than the MTU of N3 (the socket fragments them), and ICMP Echo Replies,
//! which a caller that pings through the endpoint expects on its receiver.
//! What they leave also goes on to the interface's other TCX programs and tc
//! filters (`TC_ACT_UNSPEC`), so several fast paths or other tools can share
//! an N3 interface. [`FastPath::stats`] counts the packets carried, returned
//! as too long and dropped.
//!
//! # What it needs and leaves
//!
//! The endpoint must be bound to an IPv4 address and port 2152, and a
//! tunnel's peer must be IPv4 on port 2152 too. Everything happens in the
//! network namespace `load` was called in. `load` fails without TCX or the
//! capabilities and then leaves nothing behind. The programs' links go with
//! the process, whatever ends it. The stage, `oxs` with eight hexadecimal
//! digits, outlives a killed process; the next `load` in that namespace
//! removes it, as an `oxs` veth that is up and whose far end has the alias
//! `oxirush-gtp-u fast path stage` and no program left.
//!
//! `load` starts a thread that follows the MTU of the N3 interfaces, which
//! Linux announces over rtnetlink, and writes it into the short-cuts: a
//! program cannot read it but through a helper that is for GPL programs
//! alone, and the programs are Apache-2.0. The thread ends within a second
//! of the last clone of the fast path. When it loses the announcements it
//! asks for the MTU of each N3 interface again, and when its socket fails it
//! takes another, once a second at most: a second failure within the second
//! ends it, with a warning, and [`FastPath::follows_mtus`] then has the
//! error. From then on the short-cuts keep the MTU that they have.
//!
//! `load` and `add_tun` also spread what the stage's far end and the TUN
//! receive over the CPUs the process may use (RPS), when `/sys` shows the
//! process's network namespace. After `unshare --net` alone it shows the former
//! one, and nothing is steered.
//!
//! # The object
//!
//! The programs' source is `src/ebpf/programs.rs` and their object
//! `src/ebpf/gtpu.o`: building the crate needs no nightly toolchain and no
//! eBPF linker. `ebpf/build.sh` rebuilds the object, with the nightly
//! toolchain that `ebpf/rust-toolchain.toml` pins, `rust-src` and
//! `bpf-linker`; CI rebuilds it the same way with bpf-linker 0.11.1 and fails
//! when it differs from the committed one. The published crate has these files
//! too: in a copy of it, `ebpf/build.sh` rebuilds the object that it ships.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeSet, HashMap};
use std::ffi::CStr;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aya::maps::{HashMap as Map, MapData, PerCpuArray};
use aya::programs::tc::{SchedClassifierLinkId, TcAttachOptions};
use aya::programs::{LinkOrder, SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader, Pod};

use crate::RemoteTunnel;
use crate::netlink::{LinkEvents, Netlink};
use crate::path::lock;

mod layout;
use layout::{
    DOWNLINK_PACKETS, DownlinkKey, NO_CONTAINER, UPLINK_DROPS, UPLINK_OVERSIZED, UPLINK_PACKETS,
    Uplink,
};

/// Built from `ebpf/programs.rs` by the crate in `ebpf/` (`ebpf/build.sh`).
static OBJECT: &[u8] = aya::include_bytes_aligned!("ebpf/gtpu.o");

/// The stage is a veth pair `oxs<8 hexadecimal digits>a` and `…b`, with
/// random digits.
const STAGE: &str = "oxs";

/// The alias of the stage's far end: what tells a stage that a killed
/// process left from an interface of that name that is not one.
const STAGE_ALIAS: &str = "oxirush-gtp-u fast path stage";

// SAFETY: plain data without implicit padding.
unsafe impl Pod for Uplink {}
// SAFETY: as above.
unsafe impl Pod for DownlinkKey {}

/// What the programs did with the packets, summed over the CPUs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FastPathStats {
    /// Uplink packets encapsulated and sent out of N3.
    pub uplink_packets: u64,
    /// Uplink packets too long for N3 once encapsulated, returned to the
    /// TUN's reader.
    pub uplink_oversized: u64,
    /// Uplink packets a program dropped: a helper failed, or their tunnel was
    /// removed after they left the TUN.
    pub uplink_drops: u64,
    /// Downlink packets decapsulated into their TUN.
    pub downlink_packets: u64,
}

/// The loaded programs and their stage. Clones share them; dropping the last
/// one removes them.
#[derive(Clone)]
pub struct FastPath {
    inner: Arc<Inner>,
}

struct Inner {
    // The programs and their links go before the stage, which `state` has.
    /// Attaching a program takes milliseconds. Inside a Tokio runtime
    /// whoever holds this lock does not hold `state`, which a tunnel's
    /// set-up and short-cut need.
    programs: Mutex<Ebpf>,
    state: Mutex<State>,
    /// Tells the thread that follows the MTU of the N3 interfaces to end.
    stop: Arc<AtomicBool>,
    /// The error that ended that thread, if one did.
    mtus: Arc<Mutex<Option<(io::ErrorKind, String)>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Map `UPLINKS`, and its entries in memory: the thread that follows the
/// MTU of the N3 interfaces looks at them for each link that Linux
/// announces, which a creation of a TUN is too, and a read of the map is
/// a system call an entry.
struct Uplinks {
    map: Map<MapData, u32, Uplink>,
    entries: HashMap<u32, Uplink>,
}

impl Uplinks {
    fn insert(&mut self, tun: u32, uplink: Uplink) -> io::Result<()> {
        self.map.insert(tun, uplink, 0).map_err(io::Error::other)?;
        self.entries.insert(tun, uplink);
        Ok(())
    }

    fn remove(&mut self, tun: u32) {
        let _ = self.map.remove(&tun);
        self.entries.remove(&tun);
    }

    /// Give the short-cuts through N3 interface `n3` its MTU, `mtu`.
    fn apply_mtu(&mut self, n3: u32, mtu: u32) {
        for (tun, uplink) in with_mtu(&self.entries, n3, mtu) {
            if self.map.insert(tun, uplink, 0).is_ok() {
                self.entries.insert(tun, uplink);
            }
        }
    }
}

/// The entries of the short-cuts through N3 interface `n3` whose MTU is
/// not `mtu`, with it.
fn with_mtu(entries: &HashMap<u32, Uplink>, n3: u32, mtu: u32) -> Vec<(u32, Uplink)> {
    let mtu = u16::try_from(mtu).unwrap_or(u16::MAX);
    entries
        .iter()
        .filter(|(_, uplink)| uplink.n3 == n3 && uplink.mtu != mtu)
        .map(|(tun, uplink)| (*tun, Uplink { mtu, ..*uplink }))
        .collect()
}

struct State {
    /// Shared with the thread that follows the MTU of the N3 interfaces,
    /// which takes this lock alone. Whoever takes both takes `state` first.
    uplinks: Arc<Mutex<Uplinks>>,
    downlinks: Map<MapData, DownlinkKey, u32>,
    stats: PerCpuArray<MapData, u64>,
    /// The N3 interfaces and their `decap` program.
    n3s: HashMap<u32, N3>,
    /// The TUN interfaces with the `uplink` program.
    tuns: HashMap<u32, Tun>,
    /// Whether `/sys` shows this network namespace: its devices are then
    /// ours to steer.
    steering: bool,
    stage: Stage,
}

struct Tun {
    uplink: SchedClassifierLinkId,
    /// Its short-cut tunnel.
    key: Option<DownlinkKey>,
}

/// The `decap` program of an N3 interface.
enum N3 {
    /// Being attached since a first tunnel through the interface was
    /// installed: its tunnels stay in userspace meanwhile.
    Attaching,
    Attached,
    /// Why it could not be attached: its tunnels stay in userspace.
    Failed(String),
}

struct Stage {
    netlink: Netlink,
    index: u32,
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = self.netlink.delete_link(self.index);
    }
}

impl FastPath {
    /// Load the programs and create the stage, a veth pair without checksum
    /// offload. The UEs' packets cross it before their encapsulation:
    /// transmitting through it splits the large segments of their TCP stack
    /// and completes their checksums.
    ///
    /// It fails without TCX (Linux 6.6) or without the rights to load eBPF
    /// programs and create interfaces, and leaves nothing behind then. It
    /// first removes the stage a killed process left in this network
    /// namespace: an `oxs` veth that is up and whose far end has the
    /// stage's alias and no TCX program. Everything else the fast path does must happen in the
    /// network namespace of this call.
    pub fn load() -> io::Result<Self> {
        let mut netlink = Netlink::new()?;
        // Before anything is read of the links: a change of an MTU from
        // now on is announced to it.
        let events = LinkEvents::new()?;
        remove_stale_stages(&mut netlink);
        let id = RandomState::new().build_hasher().finish() as u32;
        let (near, far) = (format!("{STAGE}{id:08x}a"), format!("{STAGE}{id:08x}b"));
        netlink
            .add_veth(&near, &far)
            .map_err(|error| context(error, "create the stage"))?;
        let index = netlink.index_of(&near)?;
        let mut stage = Stage { netlink, index };
        let far_index = stage.netlink.index_of(&far)?;
        stage.netlink.set_alias(far_index, STAGE_ALIAS)?;
        for end in [index, far_index] {
            // Otherwise Linux announces their IPv6 addresses to the programs.
            match stage.netlink.disable_ipv6_addresses(end) {
                Err(error)
                    if !matches!(
                        error.raw_os_error(),
                        Some(libc::EAFNOSUPPORT | libc::EOPNOTSUPP)
                    ) =>
                {
                    return Err(error);
                }
                _ => {}
            }
        }
        disable_tx_checksum(&near)?;

        let mut ebpf = EbpfLoader::new()
            .override_global("STAGE", &index, true)
            .load(OBJECT)
            .map_err(|error| other("load the eBPF programs", error))?;
        for name in ["uplink", "encap", "decap"] {
            program(&mut ebpf, name)?
                .load()
                .map_err(|error| other("load the eBPF programs", error))?;
        }
        attach(&mut ebpf, "encap", &far, TcAttachType::Ingress)?;
        // Up only now: a stage that is up without its program is a dead
        // process's, which the next load removes.
        stage.netlink.set_up(index)?;
        stage.netlink.set_up(far_index)?;
        // A stage of that name and index is this namespace's only.
        let steering = std::fs::read_to_string(format!("/sys/class/net/{far}/ifindex"))
            .is_ok_and(|index| index.trim().parse() == Ok(far_index));
        if steering {
            steer(&far);
        }
        let mut map = |name| {
            ebpf.take_map(name)
                .ok_or_else(|| io::Error::other(format!("no eBPF map {name}")))
        };
        let (uplinks, downlinks, stats) = (map("UPLINKS")?, map("DOWNLINKS")?, map("STATS")?);
        let uplinks = Arc::new(Mutex::new(Uplinks {
            map: Map::try_from(uplinks).map_err(io::Error::other)?,
            entries: HashMap::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let mtus = Arc::new(Mutex::new(None));
        let follow = {
            let (uplinks, stop, ended) = (uplinks.clone(), stop.clone(), mtus.clone());
            let mut links = Rtnetlink {
                events,
                requests: Netlink::new()?,
            };
            move || {
                if let Err(error) = follow_mtus(&*uplinks, &stop, &mut links) {
                    tracing::warn!(
                        "the fast path no longer follows the MTU of the N3 interfaces: {error}"
                    );
                    *lock(&ended) = Some((error.kind(), error.to_string()));
                }
            }
        };
        std::thread::Builder::new()
            .name("gtp-u fast path".into())
            .spawn(follow)?;
        let state = State {
            uplinks,
            downlinks: Map::try_from(downlinks).map_err(io::Error::other)?,
            stats: PerCpuArray::try_from(stats).map_err(io::Error::other)?,
            n3s: HashMap::new(),
            tuns: HashMap::new(),
            steering,
            stage,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                programs: Mutex::new(ebpf),
                state: Mutex::new(state),
                stop,
                mtus,
            }),
        })
    }

    /// Whether the thread that follows the MTU of the N3 interfaces still
    /// does: the error that ended it otherwise. From then on the short-cuts
    /// keep the MTU that they have, and a G-PDU that no longer fits a
    /// smaller one is dropped where Linux would have fragmented it; a new
    /// `load` has a thread of its own.
    pub fn follows_mtus(&self) -> io::Result<()> {
        match &*lock(&self.inner.mtus) {
            None => Ok(()),
            Some((kind, text)) => Err(io::Error::new(*kind, text.clone())),
        }
    }

    /// The packet counters.
    pub fn stats(&self) -> FastPathStats {
        let state = lock(&self.inner.state);
        let sum = |counter| {
            state
                .stats
                .get(&counter, 0)
                .map_or(0, |values| values.iter().sum())
        };
        FastPathStats {
            uplink_packets: sum(UPLINK_PACKETS),
            uplink_oversized: sum(UPLINK_OVERSIZED),
            uplink_drops: sum(UPLINK_DROPS),
            downlink_packets: sum(DOWNLINK_PACKETS),
        }
    }

    /// Put TUN interface `tun` on the fast path: the programs carry its
    /// packets once [`Endpoint::shortcut`](crate::Endpoint::shortcut) gives
    /// it a tunnel. Attaching a program takes milliseconds: call it once,
    /// when the TUN is created.
    pub fn add_tun(&self, tun: u32) -> io::Result<()> {
        if lock(&self.inner.state).tuns.contains_key(&tun) {
            return Ok(());
        }
        let name = name_of(tun)?;
        let uplink = attach(
            &mut lock(&self.inner.programs),
            "uplink",
            &name,
            TcAttachType::Egress,
        )?;
        let mut state = lock(&self.inner.state);
        if state.steering {
            steer(&name);
        }
        state.tuns.insert(tun, Tun { uplink, key: None });
        Ok(())
    }

    /// Take TUN interface `tun` off the fast path, with its tunnel's
    /// short-cut. Call it before the TUN is closed, whose index another
    /// interface may then get.
    pub fn remove_tun(&self, tun: u32) {
        let removed = {
            let mut state = lock(&self.inner.state);
            state.end_shortcut(tun);
            state.tuns.remove(&tun)
        };
        let Some(tun) = removed else {
            return;
        };
        if let Ok(program) = program(&mut lock(&self.inner.programs), "uplink") {
            let _ = program.detach(tun.uplink);
        }
    }

    /// Leave the tunnel of TUN interface `tun` to userspace again, until its
    /// next short-cut: when its UE leaves for another endpoint.
    pub fn end_shortcut(&self, tun: u32) {
        lock(&self.inner.state).end_shortcut(tun);
    }

    /// Whether TUN interface `tun` has a tunnel's short-cut: the reader of
    /// a TUN that has one need not ask for it again.
    pub fn has_shortcut(&self, tun: u32) -> bool {
        lock(&self.inner.state)
            .tuns
            .get(&tun)
            .is_some_and(|tun| tun.key.is_some())
    }

    /// Short-cut the tunnel of the endpoint at `local` with local TEID
    /// `teid` through TUN interface `tun`, in place of the TUN's former
    /// tunnel if any. A failure leaves the tunnel to userspace.
    pub(crate) fn shortcut(
        &self,
        tun: u32,
        local: Ipv4Addr,
        teid: u32,
        remote: RemoteTunnel,
        qfi: Option<u8>,
    ) -> io::Result<()> {
        let mut state = lock(&self.inner.state);
        let result = self.try_shortcut(&mut state, tun, local, teid, remote, qfi);
        if result.is_err() {
            state.end_shortcut(tun);
        }
        result
    }

    /// Apply the new remote end and QFI of the endpoint's tunnel `teid`, or
    /// its removal, to its short-cut if it has one. A tunnel's N3 interface
    /// gets its program now, before the tunnel's first packet.
    pub(crate) fn refresh(
        &self,
        local: Ipv4Addr,
        teid: u32,
        route: Option<(RemoteTunnel, Option<u8>)>,
    ) {
        let mut state = lock(&self.inner.state);
        if let Some(Ok((_, n3))) = route.map(|(remote, _)| state.n3(local, remote)) {
            let _ = self.serve(&mut state, n3);
        }
        let Ok(tun) = state.downlinks.get(&key(local, teid), 0) else {
            return;
        };
        let kept = route.is_some_and(|(remote, qfi)| {
            self.try_shortcut(&mut state, tun, local, teid, remote, qfi)
                .is_ok()
        });
        if !kept {
            state.end_shortcut(tun);
        }
    }

    /// A route lookup and two map entries, once the N3 interface has its
    /// program.
    fn try_shortcut(
        &self,
        state: &mut State,
        tun: u32,
        local: Ipv4Addr,
        teid: u32,
        remote: RemoteTunnel,
        qfi: Option<u8>,
    ) -> io::Result<()> {
        let (peer, n3) = state.n3(local, remote)?;
        if !state.tuns.contains_key(&tun) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {tun} is not on the fast path"),
            ));
        }
        self.serve(state, n3)?;
        state.write(tun, key(local, teid), peer, remote.teid, n3, qfi)
    }

    /// Have `decap` on N3 interface `n3`. Attaching it takes milliseconds,
    /// which a blocking thread of the Tokio runtime spends, not the caller:
    /// until it is done this fails with [`io::ErrorKind::WouldBlock`].
    /// Outside a runtime the caller attaches it.
    fn serve(&self, state: &mut State, n3: u32) -> io::Result<()> {
        let attached = state.n3s.entry(n3).or_insert_with(|| {
            let inner = self.inner.clone();
            let attach = move || {
                let attached = name_of(n3).and_then(|name| {
                    let mut programs = lock(&inner.programs);
                    attach(&mut programs, "decap", &name, TcAttachType::Ingress)
                });
                match attached {
                    Ok(_) => N3::Attached,
                    Err(error) => N3::Failed(error.to_string()),
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    let inner = self.inner.clone();
                    runtime.spawn_blocking(move || {
                        let attached = attach();
                        lock(&inner.state).n3s.insert(n3, attached);
                    });
                    N3::Attaching
                }
                Err(_) => attach(),
            }
        });
        match attached {
            N3::Attached => Ok(()),
            N3::Attaching => Err(io::ErrorKind::WouldBlock.into()),
            N3::Failed(error) => Err(io::Error::other(error.clone())),
        }
    }
}

impl fmt::Debug for FastPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FastPath")
            .field("tuns", &lock(&self.inner.state).tuns.len())
            .finish()
    }
}

impl State {
    /// The peer of a tunnel and its N3 interface, the one Linux routes the
    /// tunnel through. It need not hold `local`, and it is loopback for a
    /// peer on this host, whatever their addresses: the interface holding
    /// `local` would lose the uplink there, and never see the downlink.
    fn n3(&mut self, local: Ipv4Addr, remote: RemoteTunnel) -> io::Result<(Ipv4Addr, u32)> {
        // The programs send to the GTP-U port of an IPv4 peer.
        let peer = match remote.address.ip().to_canonical() {
            IpAddr::V4(peer) if remote.address.port() == crate::PORT => peer,
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        let n3 = self.stage.netlink.route_interface(local, peer)?;
        Ok((peer, n3))
    }

    /// The two map entries of the short-cut of tunnel `key` through `tun`.
    fn write(
        &mut self,
        tun: u32,
        key: DownlinkKey,
        peer: Ipv4Addr,
        remote_teid: u32,
        n3: u32,
        qfi: Option<u8>,
    ) -> io::Result<()> {
        // A tunnel has one short-cut: the TUN that had it goes back to
        // userspace.
        match self.downlinks.get(&key, 0) {
            Ok(other) if other != tun => self.end_shortcut(other),
            _ => {}
        }
        let former = self.tuns.get_mut(&tun).and_then(|tun| tun.key.replace(key));
        if let Some(former) = former.filter(|former| *former != key) {
            let _ = self.downlinks.remove(&former);
        }
        // The MTU is read with the uplinks locked: a change of it that
        // comes meanwhile is applied after, by `follow_mtus`.
        let uplinks = self.uplinks.clone();
        let mut uplinks = lock(&uplinks);
        let mtu = self.stage.netlink.mtu_of(n3)?;
        let uplink = Uplink {
            local: key.local,
            peer: peer.octets(),
            teid: remote_teid.to_be_bytes(),
            n3,
            mtu: u16::try_from(mtu).unwrap_or(u16::MAX),
            qfi: qfi.unwrap_or(NO_CONTAINER),
            padding: 0,
        };
        self.downlinks
            .insert(key, tun, 0)
            .map_err(io::Error::other)?;
        uplinks.insert(tun, uplink)
    }

    fn end_shortcut(&mut self, tun: u32) {
        if let Some(key) = self.tuns.get_mut(&tun).and_then(|tun| tun.key.take()) {
            lock(&self.uplinks).remove(tun);
            let _ = self.downlinks.remove(&key);
        }
    }
}

/// What the thread that follows the MTUs reads: the announcements of the
/// links, and the answers to its requests.
trait Links {
    /// The links of the next announcement, with their MTU.
    fn next(&mut self) -> io::Result<Vec<(u32, u32)>>;
    /// Listen to the announcements on a new socket.
    fn listen_again(&mut self) -> io::Result<()>;
    /// The MTU of link `index`.
    fn mtu_of(&mut self, index: u32) -> io::Result<u32>;
}

/// What it writes: the short-cuts through each N3 interface.
trait N3Mtus {
    /// The N3 interfaces of the short-cuts.
    fn n3s(&self) -> BTreeSet<u32>;
    /// Give the short-cuts through each interface of `changed` its MTU.
    fn apply(&self, changed: Vec<(u32, u32)>);
}

struct Rtnetlink {
    events: LinkEvents,
    requests: Netlink,
}

impl Links for Rtnetlink {
    fn next(&mut self) -> io::Result<Vec<(u32, u32)>> {
        self.events.next()
    }

    fn listen_again(&mut self) -> io::Result<()> {
        self.events = LinkEvents::new()?;
        Ok(())
    }

    fn mtu_of(&mut self, index: u32) -> io::Result<u32> {
        self.requests.mtu_of(index)
    }
}

impl N3Mtus for Mutex<Uplinks> {
    fn n3s(&self) -> BTreeSet<u32> {
        lock(self)
            .entries
            .values()
            .map(|uplink| uplink.n3)
            .collect()
    }

    fn apply(&self, changed: Vec<(u32, u32)>) {
        let mut uplinks = lock(self);
        for (n3, mtu) in changed {
            uplinks.apply_mtu(n3, mtu);
        }
    }
}

/// Keep the MTU of each short-cut's N3 interface as Linux announces it,
/// until `stop`: `encap` leaves a G-PDU too long for it to userspace,
/// whose socket fragments it. A program reads no MTU of its own but
/// through a helper that is for GPL programs alone, `bpf_check_mtu`.
///
/// When announcements were lost it asks for every MTU again. An error that
/// the socket does not recover from gives it another, after which it asks
/// again too; a second such error within a second ends it, with that
/// error.
fn follow_mtus(uplinks: &impl N3Mtus, stop: &AtomicBool, links: &mut impl Links) -> io::Result<()> {
    let mut listened_again: Option<std::time::Instant> = None;
    while !stop.load(Ordering::Relaxed) {
        let changed = match links.next() {
            Ok(changed) => changed,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => ask(uplinks, links),
            Err(error) => {
                if listened_again.is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(1))
                {
                    return Err(error);
                }
                tracing::warn!(
                    "the fast path lost the announcements of the links ({error}): it listens again"
                );
                links.listen_again()?;
                listened_again = Some(std::time::Instant::now());
                ask(uplinks, links)
            }
        };
        uplinks.apply(changed);
    }
    Ok(())
}

/// The MTU of each N3 interface of the short-cuts, asked again.
fn ask(uplinks: &impl N3Mtus, links: &mut impl Links) -> Vec<(u32, u32)> {
    uplinks
        .n3s()
        .into_iter()
        .filter_map(|n3| links.mtu_of(n3).ok().map(|mtu| (n3, mtu)))
        .collect()
}

fn key(local: Ipv4Addr, teid: u32) -> DownlinkKey {
    DownlinkKey {
        local: local.octets(),
        teid: teid.to_be_bytes(),
    }
}

fn context(error: io::Error, what: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{what}: {error}"))
}

/// An aya error with its causes, the kernel's among them, each once: the
/// text of an error of aya often has that of its cause already.
fn other(what: &str, error: impl std::error::Error) -> io::Error {
    let mut message = format!("{what}: {error}");
    let mut cause = error.source();
    while let Some(error) = cause {
        let text = error.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        cause = error.source();
    }
    io::Error::other(message)
}

fn program<'a>(ebpf: &'a mut Ebpf, name: &str) -> io::Result<&'a mut SchedClassifier> {
    ebpf.program_mut(name)
        .ok_or_else(|| io::Error::other(format!("no eBPF program {name}")))?
        .try_into()
        .map_err(io::Error::other)
}

/// Attach program `name` to `interface` through TCX: the link goes with the
/// process, whatever ends it.
fn attach(
    ebpf: &mut Ebpf,
    name: &str,
    interface: &str,
    direction: TcAttachType,
) -> io::Result<SchedClassifierLinkId> {
    program(ebpf, name)?
        .attach_with_options(
            interface,
            direction,
            TcAttachOptions::TcxOrder(LinkOrder::default()),
        )
        .map_err(|error| other(&format!("attach {name} to {interface}"), error))
}

/// Whether `name` is that of a stage's far end, which has the `encap`
/// program.
fn is_far_end(name: &str) -> bool {
    name.strip_prefix(STAGE)
        .and_then(|name| name.strip_suffix('b'))
        .is_some_and(|id| id.len() == 8 && id.bytes().all(|digit| digit.is_ascii_hexdigit()))
}

/// Delete the stages of processes that ended without dropping their fast
/// path: those that are up, whose far end has the stage's alias and has
/// lost its program, which went with its process. An interface that is
/// named as a stage is and has not the alias is not one.
fn remove_stale_stages(netlink: &mut Netlink) {
    // SAFETY: the array ends with a zero index and is freed below.
    let list = unsafe { libc::if_nameindex() };
    if list.is_null() {
        return;
    }
    let mut entry = list;
    // SAFETY: `entry` stays within the array, whose names are C strings.
    while unsafe { (*entry).if_index } != 0 {
        let (index, name) = unsafe { ((*entry).if_index, CStr::from_ptr((*entry).if_name)) };
        let stale = name.to_str().is_ok_and(|name| {
            is_far_end(name)
                && netlink.is_up_veth(index, STAGE_ALIAS)
                && SchedClassifier::query_tcx(name, TcAttachType::Ingress)
                    .is_ok_and(|(_, programs)| programs.is_empty())
        });
        if stale {
            let _ = netlink.delete_link(index);
        }
        entry = unsafe { entry.add(1) };
    }
    // SAFETY: allocated by if_nameindex.
    unsafe { libc::if_freenameindex(list) };
}

/// Spread what device `name` receives over the CPUs this thread may use:
/// otherwise the CPU of whoever transmits to it, an application or the N3
/// interface, also does the encapsulation or the reception of the UE's
/// packets.
fn steer(name: &str) {
    // SAFETY: the set is plain data, which sched_getaffinity fills.
    let cpus = unsafe {
        let mut cpus: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut cpus) != 0 {
            return;
        }
        cpus
    };
    // SAFETY: CPU_ISSET reads the set within its size.
    let mask = rps_mask(|cpu| unsafe { libc::CPU_ISSET(cpu, &cpus) });
    let _ = std::fs::write(format!("/sys/class/net/{name}/queues/rx-0/rps_cpus"), mask);
}

/// The CPU bitmap as sysfs takes it: in hexadecimal groups of 32 bits, the
/// highest first.
fn rps_mask(allowed: impl Fn(usize) -> bool) -> String {
    let mut groups: Vec<u32> = (0..libc::CPU_SETSIZE as usize / 32)
        .map(|group| {
            (0..32).fold(0, |mask, bit| {
                mask | u32::from(allowed(group * 32 + bit)) << bit
            })
        })
        .collect();
    while groups.len() > 1 && groups.last() == Some(&0) {
        groups.pop();
    }
    let groups: Vec<String> = groups
        .iter()
        .rev()
        .map(|group| format!("{group:08x}"))
        .collect();
    groups.join(",")
}

fn name_of(index: u32) -> io::Result<String> {
    let mut name = [0; libc::IFNAMSIZ];
    // SAFETY: the buffer holds IFNAMSIZ octets, as the call requires.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: if_indextoname wrote a C string.
    Ok(unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

/// Clear the TX checksum offload of device `name`.
fn disable_tx_checksum(name: &str) -> io::Result<()> {
    const SIOCETHTOOL: libc::Ioctl = 0x8946;
    const ETHTOOL_STXCSUM: u32 = 0x17;
    let mut value = [ETHTOOL_STXCSUM, 0];
    // SAFETY: ifreq is plain data, for which all zeros is valid.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (target, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *target = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_data = value.as_mut_ptr().cast();
    // SAFETY: a new descriptor, owned from here on.
    let socket = unsafe {
        let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(socket)
    };
    // SAFETY: the request and the value it points to outlive the call.
    if unsafe { libc::ioctl(socket.as_raw_fd(), SIOCETHTOOL, &mut request) } < 0 {
        return Err(context(
            io::Error::last_os_error(),
            "disable the stage's checksum offload",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Links whose announcements are scripted: once they have none left,
    /// the thread is told to stop.
    struct Scripted {
        next: std::collections::VecDeque<io::Result<Vec<(u32, u32)>>>,
        listen_again: std::collections::VecDeque<io::Result<()>>,
        mtus: HashMap<u32, u32>,
        stop: Arc<AtomicBool>,
        listened_again: usize,
    }

    impl Links for Scripted {
        fn next(&mut self) -> io::Result<Vec<(u32, u32)>> {
            self.next.pop_front().unwrap_or_else(|| {
                self.stop.store(true, Ordering::Relaxed);
                Err(io::ErrorKind::TimedOut.into())
            })
        }

        fn listen_again(&mut self) -> io::Result<()> {
            self.listened_again += 1;
            self.listen_again.pop_front().unwrap_or(Ok(()))
        }

        fn mtu_of(&mut self, index: u32) -> io::Result<u32> {
            self.mtus
                .get(&index)
                .copied()
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }

    /// The short-cuts through N3 interfaces 3 and 7, and what was applied.
    struct Applied(Mutex<Vec<(u32, u32)>>);

    impl N3Mtus for Applied {
        fn n3s(&self) -> BTreeSet<u32> {
            BTreeSet::from([3, 7])
        }

        fn apply(&self, changed: Vec<(u32, u32)>) {
            lock(&self.0).extend(changed);
        }
    }

    fn scripted(
        next: Vec<io::Result<Vec<(u32, u32)>>>,
        listen_again: Vec<io::Result<()>>,
    ) -> Scripted {
        Scripted {
            next: next.into(),
            listen_again: listen_again.into(),
            mtus: HashMap::from([(3, 1500), (7, 9000)]),
            stop: Arc::new(AtomicBool::new(false)),
            listened_again: 0,
        }
    }

    fn os(code: i32) -> io::Result<Vec<(u32, u32)>> {
        Err(io::Error::from_raw_os_error(code))
    }

    /// Lost announcements, and a socket that fails once: the thread asks for
    /// every MTU again, and goes on.
    #[test]
    fn the_thread_that_follows_the_mtus_recovers_what_it_can() {
        let applied = Applied(Mutex::new(Vec::new()));
        let mut links = scripted(
            vec![
                Ok(vec![(3, 1400)]),
                os(libc::ENOBUFS),
                os(libc::EBADF),
                Ok(vec![(7, 1280)]),
            ],
            vec![],
        );
        let stop = links.stop.clone();
        follow_mtus(&applied, &stop, &mut links).unwrap();
        assert_eq!(links.listened_again, 1);
        assert_eq!(
            *lock(&applied.0),
            [
                (3, 1400),
                (3, 1500),
                (7, 9000),
                (3, 1500),
                (7, 9000),
                (7, 1280)
            ]
        );
    }

    /// A socket that fails again at once, or that cannot be had again, ends
    /// the thread with its error.
    #[test]
    fn the_thread_that_follows_the_mtus_ends_with_an_error_it_cannot_recover_from() {
        let applied = Applied(Mutex::new(Vec::new()));
        let mut links = scripted(vec![os(libc::EBADF), os(libc::EIO)], vec![]);
        let stop = links.stop.clone();
        let error = follow_mtus(&applied, &stop, &mut links).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(links.listened_again, 1);

        let mut links = scripted(
            vec![os(libc::EBADF)],
            vec![Err(io::ErrorKind::PermissionDenied.into())],
        );
        let stop = links.stop.clone();
        let error = follow_mtus(&applied, &stop, &mut links).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn the_embedded_object_holds_what_the_loader_names() {
        // An ELF object for the eBPF machine (247), little-endian.
        assert_eq!(&OBJECT[..4], b"\x7fELF");
        assert_eq!(OBJECT[5], 1);
        assert_eq!(u16::from_le_bytes([OBJECT[18], OBJECT[19]]), 247);
        for name in [
            "uplink",
            "encap",
            "decap",
            "UPLINKS",
            "DOWNLINKS",
            "STATS",
            "STAGE",
        ] {
            let symbol = format!("\0{name}\0");
            assert!(
                OBJECT
                    .windows(symbol.len())
                    .any(|window| window == symbol.as_bytes()),
                "no {name} in the object"
            );
        }
    }

    /// What a load without the rights says, as aya's errors have it: a
    /// cause whose text is in that of its error is not said again.
    #[test]
    fn an_error_says_each_of_its_causes_once() {
        #[derive(Debug)]
        struct Error(&'static str, Option<Box<Error>>);
        impl fmt::Display for Error {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for Error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1.as_deref().map(|error| error as _)
            }
        }
        let kernel = Error("Operation not permitted (os error 1)", None);
        let map = Error("failed to create map `UPLINKS`", Some(Box::new(kernel)));
        let loader = Error(
            "map error: failed to create map `UPLINKS`",
            Some(Box::new(map)),
        );
        assert_eq!(
            other("load the eBPF programs", loader).to_string(),
            "load the eBPF programs: map error: failed to create map `UPLINKS`: \
             Operation not permitted (os error 1)"
        );
    }

    /// An announced link that is no N3 of a short-cut, or whose MTU did not
    /// change, has nothing written.
    #[test]
    fn a_change_of_mtu_is_for_the_short_cuts_through_its_link() {
        let uplink = |n3, mtu| Uplink {
            local: [127, 0, 0, 1],
            peer: [127, 0, 0, 9],
            teid: [0, 0, 0x10, 1],
            n3,
            mtu,
            qfi: 9,
            padding: 0,
        };
        let entries = HashMap::from([
            (10, uplink(1, 1500)),
            (11, uplink(1, 9000)),
            (12, uplink(2, 1500)),
        ]);
        let mut changed = with_mtu(&entries, 1, 1500);
        changed.sort_by_key(|(tun, _)| *tun);
        let changed: Vec<(u32, u32, u16)> = changed
            .into_iter()
            .map(|(tun, uplink)| (tun, uplink.n3, uplink.mtu))
            .collect();
        assert_eq!(changed, [(11, 1, 1500)]);
        assert!(with_mtu(&entries, 3, 1400).is_empty());
        // A loopback interface has 65536, more than an entry holds.
        let changed = with_mtu(&entries, 2, 65536);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].1.mtu, u16::MAX);
    }

    #[test]
    fn map_layouts_have_no_implicit_padding() {
        assert_eq!(size_of::<Uplink>(), 20);
        assert_eq!(size_of::<DownlinkKey>(), 8);
        // TEIDs and addresses are in network order, as in the packets.
        let key = key(Ipv4Addr::new(127, 0, 0, 2), 0x0102_0304);
        assert_eq!((key.local, key.teid), ([127, 0, 0, 2], [1, 2, 3, 4]));
    }

    #[test]
    fn only_the_far_end_of_this_crate_s_stages_is_looked_at() {
        assert!(is_far_end("oxs0000beefb"));
        for name in [
            "oxs0000beefa",
            "oxs4242b",
            "oxs0000beegb",
            "oxu0000beefb",
            "veth0000beefb",
            "oxsb",
        ] {
            assert!(!is_far_end(name), "{name}");
        }
    }

    #[test]
    fn the_rps_bitmap_has_32_bit_groups_with_the_highest_first() {
        assert_eq!(rps_mask(|cpu| [0, 1, 3].contains(&cpu)), "0000000b");
        assert_eq!(
            rps_mask(|cpu| [0, 1, 3, 33].contains(&cpu)),
            "00000002,0000000b"
        );
        assert_eq!(rps_mask(|_| false), "00000000");
    }

    #[test]
    fn a_peer_on_this_host_is_routed_through_loopback() {
        let mut netlink = Netlink::new().unwrap();
        let (local, peer) = (Ipv4Addr::new(127, 0, 0, 3), Ipv4Addr::new(127, 0, 0, 9));
        let n3 = netlink.route_interface(local, peer).unwrap();
        assert_eq!(name_of(n3).unwrap(), "lo");
        // TEST-NET-1 is nobody's address: nothing is sent from it.
        assert!(
            netlink
                .route_interface(Ipv4Addr::new(192, 0, 2, 77), peer)
                .is_err()
        );
    }
}
