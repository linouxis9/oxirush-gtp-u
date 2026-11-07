//! Fast path tests. They need root and Linux 6.6, and each moves its thread
//! to new network and mount namespaces first, so they leave the host's
//! networking alone: `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo cargo
//! test --features ebpf --test ebpf_linux -- --ignored`.

// Linux, on a little-endian architecture of aya: see build.rs.
#![cfg(fast_path)]

use std::ffi::{CStr, CString};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aya::programs::{SchedClassifier, TcAttachType};
use oxirush_gtp_u::ebpf::FastPath;
use oxirush_gtp_u::tun::{Routing, TunConfig, TunPort};
use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{Endpoint, Packet, RemoteTunnel, ip};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::process::Command;
use tokio::time::timeout;

const SECOND: Duration = Duration::from_secs(3);
/// An N6 address of the namespace: Linux answers for it.
const N6: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const UE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const UPF: &str = "127.0.0.8:2152";

/// Move this thread, and the processes it starts, to a new network
/// namespace with loopback up, and to a mount namespace whose `/sys` shows
/// it, as on a host: the fast path then steers its devices.
fn isolate() {
    // SAFETY: unshare only changes this thread's namespaces.
    let status = unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) };
    assert_eq!(
        status,
        0,
        "new network and mount namespaces need root: {}",
        io::Error::last_os_error()
    );
    // What is mounted from here on stays in this mount namespace.
    mount(None, c"/", None, libc::MS_REC | libc::MS_PRIVATE);
    mount(Some(c"sysfs"), c"/sys", Some(c"sysfs"), 0);
    ip(&["link", "set", "lo", "up"]);
}

fn mount(source: Option<&CStr>, target: &CStr, kind: Option<&CStr>, flags: libc::c_ulong) {
    let pointer = |name: Option<&CStr>| name.map_or(std::ptr::null(), CStr::as_ptr);
    // SAFETY: the C strings outlive the call.
    let status = unsafe {
        libc::mount(
            pointer(source),
            target.as_ptr(),
            pointer(kind),
            flags,
            std::ptr::null(),
        )
    };
    assert_eq!(
        status,
        0,
        "mount {target:?}: {}",
        io::Error::last_os_error()
    );
}

/// The interfaces named as stages are, sorted: a stage's near end first.
fn stages() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("oxs"))
        .collect();
    names.sort();
    names
}

/// The CPUs that share what `interface` receives (RPS), as a bitmap.
fn steering(interface: &str) -> u128 {
    let path = format!("/sys/class/net/{interface}/queues/rx-0/rps_cpus");
    let mask = std::fs::read_to_string(path).unwrap();
    u128::from_str_radix(&mask.trim().replace(',', ""), 16).unwrap()
}

fn ip(args: &[&str]) {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn exists(name: &str) -> bool {
    let name = CString::new(name).unwrap();
    // SAFETY: `name` is NUL-terminated and outlives the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

/// The TCX programs of `interface` in one direction.
fn programs(interface: &str, direction: TcAttachType) -> usize {
    SchedClassifier::query_tcx(interface, direction)
        .unwrap()
        .1
        .len()
}

fn ingress_programs(interface: &str) -> usize {
    programs(interface, TcAttachType::Ingress)
}

async fn ping(args: &[&str]) {
    let child = Command::new("ping")
        .args(["-n", "-c", "1", "-W", "3"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(
        output.status.success(),
        "ping {args:?}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn bind(address: &str) -> Endpoint {
    let (endpoint, mut received) = Endpoint::bind(address.parse().unwrap()).await.unwrap();
    // Nobody reads the receiver here: what the programs leave is dropped.
    tokio::spawn(async move { while received.recv().await.is_some() {} });
    endpoint
}

/// A UE TUN on the fast path, in its VRF: its address is local in the VRF
/// only, as the UPF's N6 is in the same namespace.
fn ue_tun(fast_path: &FastPath) -> TunPort {
    let routing = Routing::UeVrf {
        address: UE,
        table: 29100,
        vrf_name: "oxr1".into(),
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.add_tun(port.index()).unwrap();
    // The VRF's table goes before the namespace's own addresses, N6 among
    // them, as Documentation/networking/vrf.rst has it.
    ip(&["rule", "add", "pref", "32765", "table", "local"]);
    ip(&["rule", "del", "pref", "0"]);
    port
}

/// Short-cut the tunnel of RAN UE `ran_id` and session `session_id`
/// through `tun`, with the remote end and QFI that `install` gave it.
fn shortcut(
    fast_path: &FastPath,
    endpoint: &Endpoint,
    (ran_id, session_id): (u32, u8),
    remote: RemoteTunnel,
    qfi: Option<u8>,
    tun: u32,
) -> io::Result<()> {
    let SocketAddr::V4(local) = endpoint.local_addr().unwrap() else {
        panic!("an IPv4 endpoint");
    };
    let teid = endpoint.local_teid(ran_id, session_id).unwrap();
    fast_path.shortcut(tun, local, teid, remote, qfi)
}

/// Attaching a program blocks for milliseconds: the N3 interface gets its
/// program with the first short-cut through it, and only then.
#[tokio::test]
#[ignore = "needs root"]
async fn the_first_short_cut_through_an_n3_interface_attaches_its_program() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let gnb = bind("127.0.0.1:2152").await;
    let remote = RemoteTunnel {
        address: UPF.parse().unwrap(),
        teid: 0x1001,
    };
    gnb.install(1, 1, remote, Some(9)).unwrap();
    assert_eq!(ingress_programs("lo"), 0);
    let port = ue_tun(&fast_path);
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
    assert_eq!(ingress_programs("lo"), 1);
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
    assert_eq!(ingress_programs("lo"), 1);
}

/// The test UPF with a session whose N6 is a TUN of the namespace.
async fn upf(
    uplink_teid: u32,
    downlink_teid: u32,
    gnb: &Endpoint,
) -> (
    UpfSimulator,
    tokio::sync::mpsc::Receiver<oxirush_gtp_u::upf_sim::UplinkPacket>,
) {
    let (upf, observed) = UpfSimulator::bind(UPF.parse().unwrap()).await.unwrap();
    upf.set_session(Session::new(
        uplink_teid,
        downlink_teid,
        gnb.local_addr().unwrap(),
        9,
    ))
    .unwrap();
    let routing = Routing::Upf { ue_address: UE };
    upf.attach_tun(uplink_teid, TunConfig::new("oxn1", routing))
        .unwrap();
    (upf, observed)
}

#[tokio::test]
#[ignore = "needs root"]
async fn a_tunnel_is_carried_in_the_kernel_once_its_tun_sent_through_userspace() {
    isolate();
    ip(&["addr", "add", "198.18.0.1/32", "dev", "lo"]);
    // A stage whose process is gone has lost its program and goes with the
    // next load. One that is not up yet belongs to a process still loading;
    // a veth with such a name and without the stage's alias, and an
    // interface of another kind, are not stages: they stay.
    let veth = |name: &str, up: bool, alias: bool| {
        let (near, far) = (format!("{name}a"), format!("{name}b"));
        ip(&["link", "add", &near, "type", "veth", "peer", "name", &far]);
        if alias {
            ip(&[
                "link",
                "set",
                &far,
                "alias",
                "oxirush-gtp-u fast path stage",
            ]);
        }
        if up {
            ip(&["link", "set", &near, "up"]);
            ip(&["link", "set", &far, "up"]);
        }
    };
    veth("oxs0000dead", true, true);
    veth("oxs0000beef", false, true);
    veth("oxs0000f00d", true, false);
    ip(&["tuntap", "add", "name", "oxs0000cafeb", "mode", "tun"]);
    ip(&["link", "set", "oxs0000cafeb", "up"]);
    let before = stages();
    let fast_path = FastPath::load().unwrap();
    assert!(!exists("oxs0000deada"));
    assert!(exists("oxs0000beefa") && exists("oxs0000f00da") && exists("oxs0000cafeb"));
    let stage: Vec<String> = stages()
        .into_iter()
        .filter(|name| !before.contains(name))
        .collect();
    assert_eq!(stage.len(), 2, "{stage:?}");
    let alias = std::fs::read_to_string(format!("/sys/class/net/{}/ifalias", stage[1])).unwrap();
    assert_eq!(alias.trim_end(), "oxirush-gtp-u fast path stage");
    // The CPUs of this process share what the stage's far end receives.
    assert_ne!(steering(&stage[1]), 0);
    assert_eq!(steering("oxs0000cafeb"), 0);
    let stage = stage[0].clone();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let remote = RemoteTunnel {
        address: UPF.parse().unwrap(),
        teid: 0x1001,
    };
    let downlink_teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    let (_upf, _observed) = upf(remote.teid, downlink_teid, &gnb).await;
    let port = ue_tun(&fast_path);
    assert_ne!(steering(port.name()), 0);

    // The N3 interface gets its program with a first short-cut.
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
    fast_path.end_shortcut(port.index());

    // The userspace path, as an application runs it: what the TUN's reader gets
    // goes to N3, and short-cuts its tunnel, and what the endpoint's socket
    // gets goes to the TUN.
    let (up, down) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let uplink = tokio::spawn({
        let (gnb, port, up) = (gnb.clone(), port.clone(), up.clone());
        let fast_path = fast_path.clone();
        async move {
            let mut packet = vec![0; 65535];
            while let Ok(size) = port.recv(&mut packet).await {
                up.fetch_add(1, Ordering::Relaxed);
                gnb.send(1, 1, &packet[..size]).await.unwrap();
                shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
            }
        }
    });
    let downlink = tokio::spawn({
        let (port, down) = (port.clone(), down.clone());
        async move {
            while let Some(packet) = received.recv().await {
                down.fetch_add(1, Ordering::Relaxed);
                port.send(&packet.packet.payload).await.unwrap();
            }
        }
    });
    let userspace = || (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed));
    let kernel = || {
        let stats = fast_path.stats();
        assert_eq!((stats.uplink_drops, stats.uplink_oversized), (0, 0));
        (stats.uplink_packets, stats.downlink_packets)
    };

    // The first packet of the TUN goes through userspace, the next ones do
    // not. Echo Replies always come through the endpoint's socket.
    ping(&["-I", "oxr1", "198.18.0.1"]).await;
    assert_eq!((userspace(), kernel()), ((1, 1), (0, 0)));
    assert_eq!(ingress_programs("lo"), 1);
    ping(&["-I", "oxr1", "198.18.0.1"]).await;
    assert_eq!((userspace(), kernel()), ((1, 2), (1, 0)));
    // From N6: the Echo Request comes down and its reply goes up.
    ping(&["-I", "198.18.0.1", "198.18.0.2"]).await;
    assert_eq!((userspace(), kernel()), ((1, 2), (2, 1)));

    // TCP, whose large segments the stage splits: 1 MiB each way.
    let listener = TcpListener::bind((N6, 5001)).await.unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut data = vec![0; 1 << 20];
        stream.read_exact(&mut data).await.unwrap();
        stream.write_all(&data).await.unwrap();
    });
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind_device(Some(b"oxr1")).unwrap();
    let mut stream = timeout(SECOND, socket.connect((N6, 5001).into()))
        .await
        .unwrap()
        .unwrap();
    let sent: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
    let mut echoed = vec![0; sent.len()];
    timeout(4 * SECOND, async {
        stream.write_all(&sent).await.unwrap();
        stream.read_exact(&mut echoed).await.unwrap();
    })
    .await
    .unwrap();
    assert!(sent == echoed, "TCP data changed in the tunnel");
    server.await.unwrap();
    assert_eq!(userspace(), (1, 2));
    let (uplink_packets, downlink_packets) = kernel();
    assert!(uplink_packets > 700 && downlink_packets > 700);

    // Nothing is left: no program, no stage.
    uplink.abort();
    downlink.abort();
    assert!(uplink.await.unwrap_err().is_cancelled());
    assert!(downlink.await.unwrap_err().is_cancelled());
    drop(gnb);
    drop(fast_path);
    assert_eq!(ingress_programs("lo"), 0);
    assert!(!exists(&stage));
}

#[tokio::test]
#[ignore = "needs root"]
async fn the_short_cut_follows_handover_modification_and_release() {
    isolate();
    ip(&["addr", "add", "198.18.0.1/32", "dev", "lo"]);
    let fast_path = FastPath::load().unwrap();
    let source = bind("127.0.0.1:2152").await;
    let target = bind("127.0.0.2:2152").await;
    let remote = RemoteTunnel {
        address: UPF.parse().unwrap(),
        teid: 0x2001,
    };
    let source_teid = source.install(1, 1, remote, Some(9)).unwrap();
    let (upf, mut observed) = upf(remote.teid, source_teid, &source).await;
    let port = ue_tun(&fast_path);
    shortcut(&fast_path, &source, (1, 1), remote, Some(9), port.index()).unwrap();
    // The UPF sees the Echo Reply to its N6, from the serving node.
    let mut exchange = async |from: &str, qfi: u8| {
        ping(&["-I", "198.18.0.1", "198.18.0.2"]).await;
        let packet = timeout(SECOND, observed.recv()).await.unwrap().unwrap();
        assert_eq!(packet.from, from.parse::<SocketAddr>().unwrap());
        assert_eq!(
            (packet.uplink_teid, packet.packet.qfi()),
            (0x2001, Some(qfi))
        );
    };
    exchange("127.0.0.1:2152", 9).await;

    // Handover: the target's tunnel has another TEID and N3 address. The
    // source's routes go later, which leaves the target's short-cut.
    let target_teid = target.install(7, 1, remote, Some(9)).unwrap();
    fast_path.end_shortcut(port.index());
    shortcut(&fast_path, &target, (7, 1), remote, Some(9), port.index()).unwrap();
    upf.switch_downlink(remote.teid, target.local_addr().unwrap(), target_teid)
        .await
        .unwrap();
    exchange("127.0.0.2:2152", 9).await;
    source.remove_ran(1);
    exchange("127.0.0.2:2152", 9).await;
    // Modification: the uplink gets another QFI, and its short-cut too.
    target.install(7, 1, remote, Some(5)).unwrap();
    shortcut(&fast_path, &target, (7, 1), remote, Some(5), port.index()).unwrap();
    exchange("127.0.0.2:2152", 5).await;
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.downlink_packets), (4, 4));

    // Release: the TUN's packets reach its reader again.
    fast_path.end_shortcut(port.index());
    target.remove(7, 1);
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.bind_device(Some(b"oxr1")).unwrap();
    socket.send_to(b"released", (N6, 9)).await.unwrap();
    let mut packet = vec![0; 2048];
    let size = timeout(SECOND, port.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ip::parse_udp(&packet[..size]).unwrap().2, b"released");
    assert_eq!(fast_path.stats().uplink_packets, 4);
}

#[tokio::test]
#[ignore = "needs root"]
async fn tunnels_keep_their_teids_and_qfis_apart_and_match_the_encoder() {
    isolate();
    // A 1500-octet N3: one G-PDU below is too long for it.
    ip(&["link", "set", "lo", "mtu", "1500"]);
    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let mut ports = Vec::new();
    for i in 1..=6u8 {
        // Every third tunnel is an S1-U one, without PDU Session Container.
        let qfi = (i % 3 != 0).then_some(i);
        let remote = RemoteTunnel {
            address: peer.local_addr().unwrap(),
            teid: 0x7000 + u32::from(i),
        };
        let teid = gnb.install(u32::from(i), 1, remote, qfi).unwrap();
        let address = Ipv4Addr::new(198, 19, 1, i);
        let routing = Routing::UePolicy {
            address,
            table: 29100 + u32::from(i),
            priority: 15100 + u32::from(i),
        };
        let port = TunPort::create(TunConfig::new(format!("oxm{i}"), routing)).unwrap();
        // Without the TUN on the fast path its tunnel stays in userspace.
        let key = (u32::from(i), 1);
        let error = shortcut(&fast_path, &gnb, key, remote, qfi, port.index()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        fast_path.add_tun(port.index()).unwrap();
        shortcut(&fast_path, &gnb, key, remote, qfi, port.index()).unwrap();
        ports.push((port, address, remote.teid, teid, qfi));
    }
    let mut datagram = vec![0; 2048];
    for (_, address, uplink_teid, downlink_teid, qfi) in &ports {
        let application = UdpSocket::bind((*address, 4000)).await.unwrap();
        application.send_to(b"uplink", server).await.unwrap();
        let (size, from) = timeout(SECOND, peer.recv_from(&mut datagram))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, gnb.local_addr().unwrap());
        // The programs' G-PDU is the one the endpoint's encoder writes.
        let packet = Packet::decode(&datagram[..size]).unwrap();
        let expected = match qfi {
            Some(qfi) => Packet::uplink(*uplink_teid, *qfi, packet.payload.clone()),
            None => Packet::g_pdu(*uplink_teid, packet.payload.clone()),
        };
        assert_eq!(expected.encode().unwrap(), &datagram[..size]);
        let (source, destination, payload) = ip::parse_udp(&packet.payload).unwrap();
        assert_eq!(
            (source, destination),
            (SocketAddrV4::new(*address, 4000), server)
        );
        assert_eq!(payload, b"uplink");

        let reply = ip::udp(server, source, b"downlink").unwrap();
        let reply = match qfi {
            Some(qfi) => Packet::downlink(*downlink_teid, *qfi, reply),
            None => Packet::g_pdu(*downlink_teid, reply),
        };
        peer.send_to(&reply.encode().unwrap(), from).await.unwrap();
        let (size, from) = timeout(SECOND, application.recv_from(&mut datagram))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((&datagram[..size], from), (&b"downlink"[..], server.into()));
    }
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.downlink_packets), (6, 6));
    assert_eq!((stats.uplink_oversized, stats.uplink_drops), (0, 0));
    assert!(received.try_recv().is_err(), "a G-PDU reached userspace");

    // A packet that fills the TUN's MTU does not fit N3 with its GTP-U
    // header: it is the TUN's reader that gets it, for the endpoint's socket.
    let (port, address, ..) = &ports[0];
    let application = UdpSocket::bind((*address, 4001)).await.unwrap();
    application.send_to(&[7; 1472], server).await.unwrap();
    let size = timeout(SECOND, port.recv(&mut datagram))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ip::parse_udp(&datagram[..size]).unwrap().2, [7; 1472]);
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.uplink_oversized), (6, 1));

    // A TUN taken off the fast path leaves nothing of its tunnel behind: its
    // packets are for its reader.
    for (port, address, ..) in &ports {
        assert_eq!(programs(port.name(), TcAttachType::Egress), 1);
        fast_path.remove_tun(port.index());
        assert_eq!(programs(port.name(), TcAttachType::Egress), 0);
        let application = UdpSocket::bind((*address, 4002)).await.unwrap();
        application.send_to(b"closed", server).await.unwrap();
        let size = timeout(SECOND, port.recv(&mut datagram))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ip::parse_udp(&datagram[..size]).unwrap().2, b"closed");
    }
    assert_eq!(fast_path.stats().uplink_packets, 6);
}

#[tokio::test]
#[ignore = "needs root"]
async fn only_plain_ipv4_g_pdus_of_short_cut_tunnels_leave_userspace() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x3001,
    };
    let teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    let other = gnb.install(2, 1, remote, Some(9)).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.add_tun(port.index()).unwrap();
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();

    let inner = ip::udp(SocketAddrV4::new(N6, 9), SocketAddrV4::new(UE, 9), b"x").unwrap();
    // What `decap` reads of an ICMP Echo Reply: protocol 1, and type 0 where
    // the source port of a UDP datagram is.
    let udp = ip::udp(SocketAddrV4::new(N6, 0), SocketAddrV4::new(UE, 0), b"ping");
    let mut echo_reply = udp.unwrap();
    echo_reply[9] = 1;
    let echo_reply = checksummed(echo_reply);
    let mut sequenced = Packet::downlink(teid, 9, inner.clone());
    sequenced.sequence = Some(7);
    let mut ipv6 = vec![0x60; 40];
    ipv6[4..6].copy_from_slice(&0u16.to_be_bytes());
    for (what, packet) in [
        ("another tunnel", Packet::downlink(other, 9, inner.clone())),
        ("an Echo Reply", Packet::downlink(teid, 9, echo_reply)),
        ("IPv6", Packet::downlink(teid, 9, ipv6)),
        ("an End Marker", Packet::end_marker(other)),
    ] {
        peer.send_to(&packet.encode().unwrap(), gnb.local_addr().unwrap())
            .await
            .unwrap();
        let seen = timeout(SECOND, received.recv()).await;
        assert!(seen.is_ok(), "{what} did not reach userspace");
    }
    assert_eq!(fast_path.stats().downlink_packets, 0);
    // With a sequence number, as without: the kernel delivers it.
    for packet in [sequenced, Packet::g_pdu(teid, inner)] {
        peer.send_to(&packet.encode().unwrap(), gnb.local_addr().unwrap())
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(received.try_recv().is_err());
    assert_eq!(fast_path.stats().downlink_packets, 2);

    // A TUN with a longer MTU than a veth's default: its packets cross the
    // stage all the same.
    ip(&["link", "set", "oxu1", "mtu", "9000"]);
    let application = UdpSocket::bind((UE, 4003)).await.unwrap();
    application.send_to(&[5; 4000], (N6, 9)).await.unwrap();
    let mut datagram = vec![0; 8192];
    let long = timeout(SECOND, async {
        loop {
            let size = peer.recv(&mut datagram).await.unwrap();
            let packet = Packet::decode(&datagram[..size]).unwrap();
            if ip::parse_udp(&packet.payload).is_ok_and(|(.., payload)| payload == [5; 4000]) {
                break;
            }
        }
    })
    .await;
    assert!(long.is_ok(), "the stage dropped a 4028-octet packet");
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_oversized, stats.uplink_drops), (0, 0));
}

/// A UE's tunnel through a TUN on the fast path, to a peer on this host:
/// the endpoint, the peer's socket and the TUN.
async fn short_cut_tunnel(fast_path: &FastPath, teid: u32) -> (Endpoint, UdpSocket, TunPort, u32) {
    let (gnb, received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    // Nobody reads the receiver here: what the programs leave is dropped.
    tokio::spawn(async move {
        let mut received = received;
        while received.recv().await.is_some() {}
    });
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid,
    };
    let local_teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.add_tun(port.index()).unwrap();
    shortcut(fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
    (gnb, peer, port, local_teid)
}

/// The fast path follows the MTU of N3, which Linux announces: a packet
/// that no longer fits once N3's shrank is the TUN's reader's, whose socket
/// fragments the G-PDU.
#[tokio::test]
#[ignore = "needs root"]
async fn a_packet_that_no_longer_fits_n3_once_its_mtu_shrank_is_left_to_userspace() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (_gnb, peer, port, _) = short_cut_tunnel(&fast_path, 0x5001).await;
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let application = UdpSocket::bind((UE, 4000)).await.unwrap();
    let mut datagram = vec![0; 4096];

    // 1500 octets, the TUN's MTU, and the G-PDU's headers fit the 65536 of
    // the loopback interface.
    application.send_to(&[7; 1472], server).await.unwrap();
    let size = timeout(SECOND, peer.recv(&mut datagram))
        .await
        .expect("the G-PDU did not reach the peer")
        .unwrap();
    assert_eq!(size, 16 + 1500);
    assert_eq!(fast_path.stats().uplink_packets, 1);

    // The same packet once the loopback interface has 1500, and the
    // thread of the fast path has heard of it.
    ip(&["link", "set", "lo", "mtu", "1500"]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    application.send_to(&[8; 1472], server).await.unwrap();
    let size = timeout(SECOND, port.recv(&mut datagram))
        .await
        .expect("the TUN's reader did not get the packet")
        .unwrap();
    assert_eq!(ip::parse_udp(&datagram[..size]).unwrap().2, [8; 1472]);
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.uplink_oversized), (1, 1));
    fast_path.follows_mtus().unwrap();
}

/// Send `frame` out of the loopback interface, which receives it as from a
/// peer, with whatever its headers have.
fn inject(frame: &[u8]) {
    // SAFETY: a new descriptor, closed below.
    let socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    assert!(socket >= 0, "packet socket: {}", io::Error::last_os_error());
    // SAFETY: plain data, for which all zeros is valid.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    // SAFETY: a C string.
    address.sll_ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) } as i32;
    address.sll_halen = 6;
    // SAFETY: the frame and the address outlive the call.
    let sent = unsafe {
        libc::sendto(
            socket,
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&raw const address).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: the descriptor is this function's.
    unsafe { libc::close(socket) };
    assert_eq!(sent, frame.len() as isize, "send a frame: {error}");
}

/// The checksum of the IPv4 header at the start of `packet`, set.
fn checksummed(mut packet: Vec<u8>) -> Vec<u8> {
    packet[10..12].fill(0);
    let sum = packet[..20]
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = !((sum & 0xffff) + (sum >> 16)) as u16;
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// `decap` checks the outer IPv4 header as Linux does before it delivers a
/// datagram: one that Linux would drop is left to it, and not carried to
/// the TUN.
#[tokio::test]
#[ignore = "needs root"]
async fn a_g_pdu_whose_ipv4_header_linux_refuses_is_not_carried() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (_gnb, _peer, _port, teid) = short_cut_tunnel(&fast_path, 0x6001).await;
    let application = UdpSocket::bind((UE, 4000)).await.unwrap();
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let inner = ip::udp(server, SocketAddrV4::new(UE, 4000), b"downlink").unwrap();
    let gtp = Packet::downlink(teid, 9, inner).encode().unwrap();
    let (peer, local) = (
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 2152),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2152),
    );
    let outer = ip::udp(peer, local, &gtp).unwrap();
    let frame = |ip: &[u8]| [&[0; 12][..], &[0x08, 0x00], ip].concat();
    let mut datagram = [0; 64];

    // As a peer sends it.
    inject(&frame(&outer));
    let size = timeout(SECOND, application.recv(&mut datagram))
        .await
        .expect("the injected G-PDU did not reach the UE")
        .unwrap();
    assert_eq!(&datagram[..size], b"downlink");
    assert_eq!(fast_path.stats().downlink_packets, 1);

    // A header checksum that does not add up, and a total length longer
    // than the frame, whose checksum does.
    let mut corrupted = outer.clone();
    corrupted[10] ^= 0xff;
    let mut long = outer.clone();
    long[2..4].copy_from_slice(&(outer.len() as u16 + 4).to_be_bytes());
    for refused in [corrupted, checksummed(long)] {
        inject(&frame(&refused));
        let quiet = timeout(Duration::from_millis(300), application.recv(&mut datagram)).await;
        assert!(quiet.is_err(), "the UE got what Linux refuses");
    }
    assert_eq!(fast_path.stats().downlink_packets, 1);
}

#[tokio::test]
#[ignore = "needs root"]
async fn a_peer_on_this_host_is_reached_through_loopback_whatever_its_address() {
    isolate();
    // N3 addresses that are not loopback ones, on a device that carries
    // nothing: Linux routes between them through `lo`.
    ip(&["link", "add", "oxdummy", "type", "dummy"]);
    ip(&["addr", "add", "10.99.0.1/24", "dev", "oxdummy"]);
    ip(&["addr", "add", "10.99.0.2/24", "dev", "oxdummy"]);
    ip(&["link", "set", "oxdummy", "up"]);
    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("10.99.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("10.99.0.2:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x4001,
    };
    let teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.add_tun(port.index()).unwrap();
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();

    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let application = UdpSocket::bind((UE, 4000)).await.unwrap();
    application.send_to(b"uplink", server).await.unwrap();
    let mut datagram = vec![0; 2048];
    let (size, from) = timeout(SECOND, peer.recv_from(&mut datagram))
        .await
        .expect("the uplink did not reach a peer on this host")
        .unwrap();
    assert_eq!(from, gnb.local_addr().unwrap());
    let packet = Packet::decode(&datagram[..size]).unwrap();
    assert_eq!(ip::parse_udp(&packet.payload).unwrap().2, b"uplink");
    let reply = ip::udp(server, SocketAddrV4::new(UE, 4000), b"downlink").unwrap();
    let reply = Packet::downlink(teid, 9, reply).encode().unwrap();
    peer.send_to(&reply, from).await.unwrap();
    let size = timeout(SECOND, application.recv(&mut datagram))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&datagram[..size], b"downlink");
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.downlink_packets), (1, 1));
    assert!(received.try_recv().is_err(), "a G-PDU reached userspace");
}

#[tokio::test]
#[ignore = "needs root"]
async fn a_peer_on_another_host_is_reached_through_the_interface_of_its_route() {
    isolate();
    // The N3 address is on a device that carries nothing, and the peer in
    // another network namespace, behind a veth: N3 is that veth.
    ip(&["link", "add", "oxdummy", "type", "dummy"]);
    ip(&["addr", "add", "10.99.0.1/32", "dev", "oxdummy"]);
    ip(&["link", "set", "oxdummy", "up"]);
    // SAFETY: gettid has no preconditions.
    let here = unsafe { libc::gettid() }.to_string();
    let peer = std::thread::spawn(move || {
        // SAFETY: unshare only changes this thread's namespace.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let veth = ["type", "veth", "peer", "name", "oxn3a", "netns", &here];
        ip(&[&["link", "add", "oxn3b"], &veth[..]].concat());
        ip(&["addr", "add", "10.98.0.2/24", "dev", "oxn3b"]);
        ip(&["link", "set", "oxn3b", "up"]);
        ip(&["route", "add", "10.99.0.1/32", "via", "10.98.0.1"]);
        // The socket stays in the namespace it was made in.
        std::net::UdpSocket::bind("10.98.0.2:2152").unwrap()
    })
    .join()
    .unwrap();
    peer.set_nonblocking(true).unwrap();
    let peer = UdpSocket::from_std(peer).unwrap();
    ip(&["addr", "add", "10.98.0.1/24", "dev", "oxn3a"]);
    ip(&["link", "set", "oxn3a", "up"]);

    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("10.99.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x4001,
    };
    let teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.add_tun(port.index()).unwrap();
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
    let decap = ["oxn3a", "oxdummy", "lo"].map(ingress_programs);
    assert_eq!(decap, [1, 0, 0]);

    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let application = UdpSocket::bind((UE, 4000)).await.unwrap();
    application.send_to(b"uplink", server).await.unwrap();
    let mut datagram = vec![0; 2048];
    let (size, from) = timeout(SECOND, peer.recv_from(&mut datagram))
        .await
        .expect("the uplink did not leave through the route to the peer")
        .unwrap();
    assert_eq!(from, gnb.local_addr().unwrap());
    let packet = Packet::decode(&datagram[..size]).unwrap();
    assert_eq!(ip::parse_udp(&packet.payload).unwrap().2, b"uplink");
    // As through the TUN's writer, Linux checks the inner packet: one whose
    // payload changed on the way does not reach the application.
    let reply = ip::udp(server, SocketAddrV4::new(UE, 4000), b"downlink").unwrap();
    let mut damaged = reply.clone();
    *damaged.last_mut().unwrap() ^= 1;
    for inner in [damaged, reply] {
        let reply = Packet::downlink(teid, 9, inner).encode().unwrap();
        peer.send_to(&reply, from).await.unwrap();
    }
    let size = timeout(SECOND, application.recv(&mut datagram))
        .await
        .expect("the downlink did not come back through the route to the peer")
        .unwrap();
    assert_eq!(&datagram[..size], b"downlink");
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.downlink_packets), (1, 2));
    assert!(received.try_recv().is_err(), "a G-PDU reached userspace");
}

#[tokio::test]
#[ignore = "needs root"]
async fn two_fast_paths_share_an_n3_interface() {
    isolate();
    // As two processes on one host, or two containers on its network: each
    // has its stage, and what one's programs do not handle reaches the
    // other's.
    let fast_paths = [FastPath::load().unwrap(), FastPath::load().unwrap()];
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let mut applications = Vec::new();
    for (i, fast_path) in (1u8..).zip(&fast_paths) {
        let gnb = bind(&format!("127.0.0.{i}:2152")).await;
        let remote = RemoteTunnel {
            address: peer.local_addr().unwrap(),
            teid: 0x5000 + u32::from(i),
        };
        let teid = gnb.install(1, 1, remote, Some(9)).unwrap();
        let address = Ipv4Addr::new(198, 19, 2, i);
        let routing = Routing::UePolicy {
            address,
            table: 29100 + u32::from(i),
            priority: 15100 + u32::from(i),
        };
        let port = TunPort::create(TunConfig::new(format!("oxm{i}"), routing)).unwrap();
        fast_path.add_tun(port.index()).unwrap();
        shortcut(fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
        let application = UdpSocket::bind((address, 4000)).await.unwrap();
        applications.push((gnb, port, teid, address, application));
    }
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let mut datagram = vec![0; 2048];
    for (gnb, _, teid, address, application) in &applications {
        let reply = ip::udp(server, SocketAddrV4::new(*address, 4000), b"downlink").unwrap();
        let reply = Packet::downlink(*teid, 9, reply).encode().unwrap();
        peer.send_to(&reply, gnb.local_addr().unwrap())
            .await
            .unwrap();
        let size = timeout(SECOND, application.recv(&mut datagram))
            .await
            .expect("the first fast path kept the second one's G-PDU from its program")
            .unwrap();
        assert_eq!(&datagram[..size], b"downlink");
    }
    for fast_path in &fast_paths {
        assert_eq!(fast_path.stats().downlink_packets, 1);
    }
}

/// A policy-routed TUN of a UE at `address`, on the fast path.
fn policy_tun(fast_path: &FastPath, name: &str, address: Ipv4Addr, table: u32) -> TunPort {
    let routing = Routing::UePolicy {
        address,
        table,
        priority: 15100 + (table - 29100),
    };
    let port = TunPort::create(TunConfig::new(name, routing)).unwrap();
    fast_path.add_tun(port.index()).unwrap();
    port
}

/// A TUN has one tunnel's short-cut. Given a second tunnel's, it leaves the
/// first's: the downlink of the first is the endpoint's again.
#[tokio::test]
#[ignore = "needs root"]
async fn a_tun_given_another_tunnel_leaves_the_first() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let tunnel = |teid| RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid,
    };
    let first = gnb.install(1, 1, tunnel(0x6101), Some(9)).unwrap();
    gnb.install(2, 1, tunnel(0x6102), Some(9)).unwrap();
    let address = Ipv4Addr::new(198, 19, 4, 2);
    let port = policy_tun(&fast_path, "oxn1", address, 29103);
    shortcut(
        &fast_path,
        &gnb,
        (1, 1),
        tunnel(0x6101),
        Some(9),
        port.index(),
    )
    .unwrap();
    shortcut(
        &fast_path,
        &gnb,
        (2, 1),
        tunnel(0x6102),
        Some(9),
        port.index(),
    )
    .unwrap();

    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let downlink = ip::udp(server, SocketAddrV4::new(address, 4000), b"downlink").unwrap();
    let downlink = Packet::downlink(first, 9, downlink).encode().unwrap();
    peer.send_to(&downlink, gnb.local_addr().unwrap())
        .await
        .unwrap();
    let delivered = timeout(SECOND, received.recv())
        .await
        .expect("the first tunnel's downlink is the endpoint's")
        .unwrap();
    assert_eq!((delivered.ran_id, delivered.packet.teid), (1, first));
}

/// A tunnel given another local TEID, and short-cut again, leaves the
/// short-cut of the old one: a downlink to the old TEID reaches no TUN, and is
/// the endpoint's, which has no tunnel of it.
#[tokio::test]
#[ignore = "needs root"]
async fn a_tunnel_given_another_local_teid_leaves_the_short_cut_of_the_old_one() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x6201,
    };
    gnb.install_with_teid(1, 1, 0x7001, remote, Some(9))
        .unwrap();
    let address = Ipv4Addr::new(198, 19, 5, 2);
    let port = policy_tun(&fast_path, "oxt1", address, 29104);
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();
    gnb.install_with_teid(1, 1, 0x7002, remote, Some(9))
        .unwrap();
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap();

    let application = UdpSocket::bind((address, 4000)).await.unwrap();
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let downlink = ip::udp(server, SocketAddrV4::new(address, 4000), b"old TEID").unwrap();
    let downlink = Packet::downlink(0x7001, 9, downlink).encode().unwrap();
    peer.send_to(&downlink, gnb.local_addr().unwrap())
        .await
        .unwrap();
    let counted = async {
        while gnb.stats().unknown_teid_g_pdus == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    timeout(SECOND, counted)
        .await
        .expect("the endpoint has the old TEID's downlink");
    let mut datagram = vec![0; 2048];
    let reached = timeout(Duration::from_millis(100), application.recv(&mut datagram)).await;
    assert!(reached.is_err(), "the old TEID's downlink reached the TUN");
}

/// The programs send to the GTP-U port of a peer: a tunnel to another port
/// of it gets no short-cut.
#[tokio::test]
#[ignore = "needs root"]
async fn a_tunnel_to_another_port_gets_no_short_cut() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let gnb = bind("127.0.0.1:2152").await;
    let remote = RemoteTunnel {
        address: "127.0.0.8:2153".parse().unwrap(),
        teid: 0x1001,
    };
    gnb.install(1, 1, remote, Some(9)).unwrap();
    let port = ue_tun(&fast_path);
    let error = shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), port.index()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
}

/// Whether device `name` computes the checksums of what it sends, as
/// SIOCETHTOOL says.
fn tx_checksum(name: &str) -> u32 {
    const SIOCETHTOOL: libc::Ioctl = 0x8946;
    const ETHTOOL_GTXCSUM: u32 = 0x16;
    let mut value = [ETHTOOL_GTXCSUM, 0];
    // SAFETY: ifreq is plain data, for which all zeros is valid.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (target, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *target = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_data = value.as_mut_ptr().cast();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // SAFETY: the request and the value it points to outlive the call.
    let status = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&socket),
            SIOCETHTOOL,
            &mut request,
        )
    };
    assert_eq!(status, 0, "{}", io::Error::last_os_error());
    value[1]
}

/// The near end of the stage, `oxs…a`, which the UEs' packets are sent
/// through before their encapsulation, has its TX checksum offload off: the
/// packets leave it with their checksums.
#[tokio::test]
#[ignore = "needs root"]
async fn the_stage_completes_the_checksums_of_what_it_sends() {
    isolate();
    let _fast_path = FastPath::load().unwrap();
    let near: Vec<String> = stages()
        .into_iter()
        .filter(|name| name.ends_with('a'))
        .collect();
    assert_eq!(near.len(), 1, "{near:?}");
    assert_eq!(tx_checksum(&near[0]), 0, "{}", near[0]);
}

/// A tunnel has one short-cut. Given to a second TUN, as when a UE's TUN is
/// made anew before the old one closes, it leaves the first, whose closing
/// then takes nothing from the second; ended, it leaves the second too.
#[tokio::test]
#[ignore = "needs root"]
async fn a_tunnel_given_to_another_tun_leaves_the_first() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x6001,
    };
    let teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    let old = policy_tun(&fast_path, "oxm1", Ipv4Addr::new(198, 19, 3, 1), 29101);
    let address = Ipv4Addr::new(198, 19, 3, 2);
    let new = policy_tun(&fast_path, "oxm2", address, 29102);
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), old.index()).unwrap();
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), new.index()).unwrap();
    fast_path.remove_tun(old.index());

    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let application = UdpSocket::bind((address, 4000)).await.unwrap();
    let reply = ip::udp(server, SocketAddrV4::new(address, 4000), b"downlink").unwrap();
    let reply = Packet::downlink(teid, 9, reply).encode().unwrap();
    peer.send_to(&reply, gnb.local_addr().unwrap())
        .await
        .unwrap();
    let mut datagram = vec![0; 2048];
    let size = timeout(SECOND, application.recv(&mut datagram))
        .await
        .expect("the downlink left the new TUN's short-cut")
        .unwrap();
    assert_eq!(&datagram[..size], b"downlink");
    assert!(received.try_recv().is_err(), "a G-PDU reached userspace");

    fast_path.end_shortcut(new.index());
    gnb.remove(1, 1);
    application.send_to(b"uplink", server).await.unwrap();
    timeout(SECOND, new.recv(&mut datagram))
        .await
        .expect("the ended short-cut still carried the new TUN's uplink")
        .unwrap();
    assert_eq!(fast_path.stats().uplink_packets, 0);
}

/// The index of a TUN that the endpoint attached puts it on the fast path
/// and short-cuts its tunnel.
#[tokio::test]
#[ignore = "needs root"]
async fn a_tun_that_the_endpoint_attached_is_short_cut_by_its_index() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel::new(peer.local_addr().unwrap(), 0x7001);
    let teid = gnb.install(1, 1, remote, Some(9)).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let tun = gnb
        .attach_tun(1, 1, TunConfig::new("oxu1", routing))
        .unwrap();
    fast_path.add_tun(tun).unwrap();
    assert_eq!(programs("oxu1", TcAttachType::Egress), 1);
    shortcut(&fast_path, &gnb, (1, 1), remote, Some(9), tun).unwrap();

    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let application = UdpSocket::bind((UE, 4000)).await.unwrap();
    let mut datagram = vec![0; 2048];
    application.send_to(b"uplink", server).await.unwrap();
    let (size, from) = timeout(SECOND, peer.recv_from(&mut datagram))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, gnb.local_addr().unwrap());
    let packet = Packet::decode(&datagram[..size]).unwrap();
    assert_eq!((packet.teid, packet.qfi()), (0x7001, Some(9)));
    assert_eq!(ip::parse_udp(&packet.payload).unwrap().2, b"uplink");
    let reply = ip::udp(server, SocketAddrV4::new(UE, 4000), b"downlink").unwrap();
    let reply = Packet::downlink(teid, 9, reply).encode().unwrap();
    peer.send_to(&reply, gnb.local_addr().unwrap())
        .await
        .unwrap();
    let size = timeout(SECOND, application.recv(&mut datagram))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&datagram[..size], b"downlink");
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.downlink_packets), (1, 1));
    assert!(received.try_recv().is_err(), "a G-PDU reached the receiver");

    fast_path.remove_tun(tun);
    gnb.remove(1, 1);
    assert!(!exists("oxu1"));
    assert_eq!(format!("{fast_path:?}"), "FastPath { tuns: 0 }");
}

/// The programs send from and receive on the GTP-U port only.
#[tokio::test]
#[ignore = "needs root"]
async fn an_endpoint_on_another_port_gets_no_short_cut() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let local = "127.0.0.1:2153".parse().unwrap();
    let remote = RemoteTunnel::new(UPF.parse().unwrap(), 0x1001);
    let error = fast_path
        .shortcut(1, local, 0x2001, remote, Some(9))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}
