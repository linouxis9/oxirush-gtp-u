//! Fast path tests. They need root and Linux 6.6, and each moves its thread
//! to new network and mount namespaces first, so they leave the host's
//! networking alone: `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo cargo
//! test --features ebpf --test ebpf_linux -- --ignored`.

#![cfg(target_os = "linux")]

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
use oxirush_gtp_u::{Endpoint, Packet, RemoteTunnel, ipv4_udp, parse_ipv4_udp};
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

async fn bind(address: &str, fast_path: &FastPath) -> Endpoint {
    let (endpoint, mut received) = Endpoint::bind(address.parse().unwrap()).await.unwrap();
    endpoint.set_fast_path(fast_path.clone()).unwrap();
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
    fast_path.open(port.index()).unwrap();
    // The VRF's table goes before the namespace's own addresses, N6 among
    // them, as Documentation/networking/vrf.rst has it.
    ip(&["rule", "add", "pref", "32765", "table", "local"]);
    ip(&["rule", "del", "pref", "0"]);
    port
}

/// Short-cut a tunnel once its N3 interface has its program: installing the
/// tunnel had it attached off the caller's task, and until it is there a
/// short-cut leaves the tunnel to userspace.
async fn shortcut(endpoint: &Endpoint, ran_id: u32, session_id: u8, tun: u32) {
    let attached = async {
        loop {
            match endpoint.shortcut(ran_id, session_id, tun) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                result => break result.unwrap(),
            }
        }
    };
    timeout(SECOND, attached)
        .await
        .expect("the N3 interface did not get its program");
}

/// Attaching a program takes milliseconds, which a caller serving packets
/// cannot spend on one: the N3 interface gets its program when a tunnel
/// through it is installed, before any short-cut is asked for.
#[tokio::test]
#[ignore = "needs root"]
async fn installing_a_tunnel_attaches_the_n3_program() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let gnb = bind("127.0.0.1:2152", &fast_path).await;
    assert_eq!(ingress_programs("lo"), 0);
    let remote = RemoteTunnel {
        address: UPF.parse().unwrap(),
        teid: 0x1001,
    };
    gnb.install(1, 1, remote, 9).unwrap();
    let attached = async {
        while ingress_programs("lo") == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    timeout(SECOND, attached)
        .await
        .expect("the N3 interface did not get its program");
    let port = ue_tun(&fast_path);
    shortcut(&gnb, 1, 1, port.index()).await;
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
    ));
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
    // next load. One that is not up yet belongs to a process still loading,
    // and an interface of another kind with such a name is not a stage:
    // both stay.
    let veth = |name: &str, up: bool| {
        let (near, far) = (format!("{name}a"), format!("{name}b"));
        ip(&["link", "add", &near, "type", "veth", "peer", "name", &far]);
        if up {
            ip(&["link", "set", &near, "up"]);
            ip(&["link", "set", &far, "up"]);
        }
    };
    veth("oxs0000dead", true);
    veth("oxs0000beef", false);
    ip(&["tuntap", "add", "name", "oxs0000cafeb", "mode", "tun"]);
    ip(&["link", "set", "oxs0000cafeb", "up"]);
    let before = stages();
    let fast_path = FastPath::load().unwrap();
    assert!(!exists("oxs0000deada") && exists("oxs0000beefa") && exists("oxs0000cafeb"));
    let stage: Vec<String> = stages()
        .into_iter()
        .filter(|name| !before.contains(name))
        .collect();
    assert_eq!(stage.len(), 2, "{stage:?}");
    // The CPUs of this process share what the stage's far end receives.
    assert_ne!(steering(&stage[1]), 0);
    assert_eq!(steering("oxs0000cafeb"), 0);
    let stage = stage[0].clone();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    gnb.set_fast_path(fast_path.clone()).unwrap();
    let remote = RemoteTunnel {
        address: UPF.parse().unwrap(),
        teid: 0x1001,
    };
    let downlink_teid = gnb.install(1, 1, remote, 9).unwrap();
    let (_upf, _observed) = upf(remote.teid, downlink_teid, &gnb).await;
    let port = Arc::new(ue_tun(&fast_path));
    assert_ne!(steering(port.name()), 0);

    // The N3 interface has its program by the time a UE sends.
    shortcut(&gnb, 1, 1, port.index()).await;
    fast_path.detach(port.index());

    // The userspace path, as an application runs it: what the TUN's reader gets
    // goes to N3, with the request to short-cut its tunnel, and what the
    // endpoint's socket gets goes to the TUN.
    let (up, down) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let uplink = tokio::spawn({
        let (gnb, port, up) = (gnb.clone(), port.clone(), up.clone());
        async move {
            let mut packet = vec![0; 65535];
            while let Ok(size) = port.recv(&mut packet).await {
                up.fetch_add(1, Ordering::Relaxed);
                gnb.send(1, 1, &packet[..size]).await.unwrap();
                gnb.shortcut(1, 1, port.index()).unwrap();
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
    let source = bind("127.0.0.1:2152", &fast_path).await;
    let target = bind("127.0.0.2:2152", &fast_path).await;
    let remote = RemoteTunnel {
        address: UPF.parse().unwrap(),
        teid: 0x2001,
    };
    let source_teid = source.install(1, 1, remote, 9).unwrap();
    let (upf, mut observed) = upf(remote.teid, source_teid, &source).await;
    let port = ue_tun(&fast_path);
    shortcut(&source, 1, 1, port.index()).await;
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
    // source's routes go later, which must leave the target's short-cut.
    let target_teid = target.install(7, 1, remote, 9).unwrap();
    fast_path.detach(port.index());
    shortcut(&target, 7, 1, port.index()).await;
    upf.switch_downlink(remote.teid, target.local_addr().unwrap(), target_teid)
        .await
        .unwrap();
    exchange("127.0.0.2:2152", 9).await;
    source.remove_ran(1);
    exchange("127.0.0.2:2152", 9).await;
    // Modification: the uplink gets another QFI.
    target.install(7, 1, remote, 5).unwrap();
    exchange("127.0.0.2:2152", 5).await;
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.downlink_packets), (4, 4));

    // Release: the TUN's packets reach its reader again.
    target.remove(7, 1);
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.bind_device(Some(b"oxr1")).unwrap();
    socket.send_to(b"released", (N6, 9)).await.unwrap();
    let mut packet = vec![0; 2048];
    let size = timeout(SECOND, port.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parse_ipv4_udp(&packet[..size]).unwrap().2, b"released");
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
    gnb.set_fast_path(fast_path.clone()).unwrap();
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
        let teid = match qfi {
            Some(qfi) => gnb.install(u32::from(i), 1, remote, qfi).unwrap(),
            None => gnb.install_s1u(u32::from(i), 1, remote),
        };
        let address = Ipv4Addr::new(198, 19, 1, i);
        let routing = Routing::UePolicy {
            address,
            table: 29100 + u32::from(i),
            priority: 15100 + u32::from(i),
        };
        let port = TunPort::create(TunConfig::new(format!("oxm{i}"), routing)).unwrap();
        // Without the TUN on the fast path its tunnel stays in userspace.
        let error = gnb.shortcut(u32::from(i), 1, port.index()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        fast_path.open(port.index()).unwrap();
        shortcut(&gnb, u32::from(i), 1, port.index()).await;
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
        let (source, destination, payload) = parse_ipv4_udp(&packet.payload).unwrap();
        assert_eq!(
            (source, destination),
            (SocketAddrV4::new(*address, 4000), server)
        );
        assert_eq!(payload, b"uplink");

        let reply = ipv4_udp(server, source, b"downlink").unwrap();
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
    assert_eq!(parse_ipv4_udp(&datagram[..size]).unwrap().2, [7; 1472]);
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_packets, stats.uplink_oversized), (6, 1));

    // A TUN taken off the fast path leaves nothing of its tunnel behind: its
    // packets are for its reader.
    for (port, address, ..) in &ports {
        assert_eq!(programs(port.name(), TcAttachType::Egress), 1);
        fast_path.close(port.index());
        assert_eq!(programs(port.name(), TcAttachType::Egress), 0);
        let application = UdpSocket::bind((*address, 4002)).await.unwrap();
        application.send_to(b"closed", server).await.unwrap();
        let size = timeout(SECOND, port.recv(&mut datagram))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parse_ipv4_udp(&datagram[..size]).unwrap().2, b"closed");
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
    gnb.set_fast_path(fast_path.clone()).unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x3001,
    };
    let teid = gnb.install(1, 1, remote, 9).unwrap();
    let other = gnb.install(2, 1, remote, 9).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.open(port.index()).unwrap();
    shortcut(&gnb, 1, 1, port.index()).await;
    // A tunnel the endpoint does not have.
    assert_eq!(
        gnb.shortcut(9, 1, port.index()).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );

    let inner = ipv4_udp(SocketAddrV4::new(N6, 9), SocketAddrV4::new(UE, 9), b"x").unwrap();
    let echo_reply = oxirush_gtp_u::ipv4_icmp_echo_reply(
        &oxirush_gtp_u::ipv4_icmp_echo_request(UE, N6, 1, 1, b"ping").unwrap(),
    )
    .unwrap();
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
            if parse_ipv4_udp(&packet.payload).is_ok_and(|(.., payload)| payload == [5; 4000]) {
                break;
            }
        }
    })
    .await;
    assert!(long.is_ok(), "the stage dropped a 4028-octet packet");
    let stats = fast_path.stats();
    assert_eq!((stats.uplink_oversized, stats.uplink_drops), (0, 0));
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
    gnb.set_fast_path(fast_path.clone()).unwrap();
    let peer = UdpSocket::bind("10.99.0.2:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x4001,
    };
    let teid = gnb.install(1, 1, remote, 9).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.open(port.index()).unwrap();
    shortcut(&gnb, 1, 1, port.index()).await;

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
    assert_eq!(parse_ipv4_udp(&packet.payload).unwrap().2, b"uplink");
    let reply = ipv4_udp(server, SocketAddrV4::new(UE, 4000), b"downlink").unwrap();
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
    gnb.set_fast_path(fast_path.clone()).unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x4001,
    };
    let teid = gnb.install(1, 1, remote, 9).unwrap();
    let routing = Routing::UePolicy {
        address: UE,
        table: 29100,
        priority: 15100,
    };
    let port = TunPort::create(TunConfig::new("oxu1", routing)).unwrap();
    fast_path.open(port.index()).unwrap();
    shortcut(&gnb, 1, 1, port.index()).await;
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
    assert_eq!(parse_ipv4_udp(&packet.payload).unwrap().2, b"uplink");
    // As through the TUN's writer, Linux checks the inner packet: one whose
    // payload changed on the way does not reach the application.
    let reply = ipv4_udp(server, SocketAddrV4::new(UE, 4000), b"downlink").unwrap();
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
        let gnb = bind(&format!("127.0.0.{i}:2152"), fast_path).await;
        let remote = RemoteTunnel {
            address: peer.local_addr().unwrap(),
            teid: 0x5000 + u32::from(i),
        };
        let teid = gnb.install(1, 1, remote, 9).unwrap();
        let address = Ipv4Addr::new(198, 19, 2, i);
        let routing = Routing::UePolicy {
            address,
            table: 29100 + u32::from(i),
            priority: 15100 + u32::from(i),
        };
        let port = TunPort::create(TunConfig::new(format!("oxm{i}"), routing)).unwrap();
        fast_path.open(port.index()).unwrap();
        shortcut(&gnb, 1, 1, port.index()).await;
        let application = UdpSocket::bind((address, 4000)).await.unwrap();
        applications.push((gnb, port, teid, address, application));
    }
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let mut datagram = vec![0; 2048];
    for (gnb, _, teid, address, application) in &applications {
        let reply = ipv4_udp(server, SocketAddrV4::new(*address, 4000), b"downlink").unwrap();
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
    fast_path.open(port.index()).unwrap();
    port
}

/// A tunnel has one short-cut. Given to a second TUN, as when a UE's TUN is
/// made anew before the old one closes, it leaves the first, whose closing
/// then takes nothing from the second; removed, it leaves the second too.
#[tokio::test]
#[ignore = "needs root"]
async fn a_tunnel_given_to_another_tun_leaves_the_first() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    gnb.set_fast_path(fast_path.clone()).unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x6001,
    };
    let teid = gnb.install(1, 1, remote, 9).unwrap();
    let old = policy_tun(&fast_path, "oxm1", Ipv4Addr::new(198, 19, 3, 1), 29101);
    let address = Ipv4Addr::new(198, 19, 3, 2);
    let new = policy_tun(&fast_path, "oxm2", address, 29102);
    shortcut(&gnb, 1, 1, old.index()).await;
    shortcut(&gnb, 1, 1, new.index()).await;
    fast_path.close(old.index());

    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let application = UdpSocket::bind((address, 4000)).await.unwrap();
    let reply = ipv4_udp(server, SocketAddrV4::new(address, 4000), b"downlink").unwrap();
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

    gnb.remove(1, 1);
    application.send_to(b"uplink", server).await.unwrap();
    timeout(SECOND, new.recv(&mut datagram))
        .await
        .expect("the removed tunnel still carried the new TUN's uplink")
        .unwrap();
    assert_eq!(fast_path.stats().uplink_packets, 0);
}

/// The programs send from and receive on the GTP-U port only.
#[tokio::test]
#[ignore = "needs root"]
async fn an_endpoint_on_another_port_gets_no_fast_path() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2153".parse().unwrap())
        .await
        .unwrap();
    let error = gnb.set_fast_path(fast_path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

/// A stopped endpoint answers nothing: its tunnels' packets must not go on
/// flowing in the kernel.
#[tokio::test]
#[ignore = "needs root"]
async fn shutting_an_endpoint_down_ends_its_short_cuts() {
    isolate();
    let fast_path = FastPath::load().unwrap();
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap())
        .await
        .unwrap();
    gnb.set_fast_path(fast_path.clone()).unwrap();
    let peer = UdpSocket::bind("127.0.0.9:2152").await.unwrap();
    let remote = RemoteTunnel {
        address: peer.local_addr().unwrap(),
        teid: 0x6003,
    };
    gnb.install(1, 1, remote, 9).unwrap();
    let address = Ipv4Addr::new(198, 19, 5, 1);
    let port = policy_tun(&fast_path, "oxm1", address, 29100);
    shortcut(&gnb, 1, 1, port.index()).await;
    gnb.shutdown().await.unwrap();

    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9);
    let application = UdpSocket::bind((address, 4000)).await.unwrap();
    application.send_to(b"uplink", server).await.unwrap();
    let mut datagram = vec![0; 2048];
    timeout(SECOND, port.recv(&mut datagram))
        .await
        .expect("the stopped endpoint's tunnel still carried the uplink")
        .unwrap();
    assert_eq!(fast_path.stats().uplink_packets, 0);
}
