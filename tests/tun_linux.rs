//! TUN tests. They need root, and each moves its thread to a new network
//! namespace first, so they leave the host's networking alone:
//! `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo cargo test --features
//! tun --test tun_linux -- --ignored`.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;

use oxirush_gtp_u::tun::{Routing, TunConfig, TunPort};
use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{
    EchoKind, Endpoint, RemoteTunnel, ipv4_icmp_echo_reply, ipv4_icmp_echo_request,
    parse_ipv4_icmp_echo,
};
use tokio::process::Command;

/// Move this thread, and the processes it starts, to a new network
/// namespace with loopback up.
fn isolate() {
    // SAFETY: unshare only changes this thread's namespaces.
    let status = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    assert_eq!(
        status,
        0,
        "a new network namespace needs root: {}",
        io::Error::last_os_error()
    );
    ip(&["link", "set", "lo", "up"]);
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

/// Whether this namespace has interface `name`. (/sys/class/net shows the
/// namespace that mounted it.)
fn exists(name: &str) -> bool {
    let name = CString::new(name).unwrap();
    // SAFETY: `name` is NUL-terminated and outlives the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

fn rules() -> String {
    let output = std::process::Command::new("ip")
        .args(["-4", "rule", "show"])
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

/// Reply to the ICMP Echo Request that `ping` sends through `port`, the
/// first packet to come through it (the TUN sends no IPv6).
async fn answer_ping(port: &TunPort, source: Ipv4Addr, destination: Ipv4Addr) {
    let mut buffer = vec![0u8; 65535];
    let size = tokio::time::timeout(Duration::from_secs(3), port.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let echo = parse_ipv4_icmp_echo(&buffer[..size]).unwrap();
    assert_eq!(echo.kind, EchoKind::Request);
    assert_eq!((echo.source, echo.destination), (source, destination));
    let reply = ipv4_icmp_echo_reply(&buffer[..size]).unwrap();
    port.send(&reply).await.unwrap();
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
        "ping: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "needs root"]
async fn ue_policy_routes_the_ue_s_traffic_through_the_tun() {
    isolate();
    let address = Ipv4Addr::new(198, 19, 0, 2);
    let routing = Routing::UePolicy {
        address,
        table: 29001,
        priority: 15001,
    };
    let port = TunPort::create(TunConfig::new("oxp0", routing)).unwrap();
    assert!(
        rules().contains("15001:\tfrom 198.19.0.2 lookup 29001"),
        "{}",
        rules()
    );
    let destination = Ipv4Addr::new(203, 0, 113, 1);
    tokio::join!(
        ping(&["-I", "198.19.0.2", "203.0.113.1"]),
        answer_ping(&port, address, destination)
    );
    port.close();
    assert!(!exists("oxp0"));
    assert!(!rules().contains("15001:"), "{}", rules());
    port.close(); // again: nothing to do
}

#[tokio::test]
#[ignore = "needs root and the vrf module"]
async fn ue_vrf_routes_the_vrf_s_traffic_through_the_tun() {
    isolate();
    let address = Ipv4Addr::new(198, 19, 0, 3);
    let routing = Routing::UeVrf {
        address,
        table: 29002,
        vrf_name: "oxr0".into(),
    };
    let port = TunPort::create(TunConfig::new("oxv0", routing)).unwrap();
    let destination = Ipv4Addr::new(203, 0, 113, 2);
    tokio::join!(
        ping(&["-I", "oxr0", "203.0.113.2"]),
        answer_ping(&port, address, destination)
    );
    drop(port);
    assert!(!exists("oxv0"));
    assert!(!exists("oxr0"));
}

#[tokio::test]
#[ignore = "needs root"]
async fn rejects_names_in_use_and_cleans_up_a_failed_setup() {
    isolate();
    let error = TunPort::create(TunConfig::new(
        "lo",
        Routing::Upf {
            ue_address: Ipv4Addr::new(198, 18, 0, 9),
        },
    ))
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    let policy = |address| Routing::UePolicy {
        address,
        table: 29003,
        priority: 15003,
    };
    let first =
        TunPort::create(TunConfig::new("oxa0", policy(Ipv4Addr::new(198, 19, 0, 4)))).unwrap();
    let error =
        TunPort::create(TunConfig::new("oxa0", policy(Ipv4Addr::new(198, 19, 0, 5)))).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    // The table already has a default route: the second TUN is removed.
    let error =
        TunPort::create(TunConfig::new("oxb0", policy(Ipv4Addr::new(198, 19, 0, 5)))).unwrap_err();
    assert!(error.to_string().contains("table 29003"), "{error}");
    assert!(!exists("oxb0"));
    assert!(exists("oxa0"));
    drop(first);
    assert!(!exists("oxa0"));
    for (name, routing) in [
        ("", policy(Ipv4Addr::LOCALHOST)),
        ("name-longer-than-15", policy(Ipv4Addr::LOCALHOST)),
        ("bad name", policy(Ipv4Addr::LOCALHOST)),
        (
            "oxc0",
            Routing::UePolicy {
                address: Ipv4Addr::LOCALHOST,
                table: 254,
                priority: 1,
            },
        ),
        (
            "oxc0",
            Routing::UePolicy {
                address: Ipv4Addr::LOCALHOST,
                table: 1,
                priority: 32766,
            },
        ),
    ] {
        let error = TunPort::create(TunConfig::new(name, routing)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name}: {error}");
    }
}

#[tokio::test]
#[ignore = "needs root"]
async fn upf_tun_routes_the_kernel_s_reply_back_to_n3() {
    isolate();
    // The N6 destination is local; Linux routes its reply via the TUN.
    ip(&["addr", "add", "198.18.0.1/32", "dev", "lo"]);
    let (upf, mut upf_rx) = UpfSimulator::bind("127.0.0.8:0".parse().unwrap())
        .await
        .unwrap();
    let (gnb, mut gnb_rx) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let remote = RemoteTunnel {
        address: upf.local_addr().unwrap(),
        teid: 0x1001,
    };
    let downlink_teid = gnb.install(1, 1, remote, 9);
    upf.set_session(Session::new(
        remote.teid,
        downlink_teid,
        gnb.local_addr().unwrap(),
        9,
    ));
    let ue_address = Ipv4Addr::new(198, 18, 0, 2);
    upf.attach_tun(
        remote.teid,
        TunConfig::new("oxn0", Routing::Upf { ue_address }),
    )
    .unwrap();
    let error = upf
        .attach_tun(
            remote.teid,
            TunConfig::new("oxn1", Routing::Upf { ue_address }),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert!(!exists("oxn1"));
    let request = ipv4_icmp_echo_request(
        ue_address,
        Ipv4Addr::new(198, 18, 0, 1),
        0x1234,
        1,
        b"upf-tun",
    )
    .unwrap();
    gnb.send(1, 1, request).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(3), upf_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.uplink_teid, remote.teid);
    let downlink = loop {
        let packet = tokio::time::timeout(Duration::from_secs(3), gnb_rx.recv())
            .await
            .unwrap()
            .unwrap();
        if parse_ipv4_icmp_echo(&packet.packet.payload)
            .is_ok_and(|echo| echo.kind == EchoKind::Reply)
        {
            break packet;
        }
    };
    let echo = parse_ipv4_icmp_echo(&downlink.packet.payload).unwrap();
    assert_eq!(echo.payload, b"upf-tun");
    upf.remove_session(remote.teid);
    assert!(!exists("oxn0"));
}

#[tokio::test]
#[ignore = "needs root"]
async fn upf_routes_32_tun_sessions_without_crossing_teids() {
    use std::collections::HashSet;

    isolate();
    ip(&["addr", "add", "198.18.64.254/32", "dev", "lo"]);
    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:0".parse().unwrap())
        .await
        .unwrap();
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    for i in 1..=32u8 {
        let uplink_teid = 0x5000 + u32::from(i);
        let remote = RemoteTunnel {
            address: upf.local_addr().unwrap(),
            teid: uplink_teid,
        };
        let downlink_teid = gnb.install(u32::from(i), 1, remote, 9);
        upf.set_session(Session::new(
            uplink_teid,
            downlink_teid,
            gnb.local_addr().unwrap(),
            9,
        ));
        let ue_address = Ipv4Addr::new(198, 18, 64, i);
        upf.attach_tun(
            uplink_teid,
            TunConfig::new(format!("oxn{i}"), Routing::Upf { ue_address }),
        )
        .unwrap();
    }
    for i in 1..=32u8 {
        let request = ipv4_icmp_echo_request(
            Ipv4Addr::new(198, 18, 64, i),
            Ipv4Addr::new(198, 18, 64, 254),
            0x5000 + u16::from(i),
            1,
            &[i],
        )
        .unwrap();
        gnb.send(u32::from(i), 1, request).await.unwrap();
    }
    let mut replied = HashSet::new();
    while replied.len() < 32 {
        let packet = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        let echo = parse_ipv4_icmp_echo(&packet.packet.payload).unwrap();
        let i = echo.destination.octets()[3];
        assert_eq!(packet.ran_id, u32::from(i));
        assert_eq!(echo.identifier, 0x5000 + u16::from(i));
        assert_eq!(echo.payload, &[i]);
        assert!(replied.insert(i), "duplicate reply for session {i}");
    }
    // Dropping the last handle closes every TUN.
    drop(upf);
    for i in 1..=32u8 {
        assert!(!exists(&format!("oxn{i}")));
    }
}

#[tokio::test]
#[ignore = "needs root"]
async fn linux_sends_nothing_unasked_through_a_tun() {
    isolate();
    let routing = Routing::UePolicy {
        address: Ipv4Addr::new(198, 19, 0, 6),
        table: 29004,
        priority: 15004,
    };
    let port = TunPort::create(TunConfig::new("oxq0", routing)).unwrap();
    // Linux would send IPv6 router solicitations within a few seconds.
    let mut buffer = vec![0u8; 65535];
    let read = tokio::time::timeout(Duration::from_secs(4), port.recv(&mut buffer)).await;
    assert!(
        read.is_err(),
        "unexpected packet: {read:?} {:02x?}",
        &buffer[..64]
    );
}

#[tokio::test]
#[ignore = "needs root"]
async fn close_wakes_a_reader() {
    isolate();
    let routing = Routing::Upf {
        ue_address: Ipv4Addr::new(198, 18, 0, 7),
    };
    let port = std::sync::Arc::new(TunPort::create(TunConfig::new("oxw0", routing)).unwrap());
    let reader = port.clone();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        reader.recv(&mut buffer).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    port.close();
    let read = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("the reader still waits after close")
        .unwrap();
    assert!(read.is_err());
    assert!(port.send(&[0x45; 20]).await.is_err());
    assert!(!exists("oxw0"));
}
