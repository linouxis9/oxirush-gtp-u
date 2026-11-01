//! A send of the test UPF that finds the send buffer of its socket full
//! waits until the buffer has room, and fails for nothing else.
//!
//! Loopback never fills the send buffer of a UDP socket, however small it
//! is: it hands each datagram to the receiving socket at once, and takes it
//! off the account of the sender (`skb_orphan` in `loopback_xmit`). A
//! non-blocking send on it never answers EAGAIN. A tbf qdisc does not take a
//! datagram off that account until it lets it go: on the loopback of a
//! network namespace of the test's own, at a rate that lets almost nothing
//! go, the datagrams of the UPF stay in its queue, and the next send finds
//! the buffer full. Removing the qdisc drops its queue, and the buffer is
//! empty again.
//!
//! The tests need `CAP_NET_ADMIN`, as tun_linux.rs does, which says how to
//! run them, and the tbf qdisc, which many kernels have as the module
//! `sch_tbf`: adding the qdisc loads it on the host. The job `tun` of the CI
//! runs them, and so does the job `privileged` of the mutation runs; run them
//! elsewhere only where loading that module is no change to the host.

#![cfg(target_os = "linux")]

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{MessageType, Packet};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

const WAIT: Duration = Duration::from_secs(5);

/// Move this thread, and the processes it starts, to a new network
/// namespace whose loopback holds what is sent on it.
fn isolate() {
    // SAFETY: unshare only changes this thread's namespaces.
    let status = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    assert_eq!(
        status,
        0,
        "a new network namespace needs CAP_NET_ADMIN: {}",
        io::Error::last_os_error()
    );
    run("ip", &["link", "set", "lo", "up"]);
    // Two datagrams of a bucket, then a bit a second
    let tbf = "root tbf rate 8bit burst 4kb limit 16mb";
    let tbf: Vec<&str> = tbf.split(' ').collect();
    run("tc", &[&["qdisc", "add", "dev", "lo"], &tbf[..]].concat());
}

fn run(program: &str, args: &[&str]) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Remove the qdisc after a while: its queue is dropped, and the send buffer
/// has room.
async fn drain() {
    sleep(Duration::from_millis(300)).await;
    run("tc", &["qdisc", "del", "dev", "lo", "root"]);
}

/// The octets that the send buffer of the loopback UDP socket on `port`
/// holds, as /proc says it.
fn queued(port: u16) -> usize {
    let local = format!("{:08X}:{port:04X}", u32::from_ne_bytes([127, 0, 0, 1]));
    let table = fs::read_to_string("/proc/thread-self/net/udp").unwrap();
    let queues = table.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.get(1) == Some(&local.as_str())).then(|| fields[4].to_owned())
    });
    let queues = queues.expect("the socket is listed in its network namespace");
    let (sent, _) = queues.split_once(':').unwrap();
    usize::from_str_radix(sent, 16).unwrap()
}

/// Send downlinks of session `uplink_teid` until the send buffer of the UPF
/// is full, each of which the socket takes at once: the next send finds it
/// full, and is the first that does. A new socket's buffer has the size of
/// the default.
async fn fill(upf: &UpfSimulator, uplink_teid: u32) {
    let port = upf.local_addr().unwrap().port();
    let default = fs::read_to_string("/proc/sys/net/core/wmem_default").unwrap();
    let size: usize = default.trim().parse().unwrap();
    for _ in 0..100_000 {
        if queued(port) >= size {
            return;
        }
        let send = upf.send_downlink(uplink_teid, [0x5a; 1400]);
        let sent = timeout(WAIT, send).await;
        sent.expect("a send waits before the buffer is full")
            .unwrap();
    }
    panic!("the send buffer of the UPF does not fill");
}

async fn bound() -> (UpfSimulator, UdpSocket, SocketAddr) {
    let (upf, _) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gnb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = gnb.local_addr().unwrap();
    upf.set_session(Session::new(1, 2, address, 9)).unwrap();
    upf.set_session(Session::new(3, 4, address, 9)).unwrap();
    (upf, gnb, address)
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn a_downlink_waits_for_room_in_the_send_buffer() {
    isolate();
    let (upf, _gnb, _) = bound().await;
    fill(&upf, 1).await;
    let (sent, ()) = tokio::join!(timeout(WAIT, upf.send_downlink(3, [0x5a; 1400])), drain());
    sent.expect("the downlink is sent once the buffer has room")
        .unwrap();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn an_end_marker_waits_for_room_in_the_send_buffer() {
    isolate();
    let (upf, gnb, address) = bound().await;
    fill(&upf, 1).await;
    // The switch of session 3 ends its old downlink, of TEID 4, with an End
    // Marker
    let (switched, ()) = tokio::join!(timeout(WAIT, upf.switch_downlink(3, address, 5)), drain());
    switched
        .expect("the End Marker is sent once the buffer has room")
        .unwrap();
    let mut buffer = [0; 2048];
    loop {
        let (size, _) = timeout(WAIT, gnb.recv_from(&mut buffer))
            .await
            .expect("an End Marker")
            .unwrap();
        let packet = Packet::decode(&buffer[..size]).unwrap();
        if packet.message_type == MessageType::END_MARKER {
            assert_eq!(packet.teid, 4);
            break;
        }
    }
}
