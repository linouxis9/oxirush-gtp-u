//! The `tun` example with the eBPF fast path: the kernel carries the
//! tunnel's packets. It needs Linux 6.6 and root, and is best run in a
//! network namespace of its own:
//!
//! ```sh
//! cargo build --example fast_path
//! sudo unshare --net sh -c 'ip link set lo up && target/debug/examples/fast_path'
//! ```

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    use std::net::Ipv4Addr;

    use oxirush_gtp_u::ebpf::FastPath;
    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse().unwrap()).await?;
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap()).await?;

    // Load the programs and give them to the endpoint before its tunnels:
    // installing a tunnel then prepares the interface it is routed through.
    let fast_path = FastPath::load()?;
    gnb.set_fast_path(fast_path.clone())?;

    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9));

    // As in the `tun` example. The endpoint has a fast path: the TUN is on
    // it, and the kernel carries the tunnel's packets.
    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    gnb.attach_tun(1, 5, TunConfig::new("ue0", routing))?;

    let socket = tokio::net::UdpSocket::bind((ue, 0)).await?;
    for _ in 0..5 {
        socket.send_to(b"hello", "192.0.2.1:7").await?;
        socket.recv_from(&mut [0; 16]).await?;
    }
    // What the programs carried. Userspace carries the first packets when
    // the tunnel's interface is still getting its program.
    println!("{:?}", fast_path.stats());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this example needs Linux");
}
