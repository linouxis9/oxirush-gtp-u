//! The `tun` example with the eBPF fast path: the kernel carries the
//! tunnel's packets. It needs Linux 6.6 and root, and is best run in a
//! network namespace of its own:
//!
//! ```sh
//! cargo build --features ebpf --example fast_path
//! sudo unshare --net sh -c 'ip link set lo up && target/debug/examples/fast_path'
//! ```

// Linux, on a little-endian architecture of aya: see build.rs.
#[cfg(fast_path)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use oxirush_gtp_u::ebpf::FastPath;
    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let local: SocketAddrV4 = "127.0.0.1:2152".parse()?;
    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse()?).await?;
    let (gnb, _received) = Endpoint::bind(local.into()).await?;
    let fast_path = FastPath::load()?;

    let remote = RemoteTunnel::new(upf.local_addr()?, 0x1001);
    let teid = gnb.install(1, 5, remote, Some(9))?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

    // As in the `tun` example, then the TUN goes on the fast path and the
    // tunnel through it: the kernel carries the tunnel's packets.
    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    let tun = gnb.attach_tun(1, 5, TunConfig::new("ue0", routing))?;
    fast_path.add_tun(tun)?;
    fast_path.shortcut(tun, local, teid, remote, Some(9))?;

    let socket = tokio::net::UdpSocket::bind((ue, 0)).await?;
    for _ in 0..5 {
        socket.send_to(b"hello", "192.0.2.1:7").await?;
        socket.recv_from(&mut [0; 16]).await?;
    }
    // What the programs carried: the Echo Replies of the echo service are
    // left to userspace.
    println!("{:?}", fast_path.stats());
    Ok(())
}

#[cfg(not(fast_path))]
fn main() {
    eprintln!("this example needs Linux, on a little-endian architecture of aya");
}
