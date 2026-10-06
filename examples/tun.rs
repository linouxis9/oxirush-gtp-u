//! A UE's TUN whose packets cross an N3 tunnel in userspace, to the test UPF
//! and back. It needs Linux and root, and is best run in a network namespace
//! of its own:
//!
//! ```sh
//! cargo build --example tun
//! sudo unshare --net sh -c 'ip link set lo up && target/debug/examples/tun'
//! ```

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    use std::net::Ipv4Addr;

    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse().unwrap()).await?;
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap()).await?;
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9));

    // The tunnel gets a TUN with the UE's address, and a rule that routes
    // what is sent from that address into it. The endpoint carries the
    // TUN's packets both ways, and closes the TUN with the tunnel.
    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    gnb.attach_tun(1, 5, TunConfig::new("ue0", routing))?;

    // A socket bound to the UE's address now goes through the tunnel. The
    // test UPF's echo service answers for any destination.
    let socket = tokio::net::UdpSocket::bind((ue, 0)).await?;
    socket.send_to(b"hello", "192.0.2.1:7").await?;
    let mut reply = [0; 16];
    let (length, from) = socket.recv_from(&mut reply).await?;
    let reply = String::from_utf8_lossy(&reply[..length]);
    println!("{from} answered {reply:?}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this example needs Linux");
}
