//! The `tun` example with the eBPF fast path: once userspace carried a packet
//! of the tunnel, the kernel carries the next ones. It needs Linux 6.6 and
//! root, and is best run in a network namespace of its own:
//!
//! ```sh
//! cargo build --example fast_path
//! sudo unshare --net sh -c 'ip link set lo up && target/debug/examples/fast_path'
//! ```

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use oxirush_gtp_u::ebpf::FastPath;
    use oxirush_gtp_u::tun::{Routing, TunConfig, TunPort};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, G_PDU, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse().unwrap()).await?;
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap()).await?;

    // Load the programs and give them to the endpoint before its tunnels:
    // installing a tunnel then prepares the interface it is routed through.
    let fast_path = FastPath::load()?;
    gnb.set_fast_path(fast_path.clone())?;

    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9);
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9));

    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    let tun = Arc::new(TunPort::create(TunConfig::new("ue0", routing))?);
    // Put the TUN on the fast path once, when it is created.
    fast_path.open(tun.index())?;

    // Userspace keeps carrying what the programs leave: at first, everything.
    let (reader, uplink) = (tun.clone(), gnb.clone());
    tokio::spawn(async move {
        let mut packet = vec![0; 65535];
        while let Ok(length) = reader.recv(&mut packet).await {
            let _ = uplink.send(1, 5, &packet[..length]).await;
            // Userspace carried a packet of the tunnel: have the kernel carry
            // the next ones. While the tunnel's interface is still getting
            // its program this is `WouldBlock`, and the next packet asks again.
            if let Err(error) = uplink.shortcut(1, 5, reader.index()) {
                eprintln!("still in userspace: {error}");
            }
        }
    });
    let writer = tun.clone();
    tokio::spawn(async move {
        while let Some(message) = received.recv().await {
            if message.packet.message_type == G_PDU {
                let _ = writer.send(&message.packet.payload).await;
            }
        }
    });

    let socket = tokio::net::UdpSocket::bind((ue, 0)).await?;
    for _ in 0..5 {
        socket.send_to(b"hello", "192.0.2.1:7").await?;
        socket.recv_from(&mut [0; 16]).await?;
    }
    // What the programs carried, after the datagrams userspace did.
    println!("{:?}", fast_path.stats());

    // Take the TUN off the fast path before closing it.
    fast_path.close(tun.index());
    tun.close();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this example needs Linux");
}
