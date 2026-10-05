//! A gNB's endpoint and the test UPF exchange a packet in each direction.
//!
//! ```sh
//! cargo run --example endpoint
//! ```

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{Endpoint, RemoteTunnel, ipv4_udp, parse_ipv4_udp};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;

    // What the control plane negotiates: the UPF receives the session's
    // uplink on TEID 0x1001, the gNB its downlink on the TEID it assigns
    // to RAN UE 1, PDU session 5.
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9));

    // Uplink: an IP packet of the UE, which the UPF's echo service reflects.
    let ue = "10.45.0.2:4000".parse().unwrap();
    let server = "192.0.2.1:7".parse().unwrap();
    gnb.send(1, 5, ipv4_udp(ue, server, b"hello")?).await?;
    let uplink = observed.recv().await.expect("the UPF is running");
    println!("UPF: TEID {:#x} from {}", uplink.uplink_teid, uplink.from);

    // Downlink: the reply, with the tunnel it arrived on.
    let downlink = received.recv().await.expect("the endpoint is running");
    let (from, to, payload) = parse_ipv4_udp(&downlink.packet.payload)?;
    println!(
        "gNB: RAN UE {} session {}, QFI {:?}: {from} to {to}",
        downlink.ran_id,
        downlink.session_id,
        downlink.packet.qfi()
    );
    assert_eq!((from, to, payload), (server, ue, b"hello".as_slice()));
    Ok(())
}
