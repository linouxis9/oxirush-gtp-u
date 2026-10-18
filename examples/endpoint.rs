//! A gNB's endpoint and the test UPF: the tunnel of a PDU session, a G-PDU
//! of its QoS flow in each direction, and the supervision of the path.
//!
//! ```sh
//! cargo run --example endpoint
//! ```

use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{Endpoint, PathEvent, RemoteTunnel, ipv4_udp, parse_ipv4_udp};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse()?).await?;
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse()?).await?;

    // What the control plane negotiates: the UPF receives the session's
    // uplink on TEID 0x1001, the gNB its downlink on the TEID it assigns
    // to RAN UE 1, PDU session 5, whose QoS flow is 9
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

    // Uplink: an IP packet of the UE, which the UPF's echo service reflects
    let ue = "10.45.0.2:4000".parse()?;
    let server = "192.0.2.1:7".parse()?;
    gnb.send(1, 5, ipv4_udp(ue, server, b"hello")?).await?;
    let uplink = observed.recv().await.expect("the UPF is running");
    println!(
        "UPF: TEID {:#x}, QFI {:?}",
        uplink.uplink_teid,
        uplink.packet.qfi()
    );

    // Downlink: the reply, with the tunnel it arrived on
    let downlink = received.recv().await.expect("the endpoint is running");
    let (from, to, payload) = parse_ipv4_udp(&downlink.packet.payload)?;
    println!(
        "gNB: RAN UE {} session {}, QFI {:?}: {from} to {to}",
        downlink.ran_id,
        downlink.session_id,
        downlink.packet.qfi()
    );
    assert_eq!((from, to, payload), (server, ue, b"hello".as_slice()));

    // The gNB asks whether its path to the UPF is alive, then supervises it:
    // `path_state` and `path_events` say when it goes down, and up again
    let mut events = gnb.path_events();
    gnb.echo(upf.local_addr()?).await?;
    if let Ok(PathEvent::EchoResponse { packet, .. }) = events.recv().await {
        println!("Echo Response: {:?}", packet.information_elements()?);
    }
    gnb.supervise(upf.local_addr()?)?;
    let state = gnb.path_state(upf.local_addr()?).expect("supervised");
    println!("path up: {}, unanswered: {}", state.up, state.unanswered);
    Ok(())
}
