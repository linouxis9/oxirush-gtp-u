//! What a GTP-U node owes its peer: the answer to an Echo Request, and an
//! Error Indication for a G-PDU of a tunnel that it does not have; and how
//! it supervises its path to a peer.
//!
//! ```sh
//! cargo run --example path
//! ```

use oxirush_gtp_u::upf_sim::UpfSimulator;
use oxirush_gtp_u::{Endpoint, Packet, PathEvent, RemoteTunnel};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    // An Error Indication goes to port 2152 of the sender of the G-PDU
    let (gnb, mut received) = Endpoint::bind("127.0.0.9:2152".parse().unwrap()).await?;
    let (upf, _observed) = UpfSimulator::bind("127.0.0.10:2152".parse().unwrap()).await?;

    // An endpoint answers an Echo Request by itself
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let request = Packet::echo_request(7).encode()?;
    peer.send_to(&request, gnb.local_addr()?).await?;
    let mut buffer = [0; 64];
    let (length, _) = peer.recv_from(&mut buffer).await?;
    let response = Packet::decode(&buffer[..length])?;
    println!(
        "{}, sequence number {:?}, {:?}",
        response.message_type,
        response.sequence,
        response.information_elements()?
    );

    // The gNB asks whether its path to the UPF is alive, and supervises it
    // from now on: `path_state` and `path_events` say when it is down
    let mut events = gnb.path_events();
    gnb.echo(upf.local_addr()?).await?;
    if let Ok(PathEvent::EchoResponse { from, packet, .. }) = events.recv().await {
        let elements = packet.information_elements()?;
        println!("Echo Response from {from}: {elements:?}");
    }
    gnb.supervise(upf.local_addr()?)?;

    // The UPF has no session with TEID 0x1001. It answers the G-PDU with an
    // Error Indication, which the receiver gets with its tunnel
    gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    gnb.send(1, 5, b"an IP packet".as_slice()).await?;
    let indication = received.recv().await.expect("the endpoint is running");
    println!(
        "{} for RAN UE {} session {}: {:?}",
        indication.packet.message_type,
        indication.ran_id,
        indication.session_id,
        indication.packet.information_elements()?
    );
    Ok(())
}
