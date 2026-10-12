//! What a GTP-U node owes its peer: the answer to an Echo Request, and an
//! Error Indication for a G-PDU of a tunnel that it does not have.
//!
//! ```sh
//! cargo run --example path
//! ```

use oxirush_gtp_u::upf_sim::UpfSimulator;
use oxirush_gtp_u::{Endpoint, Packet, RemoteTunnel};

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
        "message type {}, sequence number {:?}, {:?}",
        response.message_type,
        response.sequence,
        response.information_elements()?
    );

    // The UPF has no session with TEID 0x1001. It answers the G-PDU with an
    // Error Indication, which the receiver gets with its tunnel
    gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    gnb.send(1, 5, b"an IP packet".as_slice()).await?;
    let indication = received.recv().await.expect("the endpoint is running");
    println!(
        "message type {} for RAN UE {} session {}: {:?}",
        indication.packet.message_type,
        indication.ran_id,
        indication.session_id,
        indication.packet.information_elements()?
    );
    Ok(())
}
