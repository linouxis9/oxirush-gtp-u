//! Encode and decode a G-PDU with its PDU Session Container.
//!
//! ```sh
//! cargo run --example codec
//! ```

use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // An uplink G-PDU of QoS flow 9, as a gNB sends it on N3: the header,
    // the PDU Session Container, then the IP packet
    let uplink = Packet::uplink(0x1234_5678, 9, b"an IP packet".as_slice());
    let bytes = uplink.encode()?;
    println!("{:02x?}", &bytes[..16]);

    // Decode it. The payload stays in the datagram
    let decoded = Packet::decode_borrowed(&bytes)?;
    println!("TEID {:#x}, QFI {:?}", decoded.teid, decoded.qfi());
    println!("{:?}", String::from_utf8_lossy(decoded.payload));

    // A downlink G-PDU whose container has more than a QFI
    let mut information = DownlinkPduSessionInformation::new(9);
    information.rqi = true;
    let downlink = Packet::g_pdu(0x9abc_def0, b"an IP packet".as_slice())
        .with_pdu_session_container(PduSessionContainer::Downlink(information));
    let decoded = Packet::decode(&downlink.encode()?)?;
    if let Some(PduSessionContainer::Downlink(information)) = decoded.pdu_session_container() {
        println!("QFI {}, RQI {}", information.qfi, information.rqi);
    }
    Ok(())
}
