//! Encode and decode G-PDUs with a PDU Session Container.
//!
//! ```sh
//! cargo run --example codec
//! ```

use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};

fn main() -> Result<(), oxirush_gtp_u::Error> {
    // An uplink G-PDU of QoS flow 9, as a gNB sends it on N3.
    let uplink = Packet::uplink(0x1234_5678, 9, b"an IP packet".to_vec());
    let bytes = uplink.encode()?;
    let decoded = Packet::decode(&bytes)?;
    assert_eq!(decoded, uplink);
    assert_eq!(decoded.qfi(), Some(9));

    // A downlink one whose container has more than a QFI.
    let mut information = DownlinkPduSessionInformation::new(9);
    information.rqi = true;
    let container = PduSessionContainer::Downlink(information);
    let downlink = Packet::g_pdu(0x9abc_def0, b"an IP packet".as_slice())
        .with_pdu_session_container(container.clone());
    let bytes = downlink.encode()?;

    // The payload of a borrowed message stays in the datagram.
    let decoded = Packet::decode_borrowed(&bytes)?;
    assert_eq!(decoded.pdu_session_container(), Some(&container));
    assert_eq!(decoded.payload, b"an IP packet");
    Ok(())
}
