//! Encode and decode G-PDUs with a PDU Session Container, and with a chain
//! of extension headers.
//!
//! ```sh
//! cargo run --example codec
//! ```

use oxirush_gtp_u::{DownlinkPduSessionInformation, ExtensionHeader, Packet, PduSessionContainer};

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

    // The extension headers of a message are a list, in their order: here
    // the container, and one of a type that the crate keeps as octets.
    let service_class = ExtensionHeader::Other {
        kind: ExtensionHeader::SERVICE_CLASS_INDICATOR,
        content: vec![7, 0],
    };
    let mut longer = uplink.clone();
    longer.extension_headers.push(service_class.clone());
    let decoded = Packet::decode(&longer.encode()?)?;
    assert_eq!(decoded.extension_headers.len(), 2);
    assert_eq!(decoded.extension_headers[1], service_class);
    assert_eq!(decoded.qfi(), Some(9));
    Ok(())
}
