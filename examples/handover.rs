//! What a handover puts in its G-PDUs: the PDCP sequence number of a packet
//! that the source node forwards, and the container of an End Marker.
//!
//! ```sh
//! cargo run --example handover
//! ```

use oxirush_gtp_u::{ExtensionHeader, Packet, PduSessionContainer};

fn main() -> Result<(), oxirush_gtp_u::Error> {
    // A downlink packet that the source gNB forwards to the target, with
    // the PDCP sequence number that it had given it
    let mut forwarded = Packet::downlink(0x2001, 9, b"an IP packet".to_vec());
    let number = ExtensionHeader::PdcpPduNumber(0x0abc);
    forwarded.extension_headers.push(number);
    println!("{:02x?}", &forwarded.encode()?[8..20]);

    // A sequence number of 18 bits has the long header
    let mut long = Packet::downlink(0x2001, 9, b"an IP packet".to_vec());
    long.extension_headers
        .push(ExtensionHeader::LongPdcpPduNumber {
            number: 0x2_abcd,
            legacy_type: false,
        });
    println!("{:02x?}", &long.encode()?[8..24]);

    // The End Marker of a forwarding tunnel between 5GS and EPS has the PDU
    // Session Container
    let container = PduSessionContainer::downlink(9);
    let marker = Packet::end_marker(0x2001).with_pdu_session_container(container);
    println!("{:02x?}", marker.encode()?);

    // The target reads the headers of what it receives
    let decoded = Packet::decode(&forwarded.encode()?)?;
    for header in &decoded.extension_headers {
        match header {
            ExtensionHeader::PdcpPduNumber(number) => println!("PDCP PDU Number {number:#x}"),
            other => println!("{}", other.kind()),
        }
    }
    Ok(())
}
