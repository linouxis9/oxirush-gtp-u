//! Read and write the chain of extension headers of a message.
//!
//! ```sh
//! cargo run --example extension_headers
//! ```

use oxirush_gtp_u::{ExtensionHeader, ExtensionHeaderType, Packet};

fn main() -> Result<(), oxirush_gtp_u::Error> {
    // The container of an uplink G-PDU, then a header of a type that the
    // crate keeps as octets
    let mut packet = Packet::uplink(0x1234_5678, 9, b"an IP packet".to_vec());
    packet.extension_headers.push(ExtensionHeader::Other {
        kind: ExtensionHeaderType(0x21),
        content: vec![7, 0],
    });

    // A decoded message has them in their order
    let decoded = Packet::decode(&packet.encode()?)?;
    for header in &decoded.extension_headers {
        let required = header.comprehension_required();
        println!("{}, comprehension required: {required}", header.kind());
    }
    println!("{:?}", decoded.extension_headers[1]);

    // Sent on with another TEID and QoS flow
    let mut forwarded = decoded;
    forwarded.teid = 0x9abc_def0;
    forwarded.set_qfi(5);
    println!("{:02x?}", &forwarded.encode()?[4..16]);
    Ok(())
}
