//! What an error says to the person who looks at the packet: the part that is
//! wrong and the numbers that disagree.

use oxirush_gtp_u::{InformationElement, Packet, parse_ipv4_udp};

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|digit| (digit as char).to_digit(16).unwrap() as u8)
        .collect();
    digits
        .chunks(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .collect()
}

fn decode(wire: &str) -> String {
    Packet::decode(&hex(wire)).unwrap_err().to_string()
}

/// A vector written by hand has a Length field that counts the mandatory
/// header too, or forgets the optional fields: the error has both lengths.
#[test]
fn a_wrong_length_field_is_reported_with_the_length_of_the_datagram() {
    // A G-PDU of one octet: the Length field is 1, and here 9 and 0.
    assert_eq!(
        decode("30 ff 0009 12345678 45"),
        "truncated GTP-U message: the Length field says 9 octets after the header, \
         the datagram has 1"
    );
    assert_eq!(
        decode("30 ff 0000 12345678 45"),
        "invalid GTP-U message length: the Length field says 0 octets after the header, \
         the datagram has 1"
    );
    assert_eq!(
        decode("30 ff 0001"),
        "truncated GTP-U header: 8 octets needed, 4 left"
    );
}

#[test]
fn an_extension_header_is_reported_with_its_octets() {
    // A PDU Session Container whose length octet says 8 octets, in a
    // message that has 5 left.
    assert_eq!(
        decode("34 ff 0009 12345678 0000 00 85 02 10 09 00 45"),
        "truncated extension header: 8 octets needed, 5 left"
    );
    assert_eq!(
        decode("34 ff 0009 12345678 0000 00 85 00 10 09 00 45"),
        "invalid extension header length: 0 octets, expected 4"
    );
    // A UDP Port header of 8 octets.
    assert_eq!(
        decode("34 ff 000c 00000001 0000 00 40 02 0868 00000000 00"),
        "invalid UDP Port extension header length: 8 octets, expected 4"
    );
    // The E flag without the three optional fields.
    assert_eq!(
        decode("34 ff 0002 12345678 0000"),
        "truncated GTP-U optional header: 4 octets needed, 2 left"
    );
}

#[test]
fn a_value_that_does_not_encode_is_reported_with_its_limit() {
    let encode = |packet: Packet| packet.encode().unwrap_err().to_string();
    assert_eq!(
        encode(Packet::uplink(1, 64, vec![])),
        "QFI out of range: 64, at most 63"
    );
    assert_eq!(
        encode(Packet::g_pdu(1, vec![0; 70000])),
        "GTP-U Length out of range: 70000, at most 65535"
    );
}

#[test]
fn an_information_element_and_an_inner_packet_are_reported_with_their_octets() {
    let elements = |wire: &str| {
        InformationElement::decode_all(&hex(wire))
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        elements("10 0000"),
        "truncated TEID Data I: 4 octets needed, 2 left"
    );
    assert_eq!(
        elements("85 0003 010203"),
        "invalid GTP-U Peer Address length: 3 octets, expected 4"
    );
    assert_eq!(
        elements("85 0010 0102"),
        "truncated information element: 16 octets needed, 2 left"
    );
    // An IPv4 packet of 28 octets by its header, of which 21 are there.
    let inner = hex("4500001c 00004000 4011 0000 0a2d0002 c0000201 00");
    assert_eq!(
        parse_ipv4_udp(&inner).unwrap_err().to_string(),
        "truncated IPv4 packet: 28 octets needed, 21 left"
    );
}

/// The information elements of a G-PDU, whose payload is its packet: the
/// error says so, where it read the packet as elements.
#[test]
fn a_g_pdu_has_no_information_elements() {
    let mut packet = Packet::g_pdu(0x1001, vec![0x45, 0, 0, 20]);
    let error = packet.information_elements().unwrap_err();
    assert_eq!(
        error.to_string(),
        "a G-PDU has no information elements: its payload is the packet it carries"
    );
    let elements = [InformationElement::Recovery(0)];
    assert_eq!(packet.set_information_elements(&elements), Err(error));
    assert_eq!(packet.payload, [0x45, 0, 0, 20]);
}
