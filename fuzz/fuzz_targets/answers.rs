//! Whatever comes from whichever peer, a node answers what TS 29.281 has it answer, and
//! nothing else: an Echo Response to an Echo Request, with its sequence number, to the
//! address and port that it came from (§7.2.2), or a Supported Extension Headers
//! Notification to port 2152 of the peer (§4.4.2.5, §7.2.3) for an Echo Request or a
//! G-PDU with an extension header that it must understand and does not (§5.2.1). Every
//! answer decodes, and gets no answer: two nodes do not answer each other without end.
//! An Echo Request of a length that is not its own gets an Echo Response with the Cause
//! "Invalid message format" (§9.1). The ICMP Echo Reply of the test UPF answers an
//! Echo Request of valid checksums alone, from the address that the request went to,
//! with its identifier, its sequence number and its data, and valid checksums.
#![no_main]

use std::net::SocketAddr;

use libfuzzer_sys::fuzz_target;
use oxirush_gtp_u::fuzzing::{answer, echo_reply, length_error_response};
use oxirush_gtp_u::{Cause, InformationElement, MessageType, PORT, Packet};

/// The ones' complement sum of RFC 1071 over `octets`: 0xffff where a checksum in them
/// is right.
fn sum(octets: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in octets.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// What holds of the answer of a node to `packet` from `from`.
fn answered(packet: &Packet<&[u8]>, from: SocketAddr) {
    let (reply, handled) = answer(packet, from);
    let Some((reply, to)) = reply else {
        return;
    };
    assert!(handled, "a message that is answered goes on");
    let octets = reply.encode().expect("an answer encodes");
    let read = Packet::decode_borrowed(&octets).expect("an answer decodes");
    match reply.message_type {
        MessageType::ECHO_RESPONSE => {
            assert_eq!(
                packet.message_type,
                MessageType::ECHO_REQUEST,
                "an Echo Response to a {:?}",
                packet.message_type
            );
            assert_eq!(
                reply.sequence,
                Some(packet.sequence.unwrap_or(0)),
                "the sequence number of the request"
            );
            assert_eq!(
                to, from,
                "an Echo Response goes back where its request came from"
            );
        }
        MessageType::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION => {
            assert!(
                matches!(
                    packet.message_type,
                    MessageType::ECHO_REQUEST | MessageType::G_PDU
                ),
                "a Supported Extension Headers Notification to a {:?}",
                packet.message_type
            );
            assert_eq!(
                (to.ip(), to.port()),
                (from.ip(), PORT),
                "a notification goes to port 2152 of the peer"
            );
        }
        other => panic!("a node answers {other:?} to {:?}", packet.message_type),
    }
    // An answer gets none
    assert!(
        answer(&read, to).0.is_none(),
        "an answer to the answer {reply:?}"
    );
}

/// What holds of the ICMP Echo Reply to `request`.
fn echoed(request: &[u8]) {
    let Some(reply) = echo_reply(request) else {
        return;
    };
    let length = usize::from(request[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([request[2], request[3]]));
    assert!(
        request[0] >> 4 == 4 && length >= 20 && total >= length && total <= request.len(),
        "an IPv4 packet"
    );
    assert_eq!(
        sum(&request[..length]),
        0xffff,
        "the IPv4 checksum of the request"
    );
    assert_eq!(request[9], 1, "ICMP");
    let icmp = &request[length..total];
    assert!(icmp.len() >= 8 && icmp[..2] == [8, 0], "an Echo Request");
    assert_eq!(sum(icmp), 0xffff, "the ICMP checksum of the request");

    assert_eq!(reply[0], 0x45, "an IPv4 header of 20 octets");
    assert_eq!(
        usize::from(u16::from_be_bytes([reply[2], reply[3]])),
        reply.len(),
        "the total length of the reply"
    );
    assert_eq!(sum(&reply[..20]), 0xffff, "the IPv4 checksum of the reply");
    assert_eq!(reply[9], 1, "ICMP");
    assert_eq!(
        (&reply[12..16], &reply[16..20]),
        (&request[16..20], &request[12..16]),
        "the addresses, swapped"
    );
    assert_eq!(reply[20..22], [0, 0], "an Echo Reply");
    assert_eq!(
        reply[24..],
        icmp[4..],
        "the identifier, the sequence number and the data"
    );
    assert_eq!(sum(&reply[20..]), 0xffff, "the ICMP checksum of the reply");
    assert!(echo_reply(&reply).is_none(), "an Echo Reply is answered");
}

fuzz_target!(|bytes: &[u8]| {
    // The peer: its address and its port, then what it sends
    let [a, b, c, d, high, low, sent @ ..] = bytes else {
        return;
    };
    let from = SocketAddr::from(([*a, *b, *c, *d], u16::from_be_bytes([*high, *low])));
    match Packet::decode_borrowed(sent) {
        Ok(packet) => answered(&packet, from),
        Err(_) => {
            if let Some(response) = length_error_response(sent) {
                assert!(
                    sent.len() >= 8
                        && sent[0] & 0xf0 == 0x30
                        && sent[1] == MessageType::ECHO_REQUEST.0,
                    "an answer to octets that are no Echo Request"
                );
                assert_ne!(
                    usize::from(u16::from_be_bytes([sent[2], sent[3]])),
                    sent.len() - 8,
                    "an answer to an Echo Request of its own length"
                );
                assert_eq!(response.message_type, MessageType::ECHO_RESPONSE);
                let octets = response.encode().expect("an answer encodes");
                let read = Packet::decode(&octets).expect("an answer decodes");
                assert!(
                    read.information_elements().is_ok_and(|elements| elements
                        .contains(&InformationElement::Cause(Cause::INVALID_MESSAGE_FORMAT))),
                    "the Cause Invalid message format"
                );
            }
        }
    }
    echoed(sent);
});
