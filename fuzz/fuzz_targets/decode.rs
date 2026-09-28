//! Decoding never panics, and what decodes encodes back to the same thing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_gtp_u::{InformationElement, Packet, parse_ipv4_icmp_echo, parse_ipv4_udp};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(packet) = Packet::decode(bytes) {
        let encoded = packet.encode().expect("a decoded message encodes");
        assert!(encoded.len() <= bytes.len());
        assert_eq!(Packet::decode(&encoded).as_ref(), Ok(&packet));
        if let Ok(elements) = packet.information_elements() {
            let encoded =
                InformationElement::encode_all(&elements).expect("decoded elements encode");
            assert_eq!(encoded, packet.payload);
        }
    }
    let _ = parse_ipv4_udp(bytes);
    let _ = parse_ipv4_icmp_echo(bytes);
});
