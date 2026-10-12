//! Decoding never panics, and what decodes encodes back to the same thing,
//! whatever its chain of extension headers.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_gtp_u::{InformationElement, Packet, parse_ipv4_icmp_echo, parse_ipv4_udp};

fuzz_target!(|bytes: &[u8]| {
    let borrowed = Packet::decode_borrowed(bytes).map(|packet| packet.into_owned());
    let owned = Packet::decode(bytes);
    // The payload left in the datagram or copied: the same message
    assert_eq!(borrowed, owned);
    if let Ok(packet) = owned {
        let encoded = packet.encode().expect("a decoded message encodes");
        assert!(encoded.len() <= bytes.len());
        assert_eq!(Packet::decode(&encoded).as_ref(), Ok(&packet));
        // A header takes four octets of the datagram at least
        let headers = Vec::from(packet.extension_headers.clone());
        assert!(headers.len() <= bytes.len() / 4);
        // The list of the extension headers is the same list, and encodes
        // to the same octets, given its headers one at a time or as a `Vec`
        let mut rebuilt = packet.clone();
        rebuilt.extension_headers = headers.iter().cloned().collect();
        assert_eq!(rebuilt, packet);
        assert_eq!(rebuilt.encode().as_ref(), Ok(&encoded));
        rebuilt.extension_headers = headers.into();
        assert_eq!(rebuilt, packet);
        assert_eq!(rebuilt.encode().as_ref(), Ok(&encoded));
        if let Ok(elements) = packet.information_elements() {
            let encoded =
                InformationElement::encode_all(&elements).expect("decoded elements encode");
            assert_eq!(encoded, packet.payload);
        }
    }
    let _ = parse_ipv4_udp(bytes);
    let _ = parse_ipv4_icmp_echo(bytes);
});
