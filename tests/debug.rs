//! What `Debug` prints to the person who compares a value with a capture:
//! names for the numbers that have one, TEIDs in hexadecimal, and octets as
//! their number and all of them in hexadecimal.

use oxirush_gtp_u::{
    Cause, ExtensionHeader, ExtensionHeaderType, InformationElement, InformationElementType,
    MessageType, Packet, PduSessionContainer, UnknownNewIes, UplinkPduSessionInformation,
};

#[test]
fn a_message_prints_its_type_its_teid_and_its_payload() {
    let packet = Packet::uplink(0xdead_beef, 9, b"an IP packet".to_vec());
    let printed = format!("{packet:?}");
    assert!(
        printed.starts_with("Packet { message_type: G-PDU (255), teid: 0xdeadbeef, "),
        "{printed}"
    );
    assert!(
        printed.ends_with("payload: 12 octets 616e204950207061636b6574 }"),
        "{printed}"
    );
    // The payload is whole, whatever its length, and borrowed or not.
    let payload = vec![0xab; 1400];
    let printed = format!("{:?}", Packet::g_pdu(1, payload.as_slice()));
    assert!(
        printed.ends_with(&format!("payload: 1400 octets {} }}", "ab".repeat(1400))),
        "{printed}"
    );
    assert_eq!(
        format!("{:?}", Packet::end_marker(7)),
        "Packet { message_type: End Marker (254), teid: 0x00000007, sequence: None, \
         n_pdu_number: None, extension_headers: [], payload: 0 octets }"
    );
    assert_eq!(
        format!("{:?}", Packet::new(MessageType(77), 0, [1u8])),
        "Packet { message_type: MessageType(77), teid: 0x00000000, sequence: None, \
         n_pdu_number: None, extension_headers: [], payload: 1 octet 01 }"
    );
}

#[test]
fn what_is_kept_as_received_prints_its_octets() {
    let header = ExtensionHeader::Other {
        kind: ExtensionHeaderType(0x21),
        content: vec![7, 0],
    };
    assert_eq!(
        format!("{header:?}"),
        "Other { kind: ExtensionHeaderType(0x21), content: 2 octets 0700 }"
    );
    assert_eq!(
        format!("{:?}", PduSessionContainer::Other(vec![0x20, 0xff])),
        "Other(2 octets 20ff)"
    );
    let mut uplink = UplinkPduSessionInformation::new(9);
    uplink.unknown_new_ies = Some(Box::new(UnknownNewIes {
        flags: vec![0x20],
        content: vec![0xaa, 0xbb, 0xcc],
    }));
    let printed = format!("{uplink:?}");
    assert!(
        printed.ends_with(
            "unknown_new_ies: Some(UnknownNewIes { flags: 1 octet 20, content: 3 octets aabbcc }) }"
        ),
        "{printed}"
    );
}

#[test]
fn information_elements_print_their_names_and_a_teid_in_hexadecimal() {
    let elements = [
        InformationElement::Cause(Cause::INVALID_MESSAGE_FORMAT),
        InformationElement::Recovery(0),
        InformationElement::TeidDataI(0x1001),
        InformationElement::GtpUPeerAddress("127.0.0.10".parse().unwrap()),
        InformationElement::ExtensionHeaderTypeList(vec![
            ExtensionHeaderType::UDP_PORT,
            ExtensionHeaderType::PDU_SESSION_CONTAINER,
        ]),
        InformationElement::PrivateExtension {
            identifier: 0x1234,
            value: vec![5],
        },
        InformationElement::OtherTv {
            kind: InformationElementType(2),
            value: vec![0; 8],
        },
        InformationElement::Other {
            kind: InformationElementType::RECOVERY_TIME_STAMP,
            value: vec![1, 2, 3, 4],
        },
    ];
    assert_eq!(
        format!("{elements:?}"),
        "[Cause(Invalid message format (193)), Recovery(0), TeidDataI(0x00001001), \
         GtpUPeerAddress(127.0.0.10), \
         ExtensionHeaderTypeList([UDP Port (0x40), PDU Session Container (0x85)]), \
         PrivateExtension { identifier: 4660, value: 1 octet 05 }, \
         OtherTv { kind: InformationElementType(2), value: 8 octets 0000000000000000 }, \
         Other { kind: Recovery Time Stamp (231), value: 4 octets 01020304 }]"
    );
}

#[cfg(feature = "endpoint")]
#[test]
fn the_tunnels_of_an_endpoint_and_of_the_test_upf_print_their_teids_in_hexadecimal() {
    use oxirush_gtp_u::RemoteTunnel;
    use oxirush_gtp_u::upf_sim::Session;

    let address = "127.0.0.1:2152".parse().unwrap();
    assert_eq!(
        format!("{:?}", RemoteTunnel::new(address, 0x1001)),
        "RemoteTunnel { address: 127.0.0.1:2152, teid: 0x00001001 }"
    );
    assert_eq!(
        format!("{:?}", Session::new(0x1001, 0x2001, address, 9)),
        "Session { uplink_teid: 0x00001001, downlink_teid: 0x00002001, \
         gnb_address: 127.0.0.1:2152, qfi: 9 }"
    );
}
