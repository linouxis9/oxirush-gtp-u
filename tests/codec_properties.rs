use std::net::IpAddr;

use oxirush_gtp_u::{
    DownlinkPduSessionInformation, ExtensionHeader, InformationElement, Packet,
    PduSessionContainer, UplinkPduSessionInformation, UplinkTimeStamps, parse_ipv4_icmp_echo,
    parse_ipv4_udp,
};
use proptest::collection::vec;
use proptest::option::of;
use proptest::prelude::*;

fn downlink() -> impl Strategy<Value = PduSessionContainer> {
    (
        0u8..64,
        any::<bool>(),
        of(0u8..8),
        of(any::<u64>()),
        of(0u32..1 << 24),
        of(any::<u32>()),
        (of(0u32..1 << 24), of(any::<u16>())),
    )
        .prop_map(
            |(qfi, rqi, ppi, time_stamp, sequence, mbs_sequence, burst)| {
                let mut information = DownlinkPduSessionInformation::new(qfi);
                information.rqi = rqi;
                information.ppi = ppi;
                information.dl_sending_time_stamp = time_stamp;
                information.dl_qfi_sequence_number = sequence;
                information.dl_mbs_qfi_sequence_number = mbs_sequence;
                if ppi.is_some() {
                    (information.burst_size, information.time_to_next_burst) = burst;
                }
                PduSessionContainer::Downlink(information)
            },
        )
}

/// With `valid`, values the encoder accepts: raw content padded. Without,
/// also unpadded, to check what the encoder lets through.
fn uplink(valid: bool) -> impl Strategy<Value = PduSessionContainer> {
    (
        0u8..64,
        of(any::<[u64; 3]>()),
        of(any::<u32>()),
        of(any::<u32>()),
        of(0u32..1 << 24),
        of(any::<u32>()),
        (of(any::<bool>()), of(any::<u16>()), of(any::<u16>())),
        of((0u8..16, vec(any::<u8>(), 0..8))),
    )
        .prop_map(
            move |(qfi, time_stamps, dl, ul, sequence, n3_n9, known, unknown)| {
                let mut information = UplinkPduSessionInformation::new(qfi);
                information.time_stamps =
                    time_stamps.map(|[dl_sending_repeated, dl_received, ul_sending]| {
                        UplinkTimeStamps {
                            dl_sending_repeated,
                            dl_received,
                            ul_sending,
                        }
                    });
                information.dl_delay_result = dl;
                information.ul_delay_result = ul;
                information.ul_qfi_sequence_number = sequence;
                information.n3_n9_delay_result = n3_n9;
                let (d1, ul_congestion, dl_congestion) = known;
                information.d1_ul_pdcp_delay_result_ind = d1;
                information.ul_congestion_information = ul_congestion;
                information.dl_congestion_information = dl_congestion;
                // Unknown flags 3 to 6, or an extension octet; decoding keeps the
                // padding in the content, so include it.
                information.unknown_new_ies = unknown.map(|(flags, mut content)| {
                    let flags = match flags {
                        0 => vec![0x80, 0x01],     // an extension octet
                        flags => vec![flags << 3], // New IE Flags 3 to 6
                    };
                    let mut length = 2
                        + time_stamps.map_or(0, |_| 24)
                        + dl.map_or(0, |_| 4)
                        + ul.map_or(0, |_| 4)
                        + sequence.map_or(0, |_| 3)
                        + n3_n9.map_or(0, |_| 4)
                        + flags.len()
                        + d1.map_or(0, |_| 1)
                        + ul_congestion.map_or(0, |_| 2)
                        + dl_congestion.map_or(0, |_| 2)
                        + content.len();
                    while valid && (length + 2) % 4 != 0 {
                        content.push(0);
                        length += 1;
                    }
                    oxirush_gtp_u::UnknownNewIes { flags, content }
                });
                PduSessionContainer::Uplink(information)
            },
        )
}

/// With `valid`, content whose length plus 2 is a multiple of 4, as on the
/// wire; without, any length.
fn content(valid: bool) -> impl Strategy<Value = Vec<u8>> {
    (0usize..6, 0usize..4).prop_flat_map(move |(units, extra)| {
        let extra = if valid { 0 } else { extra };
        vec(any::<u8>(), units * 4 + 2 + extra)
    })
}

fn extension_header(valid: bool) -> impl Strategy<Value = ExtensionHeader> {
    prop_oneof![
        any::<u16>().prop_map(ExtensionHeader::UdpPort),
        downlink().prop_map(ExtensionHeader::PduSessionContainer),
        uplink(valid).prop_map(ExtensionHeader::PduSessionContainer),
        (2u8..16, content(valid)).prop_map(|(pdu_type, mut content)| {
            content[0] = pdu_type << 4 | (content[0] & 0x0f);
            ExtensionHeader::PduSessionContainer(PduSessionContainer::Other(content))
        }),
        (
            (1u8..=255).prop_filter("typed", |kind| ![0x40, 0x85].contains(kind)),
            content(valid)
        )
            .prop_map(|(kind, content)| ExtensionHeader::Other { kind, content }),
    ]
}

fn packet(valid: bool) -> impl Strategy<Value = Packet> {
    (
        any::<u8>(),
        any::<u32>(),
        of(any::<u16>()),
        of(any::<u8>()),
        vec(extension_header(valid), 0..4),
        vec(any::<u8>(), 0..64),
    )
        .prop_map(
            |(message_type, teid, sequence, n_pdu_number, extension_headers, payload)| {
                let mut packet = Packet::new(message_type, teid, payload);
                packet.sequence = sequence;
                packet.n_pdu_number = n_pdu_number;
                packet.extension_headers = extension_headers;
                packet
            },
        )
}

fn information_element() -> impl Strategy<Value = InformationElement> {
    prop_oneof![
        any::<u8>().prop_map(InformationElement::Recovery),
        any::<u32>().prop_map(InformationElement::TeidDataI),
        proptest::sample::select(vec![
            (1, 1),
            (2, 8),
            (3, 6),
            (4, 4),
            (5, 4),
            (8, 1),
            (9, 28),
            (11, 1),
            (12, 3),
            (13, 1),
            (15, 1),
            (17, 4),
            (18, 5),
            (19, 1),
            (20, 1),
            (21, 1),
            (22, 9),
            (23, 1),
            (24, 1),
            (25, 2),
            (26, 2),
            (27, 2),
            (28, 2),
            (29, 1),
            (127, 4),
        ])
        .prop_flat_map(|(kind, length)| {
            vec(any::<u8>(), length)
                .prop_map(move |value| InformationElement::OtherTv { kind, value })
        }),
        any::<IpAddr>().prop_map(InformationElement::GtpUPeerAddress),
        vec(any::<u8>(), 0..8).prop_map(InformationElement::ExtensionHeaderTypeList),
        (any::<u16>(), vec(any::<u8>(), 0..8)).prop_map(|(identifier, value)| {
            InformationElement::PrivateExtension { identifier, value }
        }),
        (
            (128u8..255).prop_filter("typed", |kind| ![133, 141].contains(kind)),
            vec(any::<u8>(), 0..8)
        )
            .prop_map(|(kind, value)| InformationElement::Other { kind, value }),
    ]
}

/// A GTP-U header with a consistent length and any flags, and a random rest.
fn plausible_message() -> impl Strategy<Value = Vec<u8>> {
    (0u8..16, any::<u8>(), vec(any::<u8>(), 0..96)).prop_map(|(flags, message_type, rest)| {
        let mut bytes = vec![0x30 | flags, message_type];
        bytes.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 1]);
        bytes.extend_from_slice(&rest);
        bytes
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn decode_inverts_encode(packet in packet(true)) {
        let bytes = packet.encode().unwrap();
        prop_assert_eq!(Packet::decode(&bytes).unwrap(), packet);
    }

    #[test]
    fn whatever_encodes_decodes_to_the_same_value(packet in packet(false)) {
        if let Ok(bytes) = packet.encode() {
            prop_assert_eq!(Packet::decode(&bytes).unwrap(), packet);
        }
    }

    #[test]
    fn decoded_messages_encode_to_what_decodes_the_same(bytes in prop_oneof![
        plausible_message(),
        vec(any::<u8>(), 0..64),
    ]) {
        if let Ok(packet) = Packet::decode(&bytes) {
            let encoded = packet.encode().unwrap();
            prop_assert!(encoded.len() <= bytes.len());
            prop_assert_eq!(Packet::decode(&encoded).unwrap(), packet);
        }
    }

    #[test]
    fn information_elements_round_trip(elements in vec(information_element(), 0..6)) {
        let bytes = InformationElement::encode_all(&elements).unwrap();
        prop_assert_eq!(InformationElement::decode_all(&bytes).unwrap(), elements);
    }

    #[test]
    fn decoders_accept_any_input(bytes in vec(any::<u8>(), 0..96)) {
        if let Ok(elements) = InformationElement::decode_all(&bytes) {
            let encoded = InformationElement::encode_all(&elements).unwrap();
            prop_assert_eq!(encoded, bytes.clone());
        }
        let _ = parse_ipv4_udp(&bytes);
        let _ = parse_ipv4_icmp_echo(&bytes);
    }
}
