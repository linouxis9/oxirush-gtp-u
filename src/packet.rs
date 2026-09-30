//! The GTP-U header and messages (TS 29.281 §5.1, §6, §7).

use std::net::IpAddr;

use crate::{Error, ExtensionHeader, InformationElement, PduSessionContainer};

/// Echo Request (TS 29.281 §7.2.1).
pub const ECHO_REQUEST: u8 = 1;
/// Echo Response (TS 29.281 §7.2.2).
pub const ECHO_RESPONSE: u8 = 2;
/// Error Indication (TS 29.281 §7.3.1).
pub const ERROR_INDICATION: u8 = 26;
/// Supported Extension Headers Notification (TS 29.281 §7.2.3).
pub const SUPPORTED_EXTENSION_HEADERS_NOTIFICATION: u8 = 31;
/// Tunnel Status (TS 29.281 §7.3.3).
pub const TUNNEL_STATUS: u8 = 253;
/// End Marker (TS 29.281 §7.3.2).
pub const END_MARKER: u8 = 254;
/// G-PDU: a T-PDU, the user's IP packet, in a tunnel.
pub const G_PDU: u8 = 255;

/// Version 1, protocol type GTP.
const VERSION_1_GTP: u8 = 0x30;
const E: u8 = 0x04;
const S: u8 = 0x02;
const PN: u8 = 0x01;
const MANDATORY_LEN: usize = 8;
const OPTIONAL_LEN: usize = 4;

/// A GTP-U message: the header, its extension headers and the payload.
///
/// Decoding what [`encode`](Packet::encode) produced gives back the same
/// value, and so does encoding and decoding again what
/// [`decode`](Packet::decode) produced. The bytes of a re-encoded message can
/// differ from those received where the specs leave room: spare bits,
/// fields whose flag is clear (not interpreted, TS 29.281 §5.1), padding,
/// and fields of the PDU Session Information that later releases add.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Packet {
    /// Message type, such as [`G_PDU`] or [`ECHO_REQUEST`].
    pub message_type: u8,
    /// Tunnel Endpoint Identifier, assigned by the receiver of the tunnel;
    /// 0 in path management messages and Error Indication.
    pub teid: u32,
    /// Sequence Number (S flag).
    pub sequence: Option<u16>,
    /// N-PDU Number (PN flag).
    pub n_pdu_number: Option<u8>,
    /// Extension headers, in order (E flag).
    pub extension_headers: Vec<ExtensionHeader>,
    /// The T-PDU of a G-PDU, or the information elements of a signalling
    /// message (see [`information_elements`](Packet::information_elements)).
    pub payload: Vec<u8>,
}

impl Packet {
    /// A message without optional header fields.
    pub fn new(message_type: u8, teid: u32, payload: Vec<u8>) -> Self {
        Self {
            message_type,
            teid,
            sequence: None,
            n_pdu_number: None,
            extension_headers: Vec::new(),
            payload,
        }
    }

    /// A G-PDU without extension headers, as on S1-U.
    pub fn g_pdu(teid: u32, payload: Vec<u8>) -> Self {
        Self::new(G_PDU, teid, payload)
    }

    /// An uplink G-PDU on N3 or N9: its PDU Session Container holds UL PDU
    /// Session Information of QoS flow `qfi`.
    pub fn uplink(teid: u32, qfi: u8, payload: Vec<u8>) -> Self {
        Self::g_pdu(teid, payload).with_container(PduSessionContainer::uplink(qfi))
    }

    /// A downlink G-PDU on N3 or N9: its PDU Session Container holds DL PDU
    /// Session Information of QoS flow `qfi`.
    pub fn downlink(teid: u32, qfi: u8, payload: Vec<u8>) -> Self {
        Self::g_pdu(teid, payload).with_container(PduSessionContainer::downlink(qfi))
    }

    /// An Echo Request. Echo messages always carry a sequence number.
    pub fn echo_request(sequence: u16) -> Self {
        Self::signalling(ECHO_REQUEST, sequence, &[])
    }

    /// The Echo Response to an Echo Request with `sequence`. Its Recovery
    /// restart counter is 0, as TS 29.281 §7.2.2 requires.
    pub fn echo_response(sequence: u16) -> Self {
        Self::signalling(ECHO_RESPONSE, sequence, &[InformationElement::Recovery(0)])
    }

    /// An Error Indication for a G-PDU with TEID `teid` sent to `peer`, the
    /// local address it reached, which has no tunnel with that TEID.
    pub fn error_indication(teid: u32, peer: IpAddr) -> Self {
        Self::signalling(
            ERROR_INDICATION,
            0,
            &[
                InformationElement::TeidDataI(teid),
                InformationElement::GtpUPeerAddress(peer),
            ],
        )
    }

    /// A Supported Extension Headers Notification listing `types`, the
    /// extension header types the sender supports.
    ///
    /// # Panics
    ///
    /// If `types` has more than 255 entries (there are 255 extension header
    /// types).
    pub fn supported_extension_headers_notification(types: &[u8]) -> Self {
        assert!(
            types.len() <= 255,
            "an Extension Header Type List has at most 255 types"
        );
        Self::signalling(
            SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
            0,
            &[InformationElement::ExtensionHeaderTypeList(types.to_vec())],
        )
    }

    /// An End Marker, the last message on the tunnel with TEID `teid` before
    /// its downlink moves to another path.
    pub fn end_marker(teid: u32) -> Self {
        Self::new(END_MARKER, teid, Vec::new())
    }

    fn with_container(mut self, container: PduSessionContainer) -> Self {
        self.extension_headers
            .push(ExtensionHeader::PduSessionContainer(container));
        self
    }

    /// A path management or tunnel management message: TEID 0 and the S
    /// flag set (TS 29.281 §5.1).
    fn signalling(message_type: u8, sequence: u16, elements: &[InformationElement]) -> Self {
        let payload = InformationElement::encode_all(elements)
            .expect("the elements of the constructors above always encode");
        let mut packet = Self::new(message_type, 0, payload);
        packet.sequence = Some(sequence);
        packet
    }

    /// The PDU Session Container, if the message has one.
    pub fn pdu_session_container(&self) -> Option<&PduSessionContainer> {
        self.extension_headers
            .iter()
            .find_map(|header| match header {
                ExtensionHeader::PduSessionContainer(container) => Some(container),
                _ => None,
            })
    }

    /// The QoS Flow Identifier of the PDU Session Container, if any.
    pub fn qfi(&self) -> Option<u8> {
        self.pdu_session_container()
            .and_then(PduSessionContainer::qfi)
    }

    /// Decode the payload as information elements, the content of every
    /// message type except G-PDU.
    pub fn information_elements(&self) -> Result<Vec<InformationElement>, Error> {
        InformationElement::decode_all(&self.payload)
    }

    /// Decode one GTP-U message, the whole payload of a UDP datagram.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Some((header, rest)) = bytes.split_first_chunk::<MANDATORY_LEN>() else {
            return Err(Error::Truncated("GTP-U header"));
        };
        let flags = header[0];
        // Version 1 and protocol type 1; the spare bit is not evaluated.
        if flags & 0xf0 != VERSION_1_GTP {
            return Err(Error::UnsupportedVersion(flags));
        }
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if rest.len() < length {
            return Err(Error::Truncated("GTP-U message"));
        }
        if rest.len() > length {
            return Err(Error::InvalidLength("GTP-U message"));
        }
        let mut packet = Self::new(
            header[1],
            u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            Vec::new(),
        );
        let mut rest = rest;
        if flags & (E | S | PN) != 0 {
            let Some((optional, after)) = rest.split_first_chunk::<OPTIONAL_LEN>() else {
                return Err(Error::Truncated("GTP-U optional header"));
            };
            rest = after;
            if flags & S != 0 {
                packet.sequence = Some(u16::from_be_bytes([optional[0], optional[1]]));
            }
            if flags & PN != 0 {
                packet.n_pdu_number = Some(optional[2]);
            }
            let mut next = if flags & E != 0 { optional[3] } else { 0 };
            while next != 0 {
                let Some(&units) = rest.first() else {
                    return Err(Error::Truncated("extension header"));
                };
                let size = usize::from(units) * 4;
                if size == 0 {
                    return Err(Error::InvalidLength("extension header"));
                }
                let Some((header, after)) = rest.split_at_checked(size) else {
                    return Err(Error::Truncated("extension header"));
                };
                packet
                    .extension_headers
                    .push(ExtensionHeader::decode(next, &header[1..size - 1])?);
                next = header[size - 1];
                rest = after;
            }
        }
        packet.payload = rest.to_vec();
        Ok(packet)
    }

    /// Encode the message.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Validated wire length, including the mandatory header. No output is allocated.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        let optional = self.sequence.is_some()
            || self.n_pdu_number.is_some()
            || !self.extension_headers.is_empty();
        let mut length = self.payload.len();
        if optional {
            length = length
                .checked_add(OPTIONAL_LEN)
                .ok_or(Error::OutOfRange("GTP-U length"))?;
        }
        for header in &self.extension_headers {
            length = length
                .checked_add(header.encoded_len()?)
                .ok_or(Error::OutOfRange("GTP-U length"))?;
        }
        u16::try_from(length).map_err(|_| Error::OutOfRange("GTP-U length"))?;
        Ok(MANDATORY_LEN + length)
    }

    /// Append the message to a reusable buffer. On validation error its contents
    /// and capacity remain unchanged. Call `clear()` first to replace old output.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let length = self.encoded_len()?;
        out.reserve(length);
        let start = out.len();
        let mut flags = VERSION_1_GTP;
        if !self.extension_headers.is_empty() {
            flags |= E;
        }
        if self.sequence.is_some() {
            flags |= S;
        }
        if self.n_pdu_number.is_some() {
            flags |= PN;
        }
        out.extend_from_slice(&[flags, self.message_type, 0, 0]);
        out.extend_from_slice(&self.teid.to_be_bytes());
        if flags & (E | S | PN) != 0 {
            out.extend_from_slice(&self.sequence.unwrap_or(0).to_be_bytes());
            out.push(self.n_pdu_number.unwrap_or(0));
            out.push(
                self.extension_headers
                    .first()
                    .map_or(0, ExtensionHeader::kind),
            );
        }
        for (index, header) in self.extension_headers.iter().enumerate() {
            let next = self
                .extension_headers
                .get(index + 1)
                .map_or(0, ExtensionHeader::kind);
            header.encode(next, out)?;
        }
        out.extend_from_slice(&self.payload);
        let length = (length - MANDATORY_LEN) as u16;
        out[start + 2..start + 4].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        DownlinkPduSessionInformation, UnknownNewIes, UplinkPduSessionInformation, UplinkTimeStamps,
    };

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

    fn round_trip(packet: &Packet, wire: &str) {
        let wire = hex(wire);
        assert_eq!(packet.encode().unwrap(), wire, "encoding of {packet:?}");
        assert_eq!(packet.encoded_len().unwrap(), wire.len());
        let mut appended = vec![0xaa, 0xbb];
        packet.encode_into(&mut appended).unwrap();
        assert_eq!(&appended[2..], wire);
        assert_eq!(&appended[..2], &[0xaa, 0xbb]);
        assert_eq!(&Packet::decode(&wire).unwrap(), packet);
    }

    #[test]
    fn invalid_encoding_leaves_reusable_buffer_unchanged() {
        let mut invalid_extension = Packet::g_pdu(1, vec![1]);
        invalid_extension
            .extension_headers
            .push(ExtensionHeader::Other {
                kind: 0x20,
                content: vec![0; 1022],
            });
        for packet in [
            Packet::g_pdu(1, vec![0; 65536]),
            invalid_extension,
            Packet::uplink(1, 64, vec![]),
        ] {
            let mut buffer = Vec::with_capacity(32);
            buffer.extend_from_slice(&[0xaa, 0xbb]);
            let capacity = buffer.capacity();
            assert!(packet.encoded_len().is_err());
            assert!(packet.encode_into(&mut buffer).is_err());
            assert_eq!(buffer, [0xaa, 0xbb]);
            assert_eq!(buffer.capacity(), capacity);
        }
    }

    #[test]
    fn signalling_messages_on_the_wire() {
        // S=1, TEID 0; the Echo Response carries Recovery with counter 0.
        round_trip(&Packet::echo_request(5), "32 01 0004 00000000 0005 00 00");
        round_trip(
            &Packet::echo_response(5),
            "32 02 0006 00000000 0005 00 00 0e00",
        );
        round_trip(
            &Packet::error_indication(42, Ipv4Addr::LOCALHOST.into()),
            "32 1a 0010 00000000 0000 00 00 10 0000002a 85 0004 7f000001",
        );
        round_trip(
            &Packet::supported_extension_headers_notification(&[0x40, 0x85]),
            "32 1f 0008 00000000 0000 00 00 8d 02 40 85",
        );
        round_trip(&Packet::end_marker(7), "30 fe 0000 00000007");
    }

    #[test]
    fn g_pdus_on_the_wire() {
        round_trip(
            &Packet::g_pdu(0x1234_5678, vec![0x45]),
            "30 ff 0001 12345678 45",
        );
        round_trip(
            &Packet::uplink(0x1234_5678, 9, vec![0x45]),
            "34 ff 0009 12345678 0000 00 85 01 10 09 00 45",
        );
        round_trip(
            &Packet::downlink(1, 63, vec![0x60]),
            "34 ff 0009 00000001 0000 00 85 01 00 3f 00 60",
        );
        let packet = Packet::uplink(1, 9, vec![]);
        assert_eq!(packet.qfi(), Some(9));
        assert_eq!(Packet::g_pdu(1, vec![]).qfi(), None);
    }

    #[test]
    fn every_pdu_session_container_field() {
        let mut downlink = DownlinkPduSessionInformation::new(5);
        downlink.rqi = true;
        downlink.ppi = Some(3);
        downlink.dl_sending_time_stamp = Some(0x0102_0304_0506_0708);
        downlink.dl_qfi_sequence_number = Some(0x0a_0b0c);
        downlink.dl_mbs_qfi_sequence_number = Some(0x1122_3344);
        let mut packet = Packet::g_pdu(1, vec![]);
        packet
            .extension_headers
            .push(ExtensionHeader::PduSessionContainer(
                PduSessionContainer::Downlink(downlink),
            ));
        round_trip(
            &packet,
            "34 ff 0018 00000001 0000 00 85
             05 0e c5 60 0102030405060708 0a0b0c 11223344 00",
        );

        let mut uplink = UplinkPduSessionInformation::new(7);
        uplink.time_stamps = Some(UplinkTimeStamps {
            dl_sending_repeated: 1,
            dl_received: 2,
            ul_sending: 3,
        });
        uplink.dl_delay_result = Some(4);
        uplink.ul_delay_result = Some(5);
        uplink.ul_qfi_sequence_number = Some(6);
        uplink.n3_n9_delay_result = Some(7);
        uplink.d1_ul_pdcp_delay_result_ind = Some(true);
        uplink.ul_congestion_information = Some(9574);
        uplink.dl_congestion_information = Some(1000);
        packet.extension_headers = vec![ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Uplink(uplink.clone()),
        )];
        // New IE Flags 0 to 2, D1 UL PDCP Delay Result Ind, UL and DL
        // Congestion Information, padding.
        round_trip(
            &packet,
            "34 ff 0038 00000001 0000 00 85
             0d 1f c7 0000000000000001 0000000000000002 0000000000000003
             00000004 00000005 000006 00000007 07 01 2566 03e8 000000 00",
        );

        // A later release's New IE Flag 3 and an extension octet.
        let mut uplink = UplinkPduSessionInformation::new(7);
        uplink.d1_ul_pdcp_delay_result_ind = Some(false);
        uplink.unknown_new_ies = Some(UnknownNewIes {
            flags: vec![0x88, 0x01],
            // A new IE of three octets, and the padding.
            content: vec![0xaa, 0xbb, 0xcc, 0x00, 0x00],
        });
        packet.extension_headers = vec![ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Uplink(uplink.clone()),
        )];
        round_trip(
            &packet,
            "34 ff 0010 00000001 0000 00 85 03 10 47 89 01 00 aabbcc0000 00",
        );
        for flags in [vec![], vec![0x00], vec![0x09], vec![0x88], vec![0x08, 0x01]] {
            uplink.unknown_new_ies = Some(UnknownNewIes {
                flags,
                content: vec![],
            });
            packet.extension_headers = vec![ExtensionHeader::PduSessionContainer(
                PduSessionContainer::Uplink(uplink.clone()),
            )];
            assert_eq!(packet.encode(), Err(Error::OutOfRange("New IE Flags")));
        }
    }

    #[test]
    fn downlink_burst_information_round_trips() {
        // TS 38.415 V19.1.0 figure 5.5.2.1-1: PPP=1, PPI=3,
        // BSSI=1, TTNBI=1, BSSize=0x010203, TTNB=0x0405.
        let wire = hex("34 ff 0010 00000001 0000 00 85
             03 00 85 63 010203 0405 0000 00");
        let packet = Packet::decode(&wire).unwrap();
        assert_eq!(packet.encode().unwrap(), wire);
        let Some(PduSessionContainer::Downlink(information)) = packet.pdu_session_container()
        else {
            panic!("not DL PDU Session Information");
        };
        assert_eq!(information.burst_size, Some(0x01_0203));
        assert_eq!(information.time_to_next_burst, Some(0x0405));

        // All combinations of the optional fields, including interactions
        // with timestamps and both sequence numbers.
        for flags in 0u8..64 {
            let mut information = DownlinkPduSessionInformation::new(63);
            information.ppi = (flags & 1 != 0).then_some(7);
            information.dl_sending_time_stamp = (flags & 2 != 0).then_some(u64::MAX);
            information.dl_qfi_sequence_number = (flags & 4 != 0).then_some(0xff_ffff);
            information.dl_mbs_qfi_sequence_number = (flags & 8 != 0).then_some(u32::MAX);
            information.burst_size = (flags & 16 != 0).then_some(0xff_ffff);
            information.time_to_next_burst = (flags & 32 != 0).then_some(u16::MAX);
            let mut packet = Packet::g_pdu(1, vec![0x45]);
            packet
                .extension_headers
                .push(ExtensionHeader::PduSessionContainer(
                    PduSessionContainer::Downlink(information),
                ));
            if flags & 1 == 0 && flags & 48 != 0 {
                assert_eq!(
                    packet.encode(),
                    Err(Error::OutOfRange("burst information without PPI"))
                );
            } else {
                let wire = packet.encode().unwrap();
                let decoded = Packet::decode(&wire).unwrap();
                assert_eq!(decoded, packet);
                assert_eq!(decoded.encode().unwrap(), wire);
            }
        }
    }

    #[test]
    fn downlink_burst_information_rejects_invalid_fields() {
        // BSSize ends after the QFI Sequence Number, beyond the container.
        for content in ["04 85 02 000001", "00 85 03 010203"] {
            assert_eq!(
                Packet::decode(&hex(&format!(
                    "34 ff 000c 00000001 0000 00 85 02 {content} 00"
                ))),
                Err(Error::Truncated("PDU Session Container")),
            );
        }
        let mut information = DownlinkPduSessionInformation::new(1);
        information.ppi = Some(0);
        information.burst_size = Some(0x100_0000);
        let mut packet = Packet::g_pdu(1, vec![]);
        packet
            .extension_headers
            .push(ExtensionHeader::PduSessionContainer(
                PduSessionContainer::Downlink(information),
            ));
        assert_eq!(packet.encode(), Err(Error::OutOfRange("Burst Size")));
    }

    #[test]
    fn extension_header_chain_and_optional_fields() {
        let mut packet = Packet::g_pdu(3, vec![0xaa]);
        packet.sequence = Some(0x0102);
        packet.n_pdu_number = Some(0x33);
        packet.extension_headers = vec![
            ExtensionHeader::UdpPort(2152),
            ExtensionHeader::PduSessionContainer(PduSessionContainer::downlink(1)),
            ExtensionHeader::Other {
                kind: ExtensionHeader::SERVICE_CLASS_INDICATOR,
                content: vec![7, 0],
            },
            // Unknown and comprehension-required: kept for the endpoint to reject.
            ExtensionHeader::Other {
                kind: 0xe0,
                content: vec![1, 2, 3, 4, 5, 6],
            },
        ];
        round_trip(
            &packet,
            "37 ff 0019 00000003 0102 33 40
             01 0868 85  01 0001 20  01 0700 e0  02 010203040506 00  aa",
        );
        assert!(packet.extension_headers[3].comprehension_required());
        assert!(!packet.extension_headers[2].comprehension_required());
    }

    #[test]
    fn follows_the_receiver_rules_of_section_5_1() {
        // E=0: the next extension header type is not interpreted.
        let packet = Packet::decode(&hex("32 ff 0005 00000001 0007 99 85 45")).unwrap();
        assert_eq!(packet.sequence, Some(7));
        assert_eq!(packet.n_pdu_number, None);
        assert!(packet.extension_headers.is_empty());
        assert_eq!(packet.payload, vec![0x45]);
        // S=0: the sequence number is not interpreted either.
        let packet = Packet::decode(&hex("31 ff 0004 00000001 0007 99 00")).unwrap();
        assert_eq!((packet.sequence, packet.n_pdu_number), (None, Some(0x99)));
        // The spare bit is not evaluated.
        assert!(Packet::decode(&hex("38 ff 0000 00000001")).is_ok());
    }

    #[test]
    fn rejects_malformed_messages() {
        let wire = Packet::uplink(1, 3, vec![0x45]).encode().unwrap();
        for length in 0..wire.len() {
            assert!(
                Packet::decode(&wire[..length]).is_err(),
                "prefix of {length}"
            );
        }
        let mut longer = wire.clone();
        longer.push(0);
        assert_eq!(
            Packet::decode(&longer),
            Err(Error::InvalidLength("GTP-U message"))
        );
        for first in [0x50, 0x20, 0x10] {
            assert_eq!(
                Packet::decode(&hex(&format!("{first:02x} ff 0000 00000001"))),
                Err(Error::UnsupportedVersion(first))
            );
        }
        let mut zero_length = wire.clone();
        zero_length[12] = 0;
        assert_eq!(
            Packet::decode(&zero_length),
            Err(Error::InvalidLength("extension header"))
        );
        let mut beyond = wire;
        beyond[12] = 3;
        assert_eq!(
            Packet::decode(&beyond),
            Err(Error::Truncated("extension header"))
        );
        // A UDP Port extension header longer than its port.
        assert_eq!(
            Packet::decode(&hex("34 ff 000c 00000001 0000 00 40 02 0868 00000000 00")),
            Err(Error::InvalidLength("UDP Port extension header"))
        );
        // PPP announces a PPI octet the container does not have.
        assert_eq!(
            Packet::decode(&hex("34 ff 0008 00000001 0000 00 85 01 00 80 00")),
            Err(Error::Truncated("PDU Session Container"))
        );
    }

    #[test]
    fn rejects_values_it_cannot_encode() {
        let mut packet = Packet::downlink(1, 64, vec![]);
        assert_eq!(packet.encode(), Err(Error::OutOfRange("QFI")));
        // Content kept as received must include its padding, or it would not
        // decode back to the same value.
        let unpadded = |container| {
            let mut packet = Packet::g_pdu(1, vec![]);
            packet
                .extension_headers
                .push(ExtensionHeader::PduSessionContainer(container));
            packet.encode()
        };
        assert_eq!(
            unpadded(PduSessionContainer::Other(vec![0x20])),
            Err(Error::InvalidLength("PDU Session Container"))
        );
        let mut uplink = UplinkPduSessionInformation::new(1);
        uplink.unknown_new_ies = Some(UnknownNewIes {
            flags: vec![0x08],
            content: vec![],
        });
        assert_eq!(
            unpadded(PduSessionContainer::Uplink(uplink.clone())),
            Err(Error::InvalidLength("PDU Session Container"))
        );
        uplink.unknown_new_ies.as_mut().unwrap().content = vec![0; 3];
        assert!(unpadded(PduSessionContainer::Uplink(uplink.clone())).is_ok());
        uplink.ul_congestion_information = Some(1);
        assert_eq!(
            unpadded(PduSessionContainer::Uplink(uplink)),
            Err(Error::InvalidLength("PDU Session Container"))
        );
        let mut downlink = DownlinkPduSessionInformation::new(1);
        downlink.dl_mbs_qfi_sequence_number = Some(1);
        assert!(unpadded(PduSessionContainer::Downlink(downlink)).is_ok());
        // Congestion Information above 10000 is not checked: it can arrive.
        let mut congested = UplinkPduSessionInformation::new(1);
        congested.dl_congestion_information = Some(u16::MAX);
        assert!(unpadded(PduSessionContainer::Uplink(congested)).is_ok());
        packet.extension_headers = vec![ExtensionHeader::Other {
            kind: 0,
            content: vec![0, 0],
        }];
        assert_eq!(
            packet.encode(),
            Err(Error::OutOfRange("extension header type"))
        );
        for kind in [
            ExtensionHeader::UDP_PORT,
            ExtensionHeader::PDU_SESSION_CONTAINER,
        ] {
            packet.extension_headers = vec![ExtensionHeader::Other {
                kind,
                content: vec![0, 0],
            }];
            assert_eq!(
                packet.encode(),
                Err(Error::OutOfRange("extension header type"))
            );
        }
        packet.extension_headers = vec![ExtensionHeader::Other {
            kind: 0x20,
            content: vec![0],
        }];
        assert_eq!(
            packet.encode(),
            Err(Error::InvalidLength("extension header"))
        );
        packet.extension_headers = vec![ExtensionHeader::Other {
            kind: 0x20,
            content: vec![0; 1022],
        }];
        assert_eq!(
            packet.encode(),
            Err(Error::OutOfRange("extension header length"))
        );
        let mut downlink = DownlinkPduSessionInformation::new(1);
        downlink.ppi = Some(8);
        packet.extension_headers = vec![ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Downlink(downlink),
        )];
        assert_eq!(packet.encode(), Err(Error::OutOfRange("PPI")));
        assert_eq!(
            Packet::g_pdu(1, vec![0; 65536]).encode(),
            Err(Error::OutOfRange("GTP-U length"))
        );
        assert!(Packet::g_pdu(1, vec![0; 65535]).encode().is_ok());
    }

    #[test]
    fn information_elements() {
        let elements = vec![
            InformationElement::Recovery(0),
            InformationElement::TeidDataI(9),
            InformationElement::GtpUPeerAddress("2001:db8::1".parse().unwrap()),
            InformationElement::ExtensionHeaderTypeList(vec![0x85]),
            InformationElement::Other {
                kind: 230,
                value: vec![1, 2, 3, 4],
            },
            InformationElement::PrivateExtension {
                identifier: 0x1234,
                value: vec![5],
            },
        ];
        let wire = InformationElement::encode_all(&elements).unwrap();
        assert_eq!(
            wire,
            hex("0e00 1000000009 850010 20010db8000000000000000000000001
                 8d0185 e6000401020304 ff0003123405")
        );
        assert_eq!(InformationElement::decode_all(&wire).unwrap(), elements);
        for length in 1..wire.len() {
            // Every cut falls inside an element except the element ends.
            let ends = [2, 7, 26, 29, 36, 42];
            assert_eq!(
                InformationElement::decode_all(&wire[..length]).is_ok(),
                ends.contains(&length),
                "prefix of {length}"
            );
        }
        assert_eq!(
            InformationElement::decode_all(&[6, 0]),
            Err(Error::UnknownInformationElement(6))
        );
        for kind in [14, 133, 141, 255] {
            let other = InformationElement::Other {
                kind,
                value: vec![1],
            };
            assert_eq!(
                InformationElement::encode_all(&[other]),
                Err(Error::OutOfRange("TLV information element type"))
            );
        }
        assert_eq!(
            InformationElement::decode_all(&hex("85 0003 010203")),
            Err(Error::InvalidLength("GTP-U Peer Address"))
        );
        let echo = Packet::echo_response(1);
        assert_eq!(
            echo.information_elements().unwrap(),
            vec![InformationElement::Recovery(0)]
        );
    }
}
