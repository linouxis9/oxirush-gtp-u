//! The GTP-U header and messages (TS 29.281 §5.1, §6, §7).

use std::fmt;
use std::net::IpAddr;

use crate::error::truncated;
use crate::types::{Octets, Teid};
use crate::{
    Error, ExtensionHeader, ExtensionHeaderType, ExtensionHeaders, InformationElement, MessageType,
    Part, PduSessionContainer,
};

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
///
/// `P` defaults to an owned `Vec<u8>`. Constructors also accept slices and
/// other byte buffers implementing `AsRef<[u8]>`. Borrowed decoding keeps the
/// payload in the original datagram; the extension headers are owned, in a
/// list that holds the first of them itself.
///
/// ```
/// use oxirush_gtp_u::{MessageType, Packet};
///
/// # fn main() -> Result<(), oxirush_gtp_u::Error> {
/// let packet = Packet::uplink(0x1234_5678, 9, b"an IP packet".to_vec());
/// let bytes = packet.encode()?;
///
/// let decoded = Packet::decode(&bytes)?;
/// assert_eq!(decoded, packet);
/// assert_eq!(decoded.message_type, MessageType::G_PDU);
/// assert_eq!(decoded.teid, 0x1234_5678);
/// assert_eq!(decoded.qfi(), Some(9));
/// # Ok(())
/// # }
/// ```
///
/// `Debug` prints what a person compares with a capture: the name of the
/// message type, the TEID in hexadecimal, and the payload as its length and
/// all its octets in hexadecimal.
///
/// ```
/// # use oxirush_gtp_u::Packet;
/// let packet = Packet::g_pdu(0x1001, [0x45, 0, 0, 0x1c]);
/// assert_eq!(
///     format!("{packet:?}"),
///     "Packet { message_type: G-PDU (255), teid: 0x00001001, sequence: None, \
///      n_pdu_number: None, extension_headers: [], payload: 4 octets 4500001c }"
/// );
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Packet<P = Vec<u8>> {
    /// Message type, such as [`MessageType::G_PDU`] or
    /// [`MessageType::ECHO_REQUEST`].
    pub message_type: MessageType,
    /// Tunnel Endpoint Identifier, assigned by the receiver of the tunnel;
    /// 0 in path management messages and Error Indication.
    pub teid: u32,
    /// Sequence Number (S flag).
    pub sequence: Option<u16>,
    /// N-PDU Number (PN flag).
    pub n_pdu_number: Option<u8>,
    /// Extension headers, in order (E flag).
    pub extension_headers: ExtensionHeaders,
    /// The T-PDU of a G-PDU, or the information elements of a signalling
    /// message (see [`information_elements`](Packet::information_elements)).
    pub payload: P,
}

impl<P: AsRef<[u8]>> fmt::Debug for Packet<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("message_type", &self.message_type)
            .field("teid", &Teid(self.teid))
            .field("sequence", &self.sequence)
            .field("n_pdu_number", &self.n_pdu_number)
            .field("extension_headers", &self.extension_headers)
            .field("payload", &Octets(self.payload.as_ref()))
            .finish()
    }
}

impl<P: AsRef<[u8]>> Packet<P> {
    /// A message without optional header fields.
    pub fn new(message_type: MessageType, teid: u32, payload: P) -> Self {
        Self {
            message_type,
            teid,
            sequence: None,
            n_pdu_number: None,
            extension_headers: ExtensionHeaders::new(),
            payload,
        }
    }

    /// A G-PDU without extension headers, as on S1-U.
    pub fn g_pdu(teid: u32, payload: P) -> Self {
        Self::new(MessageType::G_PDU, teid, payload)
    }

    /// An uplink G-PDU on N3 or N9: its PDU Session Container holds UL PDU
    /// Session Information of QoS flow `qfi`.
    pub fn uplink(teid: u32, qfi: u8, payload: P) -> Self {
        Self::g_pdu(teid, payload).with_pdu_session_container(PduSessionContainer::uplink(qfi))
    }

    /// A downlink G-PDU on N3 or N9: its PDU Session Container holds DL PDU
    /// Session Information of QoS flow `qfi`.
    pub fn downlink(teid: u32, qfi: u8, payload: P) -> Self {
        Self::g_pdu(teid, payload).with_pdu_session_container(PduSessionContainer::downlink(qfi))
    }

    /// This message with `container` after its extension headers: a G-PDU
    /// whose PDU Session Information has more than a QFI.
    pub fn with_pdu_session_container(mut self, container: PduSessionContainer) -> Self {
        self.extension_headers
            .push(ExtensionHeader::PduSessionContainer(container));
        self
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

    /// The PDU Session Container, if the message has one, to change it.
    pub fn pdu_session_container_mut(&mut self) -> Option<&mut PduSessionContainer> {
        self.extension_headers
            .iter_mut()
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

    /// Give the PDU Session Container QoS flow `qfi` and return the former
    /// one, as [`PduSessionContainer::set_qfi`] does: `None`, and nothing
    /// changes, if the message has no container with a QFI. The encoder
    /// refuses a QFI above 63.
    pub fn set_qfi(&mut self, qfi: u8) -> Option<u8> {
        self.pdu_session_container_mut()?.set_qfi(qfi)
    }
}

impl Packet {
    /// An Echo Request. Echo messages always carry a sequence number.
    pub fn echo_request(sequence: u16) -> Self {
        Self::signalling(MessageType::ECHO_REQUEST, sequence, &[])
    }

    /// The Echo Response to an Echo Request with `sequence`. Its Recovery
    /// restart counter is 0, as TS 29.281 §7.2.2 requires.
    pub fn echo_response(sequence: u16) -> Self {
        Self::signalling(
            MessageType::ECHO_RESPONSE,
            sequence,
            &[InformationElement::Recovery(0)],
        )
    }

    /// An Error Indication for a G-PDU with TEID `teid` sent to `peer`, the
    /// local address it reached, which has no tunnel with that TEID.
    pub fn error_indication(teid: u32, peer: IpAddr) -> Self {
        Self::signalling(
            MessageType::ERROR_INDICATION,
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
    pub fn supported_extension_headers_notification(types: &[ExtensionHeaderType]) -> Self {
        assert!(
            types.len() <= 255,
            "an Extension Header Type List has at most 255 types"
        );
        Self::signalling(
            MessageType::SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
            0,
            &[InformationElement::ExtensionHeaderTypeList(types.to_vec())],
        )
    }

    /// An End Marker, the last message on the tunnel with TEID `teid` before
    /// its downlink moves to another path.
    pub fn end_marker(teid: u32) -> Self {
        Self::new(MessageType::END_MARKER, teid, Vec::new())
    }

    /// A path management or tunnel management message: TEID 0 and the S
    /// flag set (TS 29.281 §5.1).
    fn signalling(
        message_type: MessageType,
        sequence: u16,
        elements: &[InformationElement],
    ) -> Self {
        let payload = InformationElement::encode_all(elements)
            .expect("the elements of the constructors above always encode");
        let mut packet = Self::new(message_type, 0, payload);
        packet.sequence = Some(sequence);
        packet
    }

    /// Make `elements` the payload, as the content of a signalling message,
    /// which [`information_elements`](Packet::information_elements) reads.
    /// On an error the payload stays as it was.
    pub fn set_information_elements(
        &mut self,
        elements: &[InformationElement],
    ) -> Result<(), Error> {
        self.payload = InformationElement::encode_all(elements)?;
        Ok(())
    }

    /// Decode one GTP-U message, the whole payload of a UDP datagram.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        decode(bytes, <[u8]>::to_vec)
    }

    /// Decode a message while borrowing its payload from the input datagram.
    /// The payload is copied only when [`into_owned`](Packet::into_owned) is
    /// called.
    ///
    /// The extension headers are owned. A message without extension header,
    /// or with one that is a UDP Port or a PDU Session Container of downlink
    /// or uplink information without new IEs of a later release, is decoded
    /// without an allocation. A second header allocates the list, and a
    /// header or a PDU type that is kept as received allocates its octets.
    /// A chain of more than [`ExtensionHeaders::MAX`] headers is refused
    /// where it exceeds it.
    pub fn decode_borrowed(bytes: &[u8]) -> Result<Packet<&[u8]>, Error> {
        decode(bytes, |payload| payload)
    }
}

/// Decode a message, whose payload `payload` makes of its octets in the
/// datagram.
#[inline]
fn decode<'a, P>(bytes: &'a [u8], payload: impl Fn(&'a [u8]) -> P) -> Result<Packet<P>, Error> {
    let Some((header, rest)) = bytes.split_first_chunk::<MANDATORY_LEN>() else {
        return Err(truncated(Part::Header, MANDATORY_LEN, bytes));
    };
    let flags = header[0];
    // Version 1 and protocol type 1; the spare bit is not evaluated.
    if flags & 0xf0 != VERSION_1_GTP {
        return Err(Error::UnsupportedVersion(flags));
    }
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if rest.len() < length {
        return Err(truncated(Part::Message, length, rest));
    }
    if rest.len() > length {
        return Err(Error::InvalidLength {
            what: Part::Message,
            length,
            expected: rest.len(),
        });
    }
    let message_type = MessageType(header[1]);
    let teid = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let (mut sequence, mut n_pdu_number, mut next) = (None, None, 0);
    let mut rest = rest;
    if flags & (E | S | PN) != 0 {
        let Some((optional, after)) = rest.split_first_chunk::<OPTIONAL_LEN>() else {
            return Err(truncated(Part::OptionalHeader, OPTIONAL_LEN, rest));
        };
        rest = after;
        if flags & S != 0 {
            sequence = Some(u16::from_be_bytes([optional[0], optional[1]]));
        }
        if flags & PN != 0 {
            n_pdu_number = Some(optional[2]);
        }
        if flags & E != 0 {
            next = optional[3];
        }
    }
    // A message is made once, where it is returned: its list has the room
    // of a header, which a move copies whether the header is there or not.
    let message = |extension_headers, rest| Packet {
        message_type,
        teid,
        sequence,
        n_pdu_number,
        extension_headers,
        payload: payload(rest),
    };
    if next == 0 {
        return Ok(message(ExtensionHeaders::new(), rest));
    }
    let (content, following, after) = extension_header(rest)?;
    let first = ExtensionHeader::decode(next, content)?;
    if following == 0 {
        // The usual chain is one header, which goes from its decoder into
        // the message.
        return Ok(message(first.into(), after));
    }
    let mut extension_headers = ExtensionHeaders::from(first);
    (next, rest) = (following, after);
    while next != 0 {
        if extension_headers.len() == ExtensionHeaders::MAX {
            return Err(TOO_MANY);
        }
        let (content, following, after) = extension_header(rest)?;
        extension_headers.push(ExtensionHeader::decode(next, content)?);
        (next, rest) = (following, after);
    }
    Ok(message(extension_headers, rest))
}

/// The extension header at the start of `rest`: its content, between the
/// length and the type of the next header, that type, and what follows.
#[inline]
fn extension_header(rest: &[u8]) -> Result<(&[u8], u8, &[u8]), Error> {
    let Some(&units) = rest.first() else {
        return Err(truncated(Part::ExtensionHeader, 4, rest));
    };
    let size = usize::from(units) * 4;
    if size == 0 {
        return Err(Error::InvalidLength {
            what: Part::ExtensionHeader,
            length: 0,
            expected: 4,
        });
    }
    let Some((header, after)) = rest.split_at_checked(size) else {
        return Err(truncated(Part::ExtensionHeader, size, rest));
    };
    Ok((&header[1..size - 1], header[size - 1], after))
}

impl Packet<&[u8]> {
    /// Copy the borrowed payload into an owned message, moving its extension
    /// headers without cloning them.
    pub fn into_owned(self) -> Packet {
        Packet {
            message_type: self.message_type,
            teid: self.teid,
            sequence: self.sequence,
            n_pdu_number: self.n_pdu_number,
            extension_headers: self.extension_headers,
            payload: self.payload.to_vec(),
        }
    }
}

impl<P: AsRef<[u8]>> Packet<P> {
    /// Decode the payload as information elements, the content of every
    /// message type except G-PDU.
    pub fn information_elements(&self) -> Result<Vec<InformationElement>, Error> {
        InformationElement::decode_all(self.payload.as_ref())
    }

    /// Encode the message.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Validated wire length, including the mandatory header. No output is allocated.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        self.encoded_len_for_payload(self.payload.as_ref().len())
    }

    fn encoded_len_for_payload(&self, payload_length: usize) -> Result<usize, Error> {
        if self.extension_headers.len() > ExtensionHeaders::MAX {
            return Err(TOO_MANY);
        }
        let optional = self.sequence.is_some()
            || self.n_pdu_number.is_some()
            || !self.extension_headers.is_empty();
        // What the Length field counts. A sum that a `usize` cannot hold is
        // reported as the largest one.
        let mut length = payload_length;
        if optional {
            length = length.saturating_add(OPTIONAL_LEN);
        }
        for header in &self.extension_headers {
            length = length.saturating_add(header.encoded_len()?);
        }
        if length > usize::from(u16::MAX) {
            return Err(Error::OutOfRange {
                what: Part::Length,
                value: length as u64,
                max: u64::from(u16::MAX),
            });
        }
        Ok(MANDATORY_LEN + length)
    }

    /// Append the message to a reusable buffer. On validation error its contents
    /// and capacity remain unchanged. Call `clear()` first to replace old output.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let payload = self.payload.as_ref();
        let length = self.encoded_len_for_payload(payload.len())?;
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
        out.extend_from_slice(&[flags, self.message_type.0, 0, 0]);
        out.extend_from_slice(&self.teid.to_be_bytes());
        if flags & (E | S | PN) != 0 {
            out.extend_from_slice(&self.sequence.unwrap_or(0).to_be_bytes());
            out.push(self.n_pdu_number.unwrap_or(0));
            out.push(self.extension_headers.first().map_or(0, kind));
        }
        for (index, header) in self.extension_headers.iter().enumerate() {
            let next = self.extension_headers.get(index + 1).map_or(0, kind);
            header.encode(next, out)?;
        }
        out.extend_from_slice(payload);
        let length = (length - MANDATORY_LEN) as u16;
        out[start + 2..start + 4].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }
}

const TOO_MANY: Error = Error::TooManyExtensionHeaders {
    max: ExtensionHeaders::MAX,
};

/// The type of an extension header, as the octet that names it to the
/// header before it.
fn kind(header: &ExtensionHeader) -> u8 {
    header.kind().0
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        DownlinkPduSessionInformation, DownlinkPduSetInformation, InformationElementType,
        PduSetInformationContainer, UnknownNewIes, UplinkPduSessionInformation, UplinkTimeStamps,
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

    /// An uplink G-PDU that go-gtp v0.8.12 made, whose TEID and QFI a
    /// program changes before it sends it again.
    #[test]
    fn what_has_a_getter_has_a_setter() {
        let wire = hex(
            "34ff0029 11223344 00000085 01100900 45000021 00004000 40116e9c \
             0a2d0002 c0000201 0fa00007 000de02a 68656c6c 6f",
        );
        let mut packet = Packet::decode(&wire).unwrap();
        packet.teid = 0x5566_7788;
        assert_eq!(packet.set_qfi(5), Some(9));
        assert_eq!(packet.qfi(), Some(5));
        let mut changed = wire.clone();
        changed[4..8].copy_from_slice(&[0x55, 0x66, 0x77, 0x88]);
        changed[14] = 5;
        assert_eq!(packet.encode().unwrap(), changed);
        // The container itself, as its getter gives it.
        if let Some(PduSessionContainer::Uplink(information)) = packet.pdu_session_container_mut() {
            information.qfi = 7;
            information.ul_qfi_sequence_number = Some(3);
        }
        assert_eq!(packet.qfi(), Some(7));
        assert_eq!(
            packet.pdu_session_container().unwrap(),
            &PduSessionContainer::Uplink({
                let mut information = UplinkPduSessionInformation::new(7);
                information.ul_qfi_sequence_number = Some(3);
                information
            })
        );
        // A message without a container, and a container of another type,
        // have no QFI to change.
        let mut plain = Packet::g_pdu(1, vec![0x45]);
        assert_eq!(plain.set_qfi(5), None);
        assert_eq!(plain, Packet::g_pdu(1, vec![0x45]));
        let mut other = PduSessionContainer::Other(vec![0x20, 0]);
        assert_eq!(other.set_qfi(5), None);
        let mut downlink = PduSessionContainer::downlink(1);
        assert_eq!(downlink.set_qfi(2), Some(1));
        assert_eq!(downlink.qfi(), Some(2));
        let mut pdu_set = PduSetInformationContainer::Downlink(DownlinkPduSetInformation::new(3));
        assert_eq!(pdu_set.set_qfi(4), Some(3));
        assert_eq!(pdu_set.qfi(), Some(4));
        // A signalling message's elements, as `information_elements` reads them.
        let mut indication = Packet::new(MessageType::ERROR_INDICATION, 0, Vec::new());
        let elements = [
            InformationElement::TeidDataI(0x1001),
            InformationElement::GtpUPeerAddress(Ipv4Addr::new(192, 0, 2, 1).into()),
        ];
        indication.set_information_elements(&elements).unwrap();
        assert_eq!(indication.information_elements().unwrap(), elements);
        let refused = [InformationElement::OtherTv {
            kind: InformationElementType::RECOVERY,
            value: vec![0],
        }];
        assert!(indication.set_information_elements(&refused).is_err());
        assert_eq!(indication.information_elements().unwrap(), elements);
    }

    /// An extension header whose length octet says that it has none.
    const NO_OCTETS: Error = Error::InvalidLength {
        what: Part::ExtensionHeader,
        length: 0,
        expected: 4,
    };

    fn round_trip(packet: &Packet, wire: &str) {
        let wire = hex(wire);
        assert_eq!(packet.encode().unwrap(), wire, "encoding of {packet:?}");
        assert_eq!(packet.encoded_len().unwrap(), wire.len());
        let mut appended = vec![0xaa, 0xbb];
        packet.encode_into(&mut appended).unwrap();
        assert_eq!(&appended[2..], wire);
        assert_eq!(&appended[..2], &[0xaa, 0xbb]);
        assert_eq!(&Packet::decode(&wire).unwrap(), packet);
        let borrowed = Packet::decode_borrowed(&wire).unwrap();
        assert_eq!(borrowed.encode().unwrap(), wire);
        assert_eq!(borrowed.encoded_len().unwrap(), wire.len());
        assert_eq!(
            borrowed.payload.as_ptr(),
            wire[wire.len() - borrowed.payload.len()..].as_ptr()
        );
        assert_eq!(borrowed.into_owned(), *packet);
    }

    #[test]
    fn constructors_accept_owned_buffers_slices_and_arrays() {
        let payload = [0x45, 0, 1];
        let owned: Packet = Packet::g_pdu(1, payload.to_vec());
        let borrowed: Packet<&[u8]> = Packet::g_pdu(1, &payload[..]);
        let array = Packet::g_pdu(1, payload);
        let boxed = Packet::g_pdu(1, Box::<[u8]>::from(payload));
        assert_eq!(borrowed.encode().unwrap(), owned.encode().unwrap());
        assert_eq!(array.encode().unwrap(), owned.encode().unwrap());
        assert_eq!(boxed.encode().unwrap(), owned.encode().unwrap());
        assert_eq!(borrowed.into_owned(), owned);
        let empty = Packet::uplink(1, 9, vec![]);
        assert_eq!(empty.qfi(), Some(9));
    }

    #[test]
    fn encoding_validates_and_writes_one_payload_snapshot() {
        struct Payload(std::cell::Cell<usize>);
        impl AsRef<[u8]> for Payload {
            fn as_ref(&self) -> &[u8] {
                let calls = self.0.get();
                self.0.set(calls + 1);
                if calls == 0 {
                    b"one"
                } else {
                    b"another payload"
                }
            }
        }
        let packet = Packet::g_pdu(1, Payload(std::cell::Cell::new(0)));
        let wire = packet.encode().unwrap();
        assert_eq!(packet.payload.0.get(), 1);
        assert_eq!(Packet::decode(&wire).unwrap().payload, b"one");
    }

    #[test]
    fn invalid_encoding_leaves_reusable_buffer_unchanged() {
        let mut invalid_extension = Packet::g_pdu(1, vec![1]);
        invalid_extension
            .extension_headers
            .push(ExtensionHeader::Other {
                kind: ExtensionHeaderType(0x21),
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
            &Packet::supported_extension_headers_notification(&[
                ExtensionHeaderType::UDP_PORT,
                ExtensionHeaderType::PDU_SESSION_CONTAINER,
            ]),
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
        )]
        .into();
        // New IE Flags 0 to 2, D1 UL PDCP Delay Result Ind, UL and DL
        // Congestion Information, padding.
        round_trip(
            &packet,
            "34 ff 0038 00000001 0000 00 85
             0d 1f c7 0000000000000001 0000000000000002 0000000000000003
             00000004 00000005 000006 00000007 07 01 2566 03e8 000000 00",
        );

        // A later release's New IE Flag 5 and an extension octet.
        let mut uplink = UplinkPduSessionInformation::new(7);
        uplink.d1_ul_pdcp_delay_result_ind = Some(false);
        uplink.unknown_new_ies = Some(Box::new(UnknownNewIes {
            flags: vec![0xa0, 0x01],
            // A new IE of three octets, and the padding.
            content: vec![0xaa, 0xbb, 0xcc, 0x00, 0x00],
        }));
        packet.extension_headers = vec![ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Uplink(uplink.clone()),
        )]
        .into();
        round_trip(
            &packet,
            "34 ff 0010 00000001 0000 00 85 03 10 47 a1 01 00 aabbcc0000 00",
        );
        // No octet, a first octet without a flag, one with a flag that has a
        // field of its own (0, 3 or 4), an E bit without the octet that it
        // announces, and an octet that no E bit announces.
        for flags in [
            vec![],
            vec![0x00],
            vec![0x21],
            vec![0x28],
            vec![0x30],
            vec![0xa0],
            vec![0x20, 0x01],
        ] {
            uplink.unknown_new_ies = Some(Box::new(UnknownNewIes {
                flags,
                content: vec![],
            }));
            packet.extension_headers = vec![ExtensionHeader::PduSessionContainer(
                PduSessionContainer::Uplink(uplink.clone()),
            )]
            .into();
            assert_eq!(packet.encode(), Err(Error::Malformed(Part::NewIeFlags)));
        }
    }

    /// The UL and DL Available Bitrate of TS 38.415 V19.1.0, which figure
    /// 5.5.2.2-1 puts after the congestion information: New IE Flags 3 and
    /// 4, four octets each, in kbit/s.
    #[test]
    fn uplink_available_bitrates_on_the_wire() {
        let container = |uplink: &UplinkPduSessionInformation| {
            Packet::g_pdu(1, vec![])
                .with_pdu_session_container(PduSessionContainer::Uplink(uplink.clone()))
        };
        let mut uplink = UplinkPduSessionInformation::new(7);
        uplink.ul_available_bitrate = Some(1_000_000);
        uplink.dl_available_bitrate = Some(4_000_000_000);
        // The New IE Flag, flags 3 and 4, the two bitrates, padding.
        round_trip(
            &container(&uplink),
            "34 ff 0014 00000001 0000 00 85
             04 10 47 18 000f4240 ee6b2800 000000 00",
        );
        // Each alone.
        uplink.dl_available_bitrate = None;
        round_trip(
            &container(&uplink),
            "34 ff 0010 00000001 0000 00 85  03 10 47 08 000f4240 000000 00",
        );
        uplink.ul_available_bitrate = None;
        uplink.dl_available_bitrate = Some(u32::MAX);
        round_trip(
            &container(&uplink),
            "34 ff 0010 00000001 0000 00 85  03 10 47 10 ffffffff 000000 00",
        );
        // After the three IEs of the flags before theirs, and before those
        // of a later release.
        uplink.d1_ul_pdcp_delay_result_ind = Some(true);
        uplink.ul_congestion_information = Some(9574);
        uplink.dl_congestion_information = Some(1000);
        uplink.ul_available_bitrate = Some(0x0102_0304);
        uplink.dl_available_bitrate = Some(0x0506_0708);
        uplink.unknown_new_ies = Some(Box::new(UnknownNewIes {
            flags: vec![0x20],
            // A new IE of three octets, and the padding.
            content: vec![0xaa, 0xbb, 0xcc, 0, 0, 0],
        }));
        round_trip(
            &container(&uplink),
            "34 ff 001c 00000001 0000 00 85
             06 10 47 3f 01 2566 03e8 01020304 05060708 aabbcc 000000 00",
        );
        // Flag 4 announces a bitrate where the container has its padding.
        assert_eq!(
            Packet::decode(&hex(
                "34 ff 0010 00000001 0000 00 85  03 10 47 18 000f4240 000000 00"
            )),
            Err(Error::Truncated {
                what: Part::PduSessionContainer,
                needed: 4,
                available: 3
            })
        );
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
                assert_eq!(packet.encode(), Err(Error::Missing(Part::Ppi)));
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
        // BSSize ends after the QFI Sequence Number, beyond the container,
        // and so does TTNB after BSSize.
        for (content, needed) in [("04 85 02 000001", 3), ("00 85 03 010203", 2)] {
            assert_eq!(
                Packet::decode(&hex(&format!(
                    "34 ff 000c 00000001 0000 00 85 02 {content} 00"
                ))),
                Err(Error::Truncated {
                    what: Part::PduSessionContainer,
                    needed,
                    available: 0
                }),
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
        assert_eq!(
            packet.encode(),
            Err(Error::OutOfRange {
                what: Part::BurstSize,
                value: 0x100_0000,
                max: 0xff_ffff
            })
        );
    }

    #[test]
    fn extension_header_chain_and_optional_fields() {
        let mut packet = Packet::g_pdu(3, vec![0xaa]);
        packet.sequence = Some(0x0102);
        packet.n_pdu_number = Some(0x33);
        packet.extension_headers = vec![
            ExtensionHeader::UdpPort(2152),
            ExtensionHeader::PduSessionContainer(PduSessionContainer::downlink(1)),
            ExtensionHeader::ServiceClassIndicator(7),
            // Unknown and comprehension-required: kept for the endpoint to reject.
            ExtensionHeader::Other {
                kind: ExtensionHeaderType(0xe0),
                content: vec![1, 2, 3, 4, 5, 6],
            },
        ]
        .into();
        round_trip(
            &packet,
            "37 ff 0019 00000003 0102 33 40
             01 0868 85  01 0001 20  01 0700 e0  02 010203040506 00  aa",
        );
        assert!(packet.extension_headers[3].comprehension_required());
        assert!(!packet.extension_headers[2].comprehension_required());
    }

    #[test]
    fn a_chain_that_ends_badly_is_an_error_wherever_it_does() {
        // The chain above: four headers, at octets 12, 16, 20 and 24.
        let wire = hex("37 ff 0019 00000003 0102 33 40
             01 0868 85  01 0001 20  01 0700 e0  02 010203040506 00  aa");
        assert_eq!(Packet::decode(&wire).unwrap().extension_headers.len(), 4);
        // The message ends inside the chain, or where another header is due.
        for end in 12..32 {
            let mut short = wire[..end].to_vec();
            short[2..4].copy_from_slice(&((end - 8) as u16).to_be_bytes());
            // The header that is cut starts at a multiple of 4. The last
            // one says that it is 8 octets long, once its first octet is
            // there; one that is not there at all needs 4 at least.
            let (start, needed) = if end > 24 { (24, 8) } else { (end / 4 * 4, 4) };
            assert_eq!(
                Packet::decode(&short),
                Err(Error::Truncated {
                    what: Part::ExtensionHeader,
                    needed,
                    available: end - start
                }),
                "{end} octets"
            );
        }
        for start in [12, 16, 20, 24] {
            // A header of no octets would never end the chain.
            let mut empty = wire.clone();
            empty[start] = 0;
            assert_eq!(Packet::decode(&empty), Err(NO_OCTETS));
            // A header longer than what is left of the message.
            let mut beyond = wire.clone();
            beyond[start] = 0xff;
            assert_eq!(
                Packet::decode(&beyond),
                Err(Error::Truncated {
                    what: Part::ExtensionHeader,
                    needed: 4 * 0xff,
                    available: wire.len() - start
                })
            );
        }
        // The last header names a next one, and the payload is not one.
        let mut next = wire.clone();
        next[31] = 0x40;
        assert_eq!(
            Packet::decode(&next),
            Err(Error::Truncated {
                what: Part::ExtensionHeader,
                needed: 4 * 0xaa,
                available: 1
            })
        );
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
            Err(Error::InvalidLength {
                what: Part::Message,
                length: 9,
                expected: 10
            })
        );
        for first in [0x50, 0x20, 0x10] {
            assert_eq!(
                Packet::decode(&hex(&format!("{first:02x} ff 0000 00000001"))),
                Err(Error::UnsupportedVersion(first))
            );
        }
        let mut zero_length = wire.clone();
        zero_length[12] = 0;
        assert_eq!(Packet::decode(&zero_length), Err(NO_OCTETS));
        let mut beyond = wire;
        beyond[12] = 3;
        assert_eq!(
            Packet::decode(&beyond),
            Err(Error::Truncated {
                what: Part::ExtensionHeader,
                needed: 12,
                available: 5
            })
        );
        // A UDP Port extension header longer than its port.
        assert_eq!(
            Packet::decode(&hex("34 ff 000c 00000001 0000 00 40 02 0868 00000000 00")),
            Err(Error::InvalidLength {
                what: Part::UdpPort,
                length: 8,
                expected: 4
            })
        );
        // PPP announces a PPI octet the container does not have.
        assert_eq!(
            Packet::decode(&hex("34 ff 0008 00000001 0000 00 85 01 00 80 00")),
            Err(Error::Truncated {
                what: Part::PduSessionContainer,
                needed: 1,
                available: 0
            })
        );
    }

    #[test]
    fn rejects_values_it_cannot_encode() {
        let mut packet = Packet::downlink(1, 64, vec![]);
        assert_eq!(
            packet.encode(),
            Err(Error::OutOfRange {
                what: Part::Qfi,
                value: 64,
                max: 63
            })
        );
        // Content kept as received must include its padding, or it would not
        // decode back to the same value.
        let unpadded = |container| {
            let mut packet = Packet::g_pdu(1, vec![]);
            packet
                .extension_headers
                .push(ExtensionHeader::PduSessionContainer(container));
            packet.encode()
        };
        // The lengths are those of the extension header, with its length and
        // next type octets.
        let container = |length, expected| Error::InvalidLength {
            what: Part::PduSessionContainer,
            length,
            expected,
        };
        assert_eq!(
            unpadded(PduSessionContainer::Other(vec![0x20])),
            Err(container(3, 4))
        );
        assert_eq!(
            unpadded(PduSessionContainer::Other(vec![])),
            Err(container(2, 4))
        );
        assert_eq!(
            unpadded(PduSessionContainer::Other(vec![0x10, 0])),
            Err(Error::InvalidType {
                what: Part::PduSessionContainer,
                kind: 1
            })
        );
        let mut uplink = UplinkPduSessionInformation::new(1);
        uplink.unknown_new_ies = Some(Box::new(UnknownNewIes {
            flags: vec![0x20],
            content: vec![],
        }));
        assert_eq!(
            unpadded(PduSessionContainer::Uplink(uplink.clone())),
            Err(container(5, 8))
        );
        uplink.unknown_new_ies.as_mut().unwrap().content = vec![0; 3];
        assert!(unpadded(PduSessionContainer::Uplink(uplink.clone())).is_ok());
        uplink.ul_congestion_information = Some(1);
        assert_eq!(
            unpadded(PduSessionContainer::Uplink(uplink)),
            Err(container(10, 12))
        );
        let mut downlink = DownlinkPduSessionInformation::new(1);
        downlink.dl_mbs_qfi_sequence_number = Some(1);
        assert!(unpadded(PduSessionContainer::Downlink(downlink)).is_ok());
        // Congestion Information above 10000 is not checked: it can arrive.
        let mut congested = UplinkPduSessionInformation::new(1);
        congested.dl_congestion_information = Some(u16::MAX);
        assert!(unpadded(PduSessionContainer::Uplink(congested)).is_ok());
        packet.extension_headers = vec![ExtensionHeader::Other {
            kind: ExtensionHeaderType(0),
            content: vec![0, 0],
        }]
        .into();
        let kept = |kind| Error::InvalidType {
            what: Part::ExtensionHeader,
            kind,
        };
        assert_eq!(packet.encode(), Err(kept(0)));
        // A type that has a variant of its own is not kept as octets.
        for kind in ExtensionHeader::TYPES {
            packet.extension_headers = vec![ExtensionHeader::Other {
                kind,
                content: vec![0, 0],
            }]
            .into();
            assert_eq!(packet.encode(), Err(kept(kind.0)));
        }
        packet.extension_headers = vec![ExtensionHeader::Other {
            kind: ExtensionHeaderType(0x21),
            content: vec![0],
        }]
        .into();
        assert_eq!(
            packet.encode(),
            Err(Error::InvalidLength {
                what: Part::ExtensionHeader,
                length: 3,
                expected: 4
            })
        );
        packet.extension_headers = vec![ExtensionHeader::Other {
            kind: ExtensionHeaderType(0x21),
            content: vec![0; 1022],
        }]
        .into();
        assert_eq!(
            packet.encode(),
            Err(Error::OutOfRange {
                what: Part::ExtensionHeader,
                value: 1024,
                max: 1020
            })
        );
        let mut downlink = DownlinkPduSessionInformation::new(1);
        downlink.ppi = Some(8);
        packet.extension_headers = vec![ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Downlink(downlink),
        )]
        .into();
        assert_eq!(
            packet.encode(),
            Err(Error::OutOfRange {
                what: Part::Ppi,
                value: 8,
                max: 7
            })
        );
        assert_eq!(
            Packet::g_pdu(1, vec![0; 65536]).encode(),
            Err(Error::OutOfRange {
                what: Part::Length,
                value: 65536,
                max: 65535
            })
        );
        assert!(Packet::g_pdu(1, vec![0; 65535]).encode().is_ok());
    }

    /// The headers of a handover, and those that carry the frames of a RAN
    /// protocol, as figures 5.2.2.2-1 to 5.2.2.6-1 of TS 29.281 draw them.
    #[test]
    fn handover_and_forwarding_headers_on_the_wire() {
        let with = |header| {
            let mut packet = Packet::g_pdu(0x2001, vec![0x45]);
            packet.extension_headers.push(header);
            packet
        };
        // A PDCP PDU Number of 12 bits, between NG-RAN nodes.
        round_trip(
            &with(ExtensionHeader::PdcpPduNumber(0x0abc)),
            "34 ff 0009 00002001 0000 00 c0  01 0abc 00  45",
        );
        // 18 bits, then three spare octets: with the type of this release
        // and with that of earlier ones.
        for (legacy_type, kind) in [(false, "03"), (true, "82")] {
            let header = ExtensionHeader::LongPdcpPduNumber {
                number: 0x2_abcd,
                legacy_type,
            };
            round_trip(
                &with(header),
                &format!("34 ff 000d 00002001 0000 00 {kind}  02 02abcd 000000 00  45"),
            );
        }
        round_trip(
            &with(ExtensionHeader::ServiceClassIndicator(7)),
            "34 ff 0009 00002001 0000 00 20  01 07 00 00  45",
        );
        for (header, kind) in [
            (ExtensionHeader::RanContainer(vec![0xaa, 0xbb]), "81"),
            (ExtensionHeader::XwRanContainer(vec![0xaa, 0xbb]), "83"),
            (ExtensionHeader::NrRanContainer(vec![0xaa, 0xbb]), "84"),
        ] {
            assert!(header.comprehension_required());
            round_trip(
                &with(header),
                &format!("34 ff 0009 00002001 0000 00 {kind}  01 aabb 00  45"),
            );
        }
        // A frame of flow control, which a G-PDU carries without a T-PDU.
        let mut frame = Packet::g_pdu(0x2001, vec![]);
        frame
            .extension_headers
            .push(ExtensionHeader::NrRanContainer(vec![1, 2, 3, 4, 5, 6]));
        round_trip(&frame, "34 ff 000c 00002001 0000 00 84  02 010203040506 00");
        // The End Marker of a forwarding tunnel between 5GS and EPS has the
        // PDU Session Container (§7.3.2).
        round_trip(
            &Packet::end_marker(0x2001)
                .with_pdu_session_container(PduSessionContainer::downlink(9)),
            "34 fe 0008 00002001 0000 00 85  01 0009 00",
        );
    }

    #[test]
    fn handover_headers_follow_the_receiver_and_the_sender_rules() {
        let decode = |wire: &str| Packet::decode(&hex(wire));
        let headers = |wire: &str| decode(wire).unwrap().extension_headers;
        // Spare bits and octets that a sender set are not evaluated.
        assert_eq!(
            headers("34 ff 000c 00002001 0000 00 03  02 feabcd 112233 00"),
            [ExtensionHeader::LongPdcpPduNumber {
                number: 0x2_abcd,
                legacy_type: false
            }]
        );
        assert_eq!(
            headers("34 ff 0008 00002001 0000 00 20  01 87 ff 00"),
            [ExtensionHeader::ServiceClassIndicator(0x87)]
        );
        // All 16 bits of a PDCP PDU Number are kept: UTRAN uses them.
        assert_eq!(
            headers("34 ff 0008 00002001 0000 00 c0  01 ffff 00"),
            [ExtensionHeader::PdcpPduNumber(0xffff)]
        );
        // Each of the three has one length.
        for (kind, what, expected) in [
            ("c0", Part::PdcpPduNumber, 4),
            ("20", Part::ServiceClassIndicator, 4),
            ("03", Part::LongPdcpPduNumber, 8),
            ("82", Part::LongPdcpPduNumber, 8),
        ] {
            let other = if expected == 4 {
                "02 000000000000 00"
            } else {
                "01 0000 00"
            };
            let length = 4 + other.split_whitespace().map(str::len).sum::<usize>() / 2;
            assert_eq!(
                decode(&format!(
                    "34 ff {length:04x} 00002001 0000 00 {kind}  {other}"
                )),
                Err(Error::InvalidLength {
                    what,
                    length: 12 - expected,
                    expected
                })
            );
        }
        let encode = |header| {
            let mut packet = Packet::g_pdu(1, vec![]);
            packet.extension_headers.push(header);
            packet.encode()
        };
        assert_eq!(
            encode(ExtensionHeader::LongPdcpPduNumber {
                number: 0x4_0000,
                legacy_type: false
            }),
            Err(Error::OutOfRange {
                what: Part::LongPdcpPduNumber,
                value: 0x4_0000,
                max: 0x3_ffff
            })
        );
        // A container has its padding, as a header that is kept as octets.
        for (header, what) in [
            (ExtensionHeader::RanContainer(vec![1]), Part::RanContainer),
            (
                ExtensionHeader::XwRanContainer(vec![]),
                Part::XwRanContainer,
            ),
            (
                ExtensionHeader::NrRanContainer(vec![1, 2, 3]),
                Part::NrRanContainer,
            ),
        ] {
            let length = match &header {
                ExtensionHeader::RanContainer(content)
                | ExtensionHeader::XwRanContainer(content)
                | ExtensionHeader::NrRanContainer(content) => content.len() + 2,
                _ => unreachable!(),
            };
            assert_eq!(
                encode(header),
                Err(Error::InvalidLength {
                    what,
                    length,
                    expected: 4 * length.div_ceil(4)
                })
            );
        }
    }

    /// DL PDU SET INFORMATION, as figure 6.5.2.1-1 of TS 38.415 V19.1.0
    /// draws it: EDB, EPDU and PSSI in the first octet, six bits of QFI and
    /// ten of PSSN, four of PSI, the PSN, then the PSSize if PSSI says so.
    #[test]
    fn pdu_set_information_on_the_wire() {
        let mut information = DownlinkPduSetInformation::new(9);
        information.pdu_set_sequence_number = 0x2a5;
        information.pdu_set_importance = 3;
        information.pdu_sequence_number = 7;
        let mut packet = Packet::downlink(0x2001, 9, vec![0x45]);
        let header = |information, legacy_type| ExtensionHeader::PduSetInformationContainer {
            information: PduSetInformationContainer::Downlink(information),
            legacy_type,
        };
        // After the PDU Session Container, as the specification asks.
        packet.extension_headers.push(header(information, false));
        round_trip(
            &packet,
            "34 ff 0011 00002001 0000 00 85  01 0009 04  02 00 26a5 03 07 00 00  45",
        );
        // The last PDU of its PDU Set and of a data burst, with the size of
        // the set, under the type of earlier versions.
        information.end_of_data_burst = true;
        information.end_pdu = true;
        information.pdu_set_size = Some(0x01_0203);
        packet.extension_headers[1] = header(information, true);
        round_trip(
            &packet,
            "34 ff 0015 00002001 0000 00 85  01 0009 86
             03 0e 26a5 03 07 010203 0000 00  45",
        );
        assert!(packet.extension_headers[1].comprehension_required());
        // Every field at its largest and at its least.
        let mut most = DownlinkPduSetInformation::new(63);
        most.pdu_set_sequence_number = 0x3ff;
        most.pdu_set_importance = 15;
        most.pdu_sequence_number = 255;
        most.pdu_set_size = Some(0xff_ffff);
        for information in [most, DownlinkPduSetInformation::new(0)] {
            let mut packet = Packet::g_pdu(1, vec![]);
            packet.extension_headers.push(header(information, false));
            let wire = packet.encode().unwrap();
            assert_eq!(Packet::decode(&wire).unwrap(), packet);
        }
        assert_eq!(
            Packet::g_pdu(1, vec![])
                .encode()
                .map(|wire| wire.len())
                .unwrap(),
            8
        );
        // Spare bits are not evaluated, and what follows the fields is
        // padding.
        let decoded = Packet::decode(&hex(
            "34 ff 000c 00000001 0000 00 04  02 01 26a5 f3 07 ff 00",
        ))
        .unwrap();
        information.end_of_data_burst = false;
        information.end_pdu = false;
        information.pdu_set_size = None;
        assert_eq!(decoded.extension_headers, [header(information, false)]);

        // Another PDU type is kept as received.
        let other = ExtensionHeader::PduSetInformationContainer {
            information: PduSetInformationContainer::Other(vec![0x10, 1, 2, 3, 4, 5]),
            legacy_type: false,
        };
        let mut packet = Packet::g_pdu(1, vec![]);
        packet.extension_headers.push(other);
        round_trip(
            &packet,
            "34 ff 000c 00000001 0000 00 04  02 10 0102030405 00",
        );
    }

    #[test]
    fn pdu_set_information_rejects_what_it_cannot_carry() {
        let container = Part::PduSetInformationContainer;
        // The frame has five octets at least, and three more with PSSI.
        assert_eq!(
            Packet::decode(&hex("34 ff 0008 00000001 0000 00 04  01 00 26 00")),
            Err(Error::Truncated {
                what: container,
                needed: 5,
                available: 2
            })
        );
        assert_eq!(
            Packet::decode(&hex(
                "34 ff 000c 00000001 0000 00 04  02 02 26a5 03 07 01 00"
            )),
            Err(Error::Truncated {
                what: container,
                needed: 3,
                available: 1
            })
        );
        let encode = |information: PduSetInformationContainer| {
            let mut packet = Packet::g_pdu(1, vec![]);
            packet
                .extension_headers
                .push(ExtensionHeader::PduSetInformationContainer {
                    information,
                    legacy_type: false,
                });
            packet.encode()
        };
        let out_of_range = |change: fn(&mut DownlinkPduSetInformation)| {
            let mut information = DownlinkPduSetInformation::new(1);
            change(&mut information);
            encode(PduSetInformationContainer::Downlink(information))
        };
        for (result, what, value, max) in [
            (out_of_range(|i| i.qfi = 64), Part::Qfi, 64, 63),
            (
                out_of_range(|i| i.pdu_set_sequence_number = 0x400),
                Part::PduSetSequenceNumber,
                0x400,
                0x3ff,
            ),
            (
                out_of_range(|i| i.pdu_set_importance = 16),
                Part::PduSetImportance,
                16,
                15,
            ),
            (
                out_of_range(|i| i.pdu_set_size = Some(0x100_0000)),
                Part::PduSetSize,
                0x100_0000,
                0xff_ffff,
            ),
        ] {
            assert_eq!(result, Err(Error::OutOfRange { what, value, max }));
        }
        // Content that is kept as received has its padding, and is not of
        // the PDU type that has a variant.
        assert_eq!(
            encode(PduSetInformationContainer::Other(vec![0x10])),
            Err(Error::InvalidLength {
                what: container,
                length: 3,
                expected: 4
            })
        );
        assert_eq!(
            encode(PduSetInformationContainer::Other(vec![])),
            Err(Error::InvalidLength {
                what: container,
                length: 2,
                expected: 4
            })
        );
        assert_eq!(
            encode(PduSetInformationContainer::Other(vec![0x00, 0])),
            Err(Error::InvalidType {
                what: container,
                kind: 0
            })
        );
    }

    #[test]
    fn information_elements() {
        let elements = vec![
            InformationElement::Recovery(0),
            InformationElement::TeidDataI(9),
            InformationElement::GtpUPeerAddress("2001:db8::1".parse().unwrap()),
            InformationElement::ExtensionHeaderTypeList(vec![
                ExtensionHeaderType::PDU_SESSION_CONTAINER,
            ]),
            InformationElement::Other {
                kind: InformationElementType::GTP_U_TUNNEL_STATUS_INFORMATION,
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
            Err(Error::UnknownInformationElement(InformationElementType(6)))
        );
        for kind in [14, 133, 141, 255] {
            let other = InformationElement::Other {
                kind: InformationElementType(kind),
                value: vec![1],
            };
            assert_eq!(
                InformationElement::encode_all(&[other]),
                Err(Error::InvalidType {
                    what: Part::InformationElement,
                    kind
                })
            );
        }
        for (wire, length, expected) in [
            ("85 0003 010203", 3, 4),
            ("85 0005 0102030405", 5, 4),
            ("85 000f 0102030405060708090a0b0c0d0e0f", 15, 16),
        ] {
            assert_eq!(
                InformationElement::decode_all(&hex(wire)),
                Err(Error::InvalidLength {
                    what: Part::GtpUPeerAddress,
                    length,
                    expected
                })
            );
        }
        let echo = Packet::echo_response(1);
        assert_eq!(
            echo.information_elements().unwrap(),
            vec![InformationElement::Recovery(0)]
        );
    }
}
