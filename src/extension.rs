//! GTP-U extension headers (TS 29.281 §5.2) and the PDU Session Container
//! content (TS 38.415 §5.5.2).

use std::fmt;

use crate::error::{header_length, truncated};
use crate::types::Octets;
use crate::{Error, ExtensionHeaderType, Part, PduSetInformationContainer};

// The same serializer counts validated bytes before writing them. This avoids
// maintaining separate length and field-validation implementations.
pub(crate) trait EncodeBuffer {
    fn len(&self) -> usize;
    fn push(&mut self, byte: u8);
    fn extend_from_slice(&mut self, bytes: &[u8]);
    fn set(&mut self, index: usize, byte: u8);
}

impl EncodeBuffer for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn push(&mut self, byte: u8) {
        Vec::push(self, byte);
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
    fn set(&mut self, index: usize, byte: u8) {
        self[index] = byte;
    }
}

#[derive(Default)]
struct EncodedLength(usize);

impl EncodeBuffer for EncodedLength {
    fn len(&self) -> usize {
        self.0
    }
    fn push(&mut self, _: u8) {
        self.0 += 1;
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
    fn set(&mut self, _: usize, _: u8) {}
}

/// A GTP-U extension header (TS 29.281 §5.2).
///
/// `Debug` prints the octets of a header that is kept as received in
/// hexadecimal, after their number.
///
/// ```
/// use oxirush_gtp_u::{ExtensionHeader, ExtensionHeaderType, Packet};
///
/// // The container of an uplink G-PDU, then a header of a type that the crate keeps as octets
/// let mut packet = Packet::uplink(0x1234_5678, 9, vec![0x45]);
/// packet.extension_headers.push(ExtensionHeader::Other {
///     kind: ExtensionHeaderType(0x21),
///     content: vec![7, 0],
/// });
/// let decoded = Packet::decode(&packet.encode()?)?;
/// let kinds: Vec<_> = decoded.extension_headers.iter().map(|header| header.kind()).collect();
/// assert_eq!(kinds, [ExtensionHeaderType::PDU_SESSION_CONTAINER, ExtensionHeaderType(0x21)]);
/// assert!(!decoded.extension_headers[1].comprehension_required());
/// # Ok::<(), oxirush_gtp_u::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionHeader {
    /// UDP Port: the UDP source port of the G-PDU that triggered an Error
    /// Indication.
    UdpPort(u16),
    /// PDU Session Container: the QoS flow of a G-PDU on N3 and N9.
    PduSessionContainer(PduSessionContainer),
    /// PDCP PDU Number (TS 29.281 §5.2.2.2): the PDCP sequence number of a
    /// packet that is forwarded during a handover. It is 15 bits between
    /// eNBs and 12 between NG-RAN nodes, whose other bits are spare; all 16
    /// are kept as received.
    PdcpPduNumber(u16),
    /// Long PDCP PDU Number (§5.2.2.2A): the PDCP sequence number of a
    /// forwarded packet when it is 18 bits long.
    LongPdcpPduNumber {
        /// The PDCP PDU number, 18 bits. Spare bits that a sender set are
        /// not kept.
        number: u32,
        /// Whether the header has the type of earlier releases, 0x82,
        /// which a receiver may still get, and not 0x03.
        legacy_type: bool,
    },
    /// Service Class Indicator (§5.2.2.3) of the packet of a downlink
    /// G-PDU, for GERAN: an operator's value when below 128.
    ServiceClassIndicator(u8),
    /// RAN Container (§5.2.2.4), between eNBs: the frame of TS 36.425 as
    /// octets, padding included. Its length plus 2 is a multiple of 4.
    RanContainer(Vec<u8>),
    /// Xw RAN Container (§5.2.2.5), between an eNB and a WLAN termination:
    /// the frame of TS 36.465 as octets, as for `RanContainer`.
    XwRanContainer(Vec<u8>),
    /// NR RAN Container (§5.2.2.6), on X2-U, Xn-U and F1-U: the frame of
    /// TS 38.425 as octets, as for `RanContainer`.
    NrRanContainer(Vec<u8>),
    /// PDU Set Information Container (§5.2.2.8): the PDU Set of a downlink
    /// G-PDU on N3 and N9, and on Xn-U and F1-U.
    PduSetInformationContainer {
        /// Its content.
        information: PduSetInformationContainer,
        /// Whether the header has the type of earlier versions, 0x86,
        /// which a receiver may still get, and not 0x04.
        legacy_type: bool,
    },
    /// An extension header of a type that has no variant above, kept as
    /// received: one of a later release, or of the control plane. A later
    /// version of the crate may decode more types into variants of their
    /// own, which the encoder then refuses as `Other`.
    Other {
        /// Extension header type: not 0, and not one of
        /// [`TYPES`](Self::TYPES).
        kind: ExtensionHeaderType,
        /// The octets between the length octet and the next extension
        /// header type octet. Its length plus 2 is a multiple of 4.
        content: Vec<u8>,
    },
}

// The types with a variant, as the octets that the decoder matches.
const LONG_PDCP_PDU_NUMBER: u8 = ExtensionHeaderType::LONG_PDCP_PDU_NUMBER.0;
const PDU_SET_INFORMATION_CONTAINER: u8 = ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER.0;
const SERVICE_CLASS_INDICATOR: u8 = ExtensionHeaderType::SERVICE_CLASS_INDICATOR.0;
const UDP_PORT: u8 = ExtensionHeaderType::UDP_PORT.0;
const RAN_CONTAINER: u8 = ExtensionHeaderType::RAN_CONTAINER.0;
const LONG_PDCP_PDU_NUMBER_LEGACY: u8 = ExtensionHeaderType::LONG_PDCP_PDU_NUMBER_LEGACY.0;
const XW_RAN_CONTAINER: u8 = ExtensionHeaderType::XW_RAN_CONTAINER.0;
const NR_RAN_CONTAINER: u8 = ExtensionHeaderType::NR_RAN_CONTAINER.0;
const PDU_SESSION_CONTAINER: u8 = ExtensionHeaderType::PDU_SESSION_CONTAINER.0;
const PDU_SET_INFORMATION_CONTAINER_LEGACY: u8 =
    ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER_LEGACY.0;
const PDCP_PDU_NUMBER: u8 = ExtensionHeaderType::PDCP_PDU_NUMBER.0;

/// The largest PDCP PDU number of 18 bits.
const U18: u32 = 0x3_ffff;

impl ExtensionHeader {
    /// The types that have a variant of their own: those of TS 29.281
    /// V19.2.0, in the order of their numbers. An endpoint understands
    /// them, and [`Other`](Self::Other) cannot have them. A later version
    /// may add to them.
    pub const TYPES: &'static [ExtensionHeaderType] = &[
        ExtensionHeaderType::LONG_PDCP_PDU_NUMBER,
        ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER,
        ExtensionHeaderType::SERVICE_CLASS_INDICATOR,
        ExtensionHeaderType::UDP_PORT,
        ExtensionHeaderType::RAN_CONTAINER,
        ExtensionHeaderType::LONG_PDCP_PDU_NUMBER_LEGACY,
        ExtensionHeaderType::XW_RAN_CONTAINER,
        ExtensionHeaderType::NR_RAN_CONTAINER,
        ExtensionHeaderType::PDU_SESSION_CONTAINER,
        ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER_LEGACY,
        ExtensionHeaderType::PDCP_PDU_NUMBER,
    ];

    /// The extension header type.
    pub fn kind(&self) -> ExtensionHeaderType {
        match self {
            ExtensionHeader::UdpPort(_) => ExtensionHeaderType::UDP_PORT,
            ExtensionHeader::PduSessionContainer(_) => ExtensionHeaderType::PDU_SESSION_CONTAINER,
            ExtensionHeader::PdcpPduNumber(_) => ExtensionHeaderType::PDCP_PDU_NUMBER,
            ExtensionHeader::LongPdcpPduNumber { legacy_type, .. } => match legacy_type {
                false => ExtensionHeaderType::LONG_PDCP_PDU_NUMBER,
                true => ExtensionHeaderType::LONG_PDCP_PDU_NUMBER_LEGACY,
            },
            ExtensionHeader::ServiceClassIndicator(_) => {
                ExtensionHeaderType::SERVICE_CLASS_INDICATOR
            }
            ExtensionHeader::RanContainer(_) => ExtensionHeaderType::RAN_CONTAINER,
            ExtensionHeader::XwRanContainer(_) => ExtensionHeaderType::XW_RAN_CONTAINER,
            ExtensionHeader::NrRanContainer(_) => ExtensionHeaderType::NR_RAN_CONTAINER,
            ExtensionHeader::PduSetInformationContainer { legacy_type, .. } => match legacy_type {
                false => ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER,
                true => ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER_LEGACY,
            },
            ExtensionHeader::Other { kind, .. } => *kind,
        }
    }

    /// Whether an endpoint that does not know this type must discard the
    /// message (bit 8 of the type, TS 29.281 §5.2.1).
    pub fn comprehension_required(&self) -> bool {
        self.kind().comprehension_required()
    }

    /// The two octets of content of the usual header, which most G-PDUs on
    /// N3 have and which their encoder writes where the message is: a PDU
    /// Session Container of downlink information with a QFI and its RQI, or
    /// of uplink information with a QFI, and none of the fields that a flag
    /// announces. None for another header, and for a QFI that the encoder
    /// refuses, which the encoder of every header then refuses.
    #[inline(always)]
    pub(crate) fn usual(&self) -> Option<[u8; 2]> {
        let ExtensionHeader::PduSessionContainer(container) = self else {
            return None;
        };
        match container {
            PduSessionContainer::Downlink(DownlinkPduSessionInformation {
                qfi: qfi @ 0..=63,
                rqi,
                ppi: None,
                dl_sending_time_stamp: None,
                dl_qfi_sequence_number: None,
                dl_mbs_qfi_sequence_number: None,
                burst_size: None,
                time_to_next_burst: None,
            }) => Some([0x00, flag(*rqi, 0x40) | qfi]),
            PduSessionContainer::Uplink(UplinkPduSessionInformation {
                qfi: qfi @ 0..=63,
                time_stamps: None,
                dl_delay_result: None,
                ul_delay_result: None,
                ul_qfi_sequence_number: None,
                n3_n9_delay_result: None,
                d1_ul_pdcp_delay_result_ind: None,
                ul_congestion_information: None,
                dl_congestion_information: None,
                ul_available_bitrate: None,
                dl_available_bitrate: None,
                unknown_new_ies: None,
            }) => Some([0x10, *qfi]),
            _ => None,
        }
    }

    /// Decode the content of an extension header of type `kind`.
    #[inline(always)]
    pub(crate) fn decode(kind: u8, content: &[u8]) -> Result<Self, Error> {
        // The usual header is made where the message is: the decoder of
        // every other one is long, and is not paid for by this one.
        if kind == PDU_SESSION_CONTAINER
            && let Some(container) = PduSessionContainer::usual(content)
        {
            return Ok(ExtensionHeader::PduSessionContainer(container));
        }
        Self::decode_any(kind, content)
    }

    #[inline(never)]
    fn decode_any(kind: u8, content: &[u8]) -> Result<Self, Error> {
        match kind {
            UDP_PORT => match *content {
                [high, low] => Ok(ExtensionHeader::UdpPort(u16::from_be_bytes([high, low]))),
                _ => Err(Error::InvalidLength {
                    what: Part::UdpPort,
                    length: content.len() + 2,
                    expected: 4,
                }),
            },
            PDU_SESSION_CONTAINER => {
                PduSessionContainer::decode(content).map(ExtensionHeader::PduSessionContainer)
            }
            PDCP_PDU_NUMBER => match *content {
                [high, low] => Ok(ExtensionHeader::PdcpPduNumber(u16::from_be_bytes([
                    high, low,
                ]))),
                _ => Err(fixed_length(Part::PdcpPduNumber, content, 4)),
            },
            LONG_PDCP_PDU_NUMBER | LONG_PDCP_PDU_NUMBER_LEGACY => match *content {
                // Six bits and three octets are spare.
                [high, middle, low, _, _, _] => Ok(ExtensionHeader::LongPdcpPduNumber {
                    number: u32::from_be_bytes([0, high, middle, low]) & U18,
                    legacy_type: kind == LONG_PDCP_PDU_NUMBER_LEGACY,
                }),
                _ => Err(fixed_length(Part::LongPdcpPduNumber, content, 8)),
            },
            SERVICE_CLASS_INDICATOR => match *content {
                [indicator, _spare] => Ok(ExtensionHeader::ServiceClassIndicator(indicator)),
                _ => Err(fixed_length(Part::ServiceClassIndicator, content, 4)),
            },
            RAN_CONTAINER => Ok(ExtensionHeader::RanContainer(content.to_vec())),
            XW_RAN_CONTAINER => Ok(ExtensionHeader::XwRanContainer(content.to_vec())),
            NR_RAN_CONTAINER => Ok(ExtensionHeader::NrRanContainer(content.to_vec())),
            PDU_SET_INFORMATION_CONTAINER | PDU_SET_INFORMATION_CONTAINER_LEGACY => {
                Ok(ExtensionHeader::PduSetInformationContainer {
                    information: PduSetInformationContainer::decode(content)?,
                    legacy_type: kind == PDU_SET_INFORMATION_CONTAINER_LEGACY,
                })
            }
            _ => Ok(ExtensionHeader::Other {
                kind: ExtensionHeaderType(kind),
                content: content.to_vec(),
            }),
        }
    }

    /// Append this header, followed by `next`, the type of the next one.
    pub(crate) fn encoded_len(&self) -> Result<usize, Error> {
        let mut length = EncodedLength::default();
        self.encode(0, &mut length)?;
        Ok(length.0)
    }

    pub(crate) fn encode(&self, next: u8, out: &mut impl EncodeBuffer) -> Result<(), Error> {
        let start = out.len();
        out.push(0); // length, set below
        match self {
            ExtensionHeader::UdpPort(port) => out.extend_from_slice(&port.to_be_bytes()),
            ExtensionHeader::PduSessionContainer(container) => container.encode(out)?,
            ExtensionHeader::PdcpPduNumber(number) => {
                out.extend_from_slice(&number.to_be_bytes());
            }
            ExtensionHeader::LongPdcpPduNumber { number, .. } => {
                check(Part::LongPdcpPduNumber, Some(*number), U18)?;
                out.extend_from_slice(&number.to_be_bytes()[1..]);
                out.extend_from_slice(&[0; 3]);
            }
            ExtensionHeader::ServiceClassIndicator(indicator) => {
                out.extend_from_slice(&[*indicator, 0]);
            }
            ExtensionHeader::RanContainer(content) => octets(Part::RanContainer, content, out)?,
            ExtensionHeader::XwRanContainer(content) => {
                octets(Part::XwRanContainer, content, out)?;
            }
            ExtensionHeader::NrRanContainer(content) => {
                octets(Part::NrRanContainer, content, out)?;
            }
            ExtensionHeader::PduSetInformationContainer { information, .. } => {
                information.encode(out)?;
            }
            ExtensionHeader::Other { kind, content } => {
                if kind.0 == 0 || Self::TYPES.contains(kind) {
                    return Err(Error::InvalidType {
                        what: Part::ExtensionHeader,
                        kind: kind.0,
                    });
                }
                octets(Part::ExtensionHeader, content, out)?;
            }
        }
        // Padding of the typed contents to a multiple of 4 octets.
        while !(out.len() - start + 1).is_multiple_of(4) {
            out.push(0);
        }
        out.push(next);
        // The length octet counts units of 4 octets.
        let octets = out.len() - start;
        let length = u8::try_from(octets / 4).map_err(|_| Error::OutOfRange {
            what: Part::ExtensionHeader,
            value: octets as u64,
            max: 4 * u64::from(u8::MAX),
        })?;
        out.set(start, length);
        Ok(())
    }
}

/// The length of a header of type `what` and of `content`, which is
/// `expected` octets long on the wire, never more or less.
fn fixed_length(what: Part, content: &[u8], expected: usize) -> Error {
    Error::InvalidLength {
        what,
        length: content.len() + 2,
        expected,
    }
}

/// Append the content of a header that is kept as octets: it has its
/// padding, to the end of a unit of 4 octets.
fn octets(what: Part, content: &[u8], out: &mut impl EncodeBuffer) -> Result<(), Error> {
    if !(content.len() + 2).is_multiple_of(4) {
        return Err(header_length(what, content.len()));
    }
    out.extend_from_slice(content);
    Ok(())
}

impl fmt::Debug for ExtensionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let container = |f: &mut fmt::Formatter<'_>, name, content: &[u8]| {
            f.debug_tuple(name).field(&Octets(content)).finish()
        };
        match self {
            ExtensionHeader::UdpPort(port) => f.debug_tuple("UdpPort").field(port).finish(),
            ExtensionHeader::PduSessionContainer(container) => f
                .debug_tuple("PduSessionContainer")
                .field(container)
                .finish(),
            ExtensionHeader::PdcpPduNumber(number) => {
                f.debug_tuple("PdcpPduNumber").field(number).finish()
            }
            ExtensionHeader::LongPdcpPduNumber {
                number,
                legacy_type,
            } => f
                .debug_struct("LongPdcpPduNumber")
                .field("number", number)
                .field("legacy_type", legacy_type)
                .finish(),
            ExtensionHeader::ServiceClassIndicator(indicator) => f
                .debug_tuple("ServiceClassIndicator")
                .field(indicator)
                .finish(),
            ExtensionHeader::RanContainer(content) => container(f, "RanContainer", content),
            ExtensionHeader::XwRanContainer(content) => container(f, "XwRanContainer", content),
            ExtensionHeader::NrRanContainer(content) => container(f, "NrRanContainer", content),
            ExtensionHeader::PduSetInformationContainer {
                information,
                legacy_type,
            } => f
                .debug_struct("PduSetInformationContainer")
                .field("information", information)
                .field("legacy_type", legacy_type)
                .finish(),
            ExtensionHeader::Other { kind, content } => f
                .debug_struct("Other")
                .field("kind", kind)
                .field("content", &Octets(content))
                .finish(),
        }
    }
}

/// The content of a PDU Session Container (TS 38.415 §5.5.2).
///
/// ```
/// use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};
///
/// // Downlink information with more than a QFI: the RQI of reflective QoS
/// let mut information = DownlinkPduSessionInformation::new(9);
/// information.rqi = true;
/// let packet = Packet::g_pdu(0x2001, vec![0x45])
///     .with_pdu_session_container(PduSessionContainer::Downlink(information));
/// let decoded = Packet::decode(&packet.encode()?)?;
/// let Some(PduSessionContainer::Downlink(read)) = decoded.pdu_session_container() else {
///     unreachable!()
/// };
/// assert_eq!((read.qfi, read.rqi), (9, true));
/// # Ok::<(), oxirush_gtp_u::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PduSessionContainer {
    /// DL PDU SESSION INFORMATION (PDU type 0).
    Downlink(DownlinkPduSessionInformation),
    /// UL PDU SESSION INFORMATION (PDU type 1).
    Uplink(UplinkPduSessionInformation),
    /// Another PDU type, kept as received: the content, from the PDU type
    /// octet to the padding. Its length is a multiple of 4 minus 2.
    Other(Vec<u8>),
}

impl PduSessionContainer {
    /// DL PDU Session Information of QoS flow `qfi` (0..=63).
    pub fn downlink(qfi: u8) -> Self {
        PduSessionContainer::Downlink(DownlinkPduSessionInformation::new(qfi))
    }

    /// UL PDU Session Information of QoS flow `qfi` (0..=63).
    pub fn uplink(qfi: u8) -> Self {
        PduSessionContainer::Uplink(UplinkPduSessionInformation::new(qfi))
    }

    /// The QoS Flow Identifier of downlink or uplink information.
    pub fn qfi(&self) -> Option<u8> {
        match self {
            PduSessionContainer::Downlink(information) => Some(information.qfi),
            PduSessionContainer::Uplink(information) => Some(information.qfi),
            PduSessionContainer::Other(_) => None,
        }
    }

    /// Give downlink or uplink information QoS flow `qfi` and return the
    /// former one: `None`, and nothing changes, for another PDU type. The
    /// encoder refuses a QFI above 63.
    pub fn set_qfi(&mut self, qfi: u8) -> Option<u8> {
        match self {
            PduSessionContainer::Downlink(information) => {
                Some(std::mem::replace(&mut information.qfi, qfi))
            }
            PduSessionContainer::Uplink(information) => {
                Some(std::mem::replace(&mut information.qfi, qfi))
            }
            PduSessionContainer::Other(_) => None,
        }
    }

    /// The container of a G-PDU as it usually is: downlink information
    /// with a QFI and its RQI, or uplink information with a QFI, and none
    /// of the fields that a flag announces.
    #[inline(always)]
    fn usual(content: &[u8]) -> Option<Self> {
        let &[flags, octet, ..] = content else {
            return None;
        };
        match flags {
            // PDU type 0, whose spare bit is not evaluated.
            0x00 | 0x01 if octet & 0x80 == 0 => Some(PduSessionContainer::Downlink(
                DownlinkPduSessionInformation {
                    qfi: octet & 0x3f,
                    rqi: octet & 0x40 != 0,
                    ..DownlinkPduSessionInformation::default()
                },
            )),
            0x10 if octet & 0xc0 == 0 => Some(PduSessionContainer::uplink(octet & 0x3f)),
            _ => None,
        }
    }

    fn decode(content: &[u8]) -> Result<Self, Error> {
        let Some(first) = content.first() else {
            return Err(truncated(Part::PduSessionContainer, 2, content));
        };
        match first >> 4 {
            0 => DownlinkPduSessionInformation::decode(content).map(PduSessionContainer::Downlink),
            1 => UplinkPduSessionInformation::decode(content).map(PduSessionContainer::Uplink),
            _ => Ok(PduSessionContainer::Other(content.to_vec())),
        }
    }

    fn encode(&self, out: &mut impl EncodeBuffer) -> Result<(), Error> {
        match self {
            PduSessionContainer::Downlink(information) => information.encode(out),
            PduSessionContainer::Uplink(information) => information.encode(out),
            PduSessionContainer::Other(content) => match content.first() {
                Some(first) if (content.len() + 2).is_multiple_of(4) => {
                    if first >> 4 <= 1 {
                        return Err(Error::InvalidType {
                            what: Part::PduSessionContainer,
                            kind: first >> 4,
                        });
                    }
                    out.extend_from_slice(content);
                    Ok(())
                }
                // No content is a container of 2 octets, where the least is 4.
                _ => Err(header_length(Part::PduSessionContainer, content.len())),
            },
        }
    }
}

impl fmt::Debug for PduSessionContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PduSessionContainer::Downlink(information) => {
                f.debug_tuple("Downlink").field(information).finish()
            }
            PduSessionContainer::Uplink(information) => {
                f.debug_tuple("Uplink").field(information).finish()
            }
            PduSessionContainer::Other(content) => {
                f.debug_tuple("Other").field(&Octets(content)).finish()
            }
        }
    }
}

/// DL PDU SESSION INFORMATION (TS 38.415 §5.5.2.1). Time stamps are 64-bit
/// NTP timestamps (RFC 5905 §6).
///
/// ```
/// use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};
///
/// // QoS flow 9, with the Reflective QoS Indicator and a QFI sequence number
/// let mut information = DownlinkPduSessionInformation::new(9);
/// information.rqi = true;
/// information.dl_qfi_sequence_number = Some(1);
/// let downlink = Packet::g_pdu(0x9abc_def0, b"an IP packet".as_slice())
///     .with_pdu_session_container(PduSessionContainer::Downlink(information.clone()));
///
/// let decoded = Packet::decode(&downlink.encode()?)?;
/// let container = decoded.pdu_session_container();
/// assert_eq!(container, Some(&PduSessionContainer::Downlink(information)));
/// # Ok::<(), oxirush_gtp_u::Error>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DownlinkPduSessionInformation {
    /// QoS Flow Identifier, 0..=63.
    pub qfi: u8,
    /// Reflective QoS Indicator.
    pub rqi: bool,
    /// Paging Policy Indicator, 0..=7 (present when PPP is set).
    pub ppi: Option<u8>,
    /// DL Sending Time Stamp (present when QMP is set).
    pub dl_sending_time_stamp: Option<u64>,
    /// DL QFI Sequence Number, 24 bits (present when SNP is set).
    pub dl_qfi_sequence_number: Option<u32>,
    /// DL MBS QFI Sequence Number (present when MSNP is set).
    pub dl_mbs_qfi_sequence_number: Option<u32>,
    /// Burst Size, 24 bits (present when BSSI is set in the PPI octet).
    pub burst_size: Option<u32>,
    /// Time To Next Burst, in tenths of a millisecond (present when TTNBI
    /// is set in the PPI octet).
    pub time_to_next_burst: Option<u16>,
}

impl DownlinkPduSessionInformation {
    /// Information of QoS flow `qfi` (0..=63), without optional fields.
    pub fn new(qfi: u8) -> Self {
        Self {
            qfi,
            ..Self::default()
        }
    }

    fn decode(content: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader(content);
        let flags = reader.u8()?;
        let octet = reader.u8()?;
        let ppi_octet = if octet & 0x80 != 0 {
            Some(reader.u8()?)
        } else {
            None
        };
        let dl_sending_time_stamp = reader.u64_if(flags & 0x08 != 0)?;
        let dl_qfi_sequence_number = reader.u24_if(flags & 0x04 != 0)?;
        let dl_mbs_qfi_sequence_number = reader.u32_if(flags & 0x02 != 0)?;
        let burst_size = reader.u24_if(ppi_octet.is_some_and(|ppi| ppi & 0x02 != 0))?;
        let time_to_next_burst = reader.u16_if(ppi_octet.is_some_and(|ppi| ppi & 0x01 != 0))?;
        // What follows the present fields is padding.
        Ok(Self {
            qfi: octet & 0x3f,
            rqi: octet & 0x40 != 0,
            ppi: ppi_octet.map(|ppi| ppi >> 5),
            dl_sending_time_stamp,
            dl_qfi_sequence_number,
            dl_mbs_qfi_sequence_number,
            burst_size,
            time_to_next_burst,
        })
    }

    fn encode(&self, out: &mut impl EncodeBuffer) -> Result<(), Error> {
        check_qfi(self.qfi)?;
        check(Part::Ppi, self.ppi.map(u32::from), 7)?;
        check(Part::DlQfiSequenceNumber, self.dl_qfi_sequence_number, U24)?;
        check(Part::BurstSize, self.burst_size, U24)?;
        if self.ppi.is_none() && (self.burst_size.is_some() || self.time_to_next_burst.is_some()) {
            return Err(Error::Missing(Part::Ppi));
        }
        out.push(
            flag(self.dl_sending_time_stamp.is_some(), 0x08)
                | flag(self.dl_qfi_sequence_number.is_some(), 0x04)
                | flag(self.dl_mbs_qfi_sequence_number.is_some(), 0x02),
        );
        out.push(flag(self.ppi.is_some(), 0x80) | flag(self.rqi, 0x40) | self.qfi);
        if let Some(ppi) = self.ppi {
            out.push(
                ppi << 5
                    | flag(self.burst_size.is_some(), 0x02)
                    | flag(self.time_to_next_burst.is_some(), 0x01),
            );
        }
        if let Some(time_stamp) = self.dl_sending_time_stamp {
            out.extend_from_slice(&time_stamp.to_be_bytes());
        }
        if let Some(sequence) = self.dl_qfi_sequence_number {
            out.extend_from_slice(&sequence.to_be_bytes()[1..]);
        }
        if let Some(sequence) = self.dl_mbs_qfi_sequence_number {
            out.extend_from_slice(&sequence.to_be_bytes());
        }
        if let Some(size) = self.burst_size {
            out.extend_from_slice(&size.to_be_bytes()[1..]);
        }
        if let Some(time) = self.time_to_next_burst {
            out.extend_from_slice(&time.to_be_bytes());
        }
        Ok(())
    }
}

/// UL PDU SESSION INFORMATION (TS 38.415 §5.5.2.2). Time stamps are 64-bit
/// NTP timestamps (RFC 5905 §6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UplinkPduSessionInformation {
    /// QoS Flow Identifier, 0..=63.
    pub qfi: u8,
    /// QoS monitoring time stamps (present when QMP is set).
    pub time_stamps: Option<UplinkTimeStamps>,
    /// DL Delay Result (present when DL Delay Ind is set).
    pub dl_delay_result: Option<u32>,
    /// UL Delay Result (present when UL Delay Ind is set).
    pub ul_delay_result: Option<u32>,
    /// UL QFI Sequence Number, 24 bits (present when SNP is set).
    pub ul_qfi_sequence_number: Option<u32>,
    /// N3/N9 Delay Result (present when N3/N9 Delay Ind is set).
    pub n3_n9_delay_result: Option<u32>,
    /// D1 UL PDCP Delay Result Ind: whether the UL Delay Result includes
    /// the D1 measurement, UL PDCP Packet Average Delay (New IE Flag 0).
    pub d1_ul_pdcp_delay_result_ind: Option<bool>,
    /// UL Congestion Information, a percentage in hundredths, 0..=10000
    /// (New IE Flag 1). Larger values are sent and received unchecked, so
    /// that whatever decodes encodes again.
    pub ul_congestion_information: Option<u16>,
    /// DL Congestion Information, a percentage in hundredths, 0..=10000
    /// (New IE Flag 2), unchecked like the UL one.
    pub dl_congestion_information: Option<u16>,
    /// UL Available Bitrate of the QoS flow in kbit/s, 0..=4 000 000 000
    /// (New IE Flag 3, TS 38.415 V19), unchecked like the congestion
    /// information.
    pub ul_available_bitrate: Option<u32>,
    /// DL Available Bitrate of the QoS flow in kbit/s (New IE Flag 4), as
    /// the UL one.
    pub dl_available_bitrate: Option<u32>,
    /// New IEs of later releases than TS 38.415 V19.1.0, as received
    /// (present when the New IE Flags announce any). They are out of the
    /// information, which without them is shorter to move.
    pub unknown_new_ies: Option<Box<UnknownNewIes>>,
}

/// New IEs of UL PDU Session Information that this crate does not decode:
/// those announced by New IE Flags 5 and 6 and by extension octets of the
/// New IE Flags (TS 38.415 Annex A).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UnknownNewIes {
    /// The New IE Flags octets, extension octets included, with New IE
    /// Flags 0 to 4 clear. The first octet is not 0, and bit 7 (E) of an
    /// octet is set exactly when another octet follows.
    pub flags: Vec<u8>,
    /// The octets after the IEs this crate decodes, padding included: the
    /// length of the whole container content is a multiple of 4 minus 2.
    pub content: Vec<u8>,
}

impl fmt::Debug for UnknownNewIes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownNewIes")
            .field("flags", &Octets(&self.flags))
            .field("content", &Octets(&self.content))
            .finish()
    }
}

/// The QoS monitoring time stamps of UL PDU Session Information.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UplinkTimeStamps {
    /// DL Sending Time Stamp Repeated.
    pub dl_sending_repeated: u64,
    /// DL Received Time Stamp.
    pub dl_received: u64,
    /// UL Sending Time Stamp.
    pub ul_sending: u64,
}

/// The New IE Flags 0 to 4, whose IEs have a field.
const KNOWN_NEW_IES: u8 = 0x1f;

impl UplinkPduSessionInformation {
    /// Information of QoS flow `qfi` (0..=63), without optional fields.
    pub fn new(qfi: u8) -> Self {
        Self {
            qfi,
            ..Self::default()
        }
    }

    fn decode(content: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader(content);
        let flags = reader.u8()?;
        let octet = reader.u8()?;
        let time_stamps = if flags & 0x08 != 0 {
            Some(UplinkTimeStamps {
                dl_sending_repeated: reader.u64()?,
                dl_received: reader.u64()?,
                ul_sending: reader.u64()?,
            })
        } else {
            None
        };
        let dl_delay_result = reader.u32_if(flags & 0x04 != 0)?;
        let ul_delay_result = reader.u32_if(flags & 0x02 != 0)?;
        let ul_qfi_sequence_number = reader.u24_if(flags & 0x01 != 0)?;
        let n3_n9_delay_result = reader.u32_if(octet & 0x80 != 0)?;
        let (mut d1_ul_pdcp_delay_result_ind, mut unknown_new_ies) = (None, None);
        let (mut ul_congestion_information, mut dl_congestion_information) = (None, None);
        let (mut ul_available_bitrate, mut dl_available_bitrate) = (None, None);
        if octet & 0x40 != 0 {
            let first = reader.u8()?;
            // The extension octets of the New IE Flags, before the IEs.
            let after_first = reader.0;
            let mut last = first;
            while last & 0x80 != 0 {
                last = reader.u8()?;
            }
            let extension = &after_first[..after_first.len() - reader.0.len()];
            if first & 0x01 != 0 {
                d1_ul_pdcp_delay_result_ind = Some(reader.u8()? & 0x01 != 0);
            }
            ul_congestion_information = reader.u16_if(first & 0x02 != 0)?;
            dl_congestion_information = reader.u16_if(first & 0x04 != 0)?;
            ul_available_bitrate = reader.u32_if(first & 0x08 != 0)?;
            dl_available_bitrate = reader.u32_if(first & 0x10 != 0)?;
            // Only flags of a later release are kept as octets: the flags
            // of the five IEs above allocate nothing.
            let unknown = first & !KNOWN_NEW_IES;
            if unknown != 0 {
                let mut flags = Vec::with_capacity(1 + extension.len());
                flags.push(unknown);
                flags.extend_from_slice(extension);
                unknown_new_ies = Some(Box::new(UnknownNewIes {
                    flags,
                    content: reader.0.to_vec(),
                }));
            }
        }
        // Otherwise what follows the present fields is padding.
        Ok(Self {
            qfi: octet & 0x3f,
            time_stamps,
            dl_delay_result,
            ul_delay_result,
            ul_qfi_sequence_number,
            n3_n9_delay_result,
            d1_ul_pdcp_delay_result_ind,
            ul_congestion_information,
            dl_congestion_information,
            ul_available_bitrate,
            dl_available_bitrate,
            unknown_new_ies,
        })
    }

    fn encode(&self, out: &mut impl EncodeBuffer) -> Result<(), Error> {
        let start = out.len();
        check_qfi(self.qfi)?;
        check(Part::UlQfiSequenceNumber, self.ul_qfi_sequence_number, U24)?;
        let known_new_ies = flag(self.d1_ul_pdcp_delay_result_ind.is_some(), 0x01)
            | flag(self.ul_congestion_information.is_some(), 0x02)
            | flag(self.dl_congestion_information.is_some(), 0x04)
            | flag(self.ul_available_bitrate.is_some(), 0x08)
            | flag(self.dl_available_bitrate.is_some(), 0x10);
        if let Some(unknown) = &self.unknown_new_ies {
            let flags = &unknown.flags;
            let chained = flags
                .iter()
                .enumerate()
                .all(|(index, flags_octet)| (flags_octet & 0x80 != 0) == (index + 1 < flags.len()));
            if flags
                .first()
                .is_none_or(|first| *first == 0 || first & KNOWN_NEW_IES != 0)
                || !chained
            {
                return Err(Error::Malformed(Part::NewIeFlags));
            }
        }
        let new_ie_flag = known_new_ies != 0 || self.unknown_new_ies.is_some();
        out.push(
            0x10 | flag(self.time_stamps.is_some(), 0x08)
                | flag(self.dl_delay_result.is_some(), 0x04)
                | flag(self.ul_delay_result.is_some(), 0x02)
                | flag(self.ul_qfi_sequence_number.is_some(), 0x01),
        );
        out.push(
            flag(self.n3_n9_delay_result.is_some(), 0x80) | flag(new_ie_flag, 0x40) | self.qfi,
        );
        if let Some(time_stamps) = &self.time_stamps {
            out.extend_from_slice(&time_stamps.dl_sending_repeated.to_be_bytes());
            out.extend_from_slice(&time_stamps.dl_received.to_be_bytes());
            out.extend_from_slice(&time_stamps.ul_sending.to_be_bytes());
        }
        for delay in [self.dl_delay_result, self.ul_delay_result]
            .into_iter()
            .flatten()
        {
            out.extend_from_slice(&delay.to_be_bytes());
        }
        if let Some(sequence) = self.ul_qfi_sequence_number {
            out.extend_from_slice(&sequence.to_be_bytes()[1..]);
        }
        if let Some(delay) = self.n3_n9_delay_result {
            out.extend_from_slice(&delay.to_be_bytes());
        }
        if new_ie_flag {
            match &self.unknown_new_ies {
                Some(unknown) => {
                    out.push(unknown.flags[0] | known_new_ies);
                    out.extend_from_slice(&unknown.flags[1..]);
                }
                None => out.push(known_new_ies),
            }
            if let Some(included) = self.d1_ul_pdcp_delay_result_ind {
                out.push(u8::from(included));
            }
            for congestion in [
                self.ul_congestion_information,
                self.dl_congestion_information,
            ]
            .into_iter()
            .flatten()
            {
                out.extend_from_slice(&congestion.to_be_bytes());
            }
            for bitrate in [self.ul_available_bitrate, self.dl_available_bitrate]
                .into_iter()
                .flatten()
            {
                out.extend_from_slice(&bitrate.to_be_bytes());
            }
            if let Some(unknown) = &self.unknown_new_ies {
                out.extend_from_slice(&unknown.content);
                // Padding added to it would decode as part of it.
                if !(out.len() - start + 2).is_multiple_of(4) {
                    return Err(header_length(Part::PduSessionContainer, out.len() - start));
                }
            }
        }
        Ok(())
    }
}

fn flag(set: bool, bit: u8) -> u8 {
    if set { bit } else { 0 }
}

/// The largest value of a field of 24 bits.
pub(crate) const U24: u32 = 0xff_ffff;

pub(crate) fn check_qfi(qfi: u8) -> Result<(), Error> {
    check(Part::Qfi, Some(u32::from(qfi)), 63)
}

/// Whether `value`, if the field is present, is one that its bits carry.
pub(crate) fn check(what: Part, value: Option<u32>, max: u32) -> Result<(), Error> {
    match value {
        Some(value) if value > max => Err(Error::OutOfRange {
            what,
            value: u64::from(value),
            max: u64::from(max),
        }),
        _ => Ok(()),
    }
}

/// Big-endian fields of a PDU Session Container.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (field, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or_else(|| truncated(Part::PduSessionContainer, N, self.0))?;
        self.0 = rest;
        Ok(*field)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take::<1>()?[0])
    }

    fn u64(&mut self) -> Result<u64, Error> {
        self.take().map(u64::from_be_bytes)
    }

    fn u16_if(&mut self, present: bool) -> Result<Option<u16>, Error> {
        if !present {
            return Ok(None);
        }
        self.take().map(|field| Some(u16::from_be_bytes(field)))
    }

    fn u24_if(&mut self, present: bool) -> Result<Option<u32>, Error> {
        if !present {
            return Ok(None);
        }
        let [a, b, c] = self.take()?;
        Ok(Some(u32::from_be_bytes([0, a, b, c])))
    }

    fn u32_if(&mut self, present: bool) -> Result<Option<u32>, Error> {
        if !present {
            return Ok(None);
        }
        self.take().map(|field| Some(u32::from_be_bytes(field)))
    }

    fn u64_if(&mut self, present: bool) -> Result<Option<u64>, Error> {
        if !present {
            return Ok(None);
        }
        self.u64().map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoder of the usual container writes what the encoder of every
    /// header writes, and leaves to it what it is not for.
    #[test]
    fn the_usual_container_is_encoded_as_every_header_is() {
        let general = |header: &ExtensionHeader| {
            let mut out = Vec::new();
            header.encode(0x40, &mut out).map(|()| out)
        };
        for qfi in 0..=64 {
            let uplink = PduSessionContainer::uplink(qfi);
            let mut headers = vec![ExtensionHeader::PduSessionContainer(uplink)];
            for rqi in [false, true] {
                let mut information = DownlinkPduSessionInformation::new(qfi);
                information.rqi = rqi;
                let downlink = PduSessionContainer::Downlink(information);
                headers.push(ExtensionHeader::PduSessionContainer(downlink));
            }
            for header in headers {
                match (header.usual(), general(&header)) {
                    (Some([first, second]), Ok(out)) => assert_eq!(out, [1, first, second, 0x40]),
                    (None, Err(_)) => assert_eq!(qfi, 64),
                    (usual, general) => panic!("{header:?}: {usual:?} and {general:?}"),
                }
            }
        }
        let mut downlink = DownlinkPduSessionInformation::new(9);
        downlink.ppi = Some(1);
        let mut uplink = UplinkPduSessionInformation::new(9);
        uplink.ul_qfi_sequence_number = Some(1);
        for other in [
            ExtensionHeader::PduSessionContainer(PduSessionContainer::Downlink(downlink)),
            ExtensionHeader::PduSessionContainer(PduSessionContainer::Uplink(uplink)),
            ExtensionHeader::PduSessionContainer(PduSessionContainer::Other(vec![0x20, 0])),
            ExtensionHeader::UdpPort(2152),
        ] {
            assert_eq!(other.usual(), None, "{other:?}");
        }
    }
}
