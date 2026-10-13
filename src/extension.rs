//! GTP-U extension headers (TS 29.281 §5.2) and the PDU Session Container
//! content (TS 38.415 §5.5.2).

use crate::error::{header_length, truncated};
use crate::{Error, Part};

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
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionHeader {
    /// UDP Port: the UDP source port of the G-PDU that triggered an Error
    /// Indication.
    UdpPort(u16),
    /// PDU Session Container: the QoS flow of a G-PDU on N3 and N9.
    PduSessionContainer(PduSessionContainer),
    /// Any other extension header, kept as received. A later version may
    /// decode more types into variants of their own, which the encoder then
    /// refuses as `Other`.
    Other {
        /// Extension header type: not 0, and not a type with a variant
        /// above.
        kind: u8,
        /// The octets between the length octet and the next extension
        /// header type octet. Its length plus 2 is a multiple of 4.
        content: Vec<u8>,
    },
}

impl ExtensionHeader {
    /// Service Class Indicator.
    pub const SERVICE_CLASS_INDICATOR: u8 = 0x20;
    /// UDP Port.
    pub const UDP_PORT: u8 = 0x40;
    /// RAN Container.
    pub const RAN_CONTAINER: u8 = 0x81;
    /// Long PDCP PDU Number, the value current senders use.
    pub const LONG_PDCP_PDU_NUMBER: u8 = 0x03;
    /// Long PDCP PDU Number as sent by earlier releases.
    pub const LONG_PDCP_PDU_NUMBER_LEGACY: u8 = 0x82;
    /// Xw RAN Container.
    pub const XW_RAN_CONTAINER: u8 = 0x83;
    /// NR RAN Container.
    pub const NR_RAN_CONTAINER: u8 = 0x84;
    /// PDU Session Container.
    pub const PDU_SESSION_CONTAINER: u8 = 0x85;
    /// PDCP PDU Number.
    pub const PDCP_PDU_NUMBER: u8 = 0xc0;

    /// The extension header type.
    pub fn kind(&self) -> u8 {
        match self {
            ExtensionHeader::UdpPort(_) => Self::UDP_PORT,
            ExtensionHeader::PduSessionContainer(_) => Self::PDU_SESSION_CONTAINER,
            ExtensionHeader::Other { kind, .. } => *kind,
        }
    }

    /// Whether an endpoint that does not know this type must discard the
    /// message (bit 8 of the type, TS 29.281 §5.2.1).
    pub fn comprehension_required(&self) -> bool {
        self.kind() & 0x80 != 0
    }

    /// Decode the content of an extension header of type `kind`.
    pub(crate) fn decode(kind: u8, content: &[u8]) -> Result<Self, Error> {
        match kind {
            Self::UDP_PORT => match *content {
                [high, low] => Ok(ExtensionHeader::UdpPort(u16::from_be_bytes([high, low]))),
                _ => Err(Error::InvalidLength {
                    what: Part::UdpPort,
                    length: content.len() + 2,
                    expected: 4,
                }),
            },
            Self::PDU_SESSION_CONTAINER => {
                PduSessionContainer::decode(content).map(ExtensionHeader::PduSessionContainer)
            }
            _ => Ok(ExtensionHeader::Other {
                kind,
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
            ExtensionHeader::Other { kind, content } => {
                if matches!(*kind, 0 | Self::UDP_PORT | Self::PDU_SESSION_CONTAINER) {
                    return Err(Error::InvalidType {
                        what: Part::ExtensionHeader,
                        kind: *kind,
                    });
                }
                if (content.len() + 2) % 4 != 0 {
                    return Err(header_length(Part::ExtensionHeader, content.len()));
                }
                out.extend_from_slice(content);
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

/// The content of a PDU Session Container (TS 38.415 §5.5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// DL PDU SESSION INFORMATION (TS 38.415 §5.5.2.1). Time stamps are 64-bit
/// NTP timestamps (RFC 5905 §6).
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
        // The usual information is a QFI and its RQI: none of the fields
        // that the flags below announce.
        if flags & 0x0e == 0 && octet & 0x80 == 0 {
            return Ok(Self {
                qfi: octet & 0x3f,
                rqi: octet & 0x40 != 0,
                ..Self::default()
            });
        }
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
    /// New IEs of later releases than TS 38.415 V18, as received (present
    /// when the New IE Flags announce any). They are out of the
    /// information, which without them is short enough to be moved in
    /// place.
    pub unknown_new_ies: Option<Box<UnknownNewIes>>,
}

/// New IEs of UL PDU Session Information that this crate does not decode:
/// those announced by New IE Flags 3 to 6 and by extension octets of the
/// New IE Flags (TS 38.415 Annex A).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnknownNewIes {
    /// The New IE Flags octets, extension octets included, with New IE
    /// Flags 0 to 2 clear. The first octet is not 0, and bit 7 (E) of an
    /// octet is set exactly when another octet follows.
    pub flags: Vec<u8>,
    /// The octets after the IEs this crate decodes, padding included: the
    /// length of the whole container content is a multiple of 4 minus 2.
    pub content: Vec<u8>,
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
        // The usual information is a QFI: none of the fields that the
        // flags below announce.
        if flags & 0x0f == 0 && octet & 0xc0 == 0 {
            return Ok(Self::new(octet & 0x3f));
        }
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
            // Only flags of a later release are kept as octets: the flags
            // of the three IEs above allocate nothing.
            let unknown = first & !0x07;
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
            unknown_new_ies,
        })
    }

    fn encode(&self, out: &mut impl EncodeBuffer) -> Result<(), Error> {
        let start = out.len();
        check_qfi(self.qfi)?;
        check(Part::UlQfiSequenceNumber, self.ul_qfi_sequence_number, U24)?;
        let known_new_ies = flag(self.d1_ul_pdcp_delay_result_ind.is_some(), 0x01)
            | flag(self.ul_congestion_information.is_some(), 0x02)
            | flag(self.dl_congestion_information.is_some(), 0x04);
        if let Some(unknown) = &self.unknown_new_ies {
            let flags = &unknown.flags;
            let chained = flags
                .iter()
                .enumerate()
                .all(|(index, flags_octet)| (flags_octet & 0x80 != 0) == (index + 1 < flags.len()));
            if flags
                .first()
                .is_none_or(|first| *first == 0 || first & 0x07 != 0)
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
        if let Some(time_stamps) = self.time_stamps {
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
const U24: u32 = 0xff_ffff;

fn check_qfi(qfi: u8) -> Result<(), Error> {
    check(Part::Qfi, Some(u32::from(qfi)), 63)
}

/// Whether `value`, if the field is present, is one that its bits carry.
fn check(what: Part, value: Option<u32>, max: u32) -> Result<(), Error> {
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
