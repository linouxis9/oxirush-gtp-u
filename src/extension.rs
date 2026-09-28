//! GTP-U extension headers (TS 29.281 §5.2) and the PDU Session Container
//! content (TS 38.415 §5.5.2).

use crate::Error;

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
                _ => Err(Error::InvalidLength("UDP Port extension header")),
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
    pub(crate) fn encode(&self, next: u8, out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        out.push(0); // length, set below
        match self {
            ExtensionHeader::UdpPort(port) => out.extend_from_slice(&port.to_be_bytes()),
            ExtensionHeader::PduSessionContainer(container) => container.encode(out)?,
            ExtensionHeader::Other { kind, content } => {
                if matches!(*kind, 0 | Self::UDP_PORT | Self::PDU_SESSION_CONTAINER) {
                    return Err(Error::OutOfRange("extension header type"));
                }
                if (content.len() + 2) % 4 != 0 {
                    return Err(Error::InvalidLength("extension header"));
                }
                out.extend_from_slice(content);
            }
        }
        // Padding of the typed contents to a multiple of 4 octets.
        while (out.len() - start + 1) % 4 != 0 {
            out.push(0);
        }
        out.push(next);
        out[start] = u8::try_from((out.len() - start) / 4)
            .map_err(|_| Error::OutOfRange("extension header length"))?;
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
            return Err(Error::Truncated("PDU Session Container"));
        };
        match first >> 4 {
            0 => DownlinkPduSessionInformation::decode(content).map(PduSessionContainer::Downlink),
            1 => UplinkPduSessionInformation::decode(content).map(PduSessionContainer::Uplink),
            _ => Ok(PduSessionContainer::Other(content.to_vec())),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            PduSessionContainer::Downlink(information) => information.encode(out),
            PduSessionContainer::Uplink(information) => information.encode(out),
            PduSessionContainer::Other(content) => match content.first() {
                Some(_) if (content.len() + 2) % 4 != 0 => {
                    Err(Error::InvalidLength("PDU Session Container"))
                }
                Some(first) if first >> 4 > 1 => {
                    out.extend_from_slice(content);
                    Ok(())
                }
                Some(_) => Err(Error::OutOfRange("PDU Session Container PDU type")),
                None => Err(Error::InvalidLength("PDU Session Container")),
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
        let ppi = if octet & 0x80 != 0 {
            Some(reader.u8()? >> 5)
        } else {
            None
        };
        let dl_sending_time_stamp = reader.u64_if(flags & 0x08 != 0)?;
        let dl_qfi_sequence_number = reader.u24_if(flags & 0x04 != 0)?;
        let dl_mbs_qfi_sequence_number = reader.u32_if(flags & 0x02 != 0)?;
        // What follows the present fields is padding.
        Ok(Self {
            qfi: octet & 0x3f,
            rqi: octet & 0x40 != 0,
            ppi,
            dl_sending_time_stamp,
            dl_qfi_sequence_number,
            dl_mbs_qfi_sequence_number,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        check_qfi(self.qfi)?;
        if self.ppi.is_some_and(|ppi| ppi > 7) {
            return Err(Error::OutOfRange("PPI"));
        }
        check_u24(self.dl_qfi_sequence_number, "DL QFI Sequence Number")?;
        out.push(
            flag(self.dl_sending_time_stamp.is_some(), 0x08)
                | flag(self.dl_qfi_sequence_number.is_some(), 0x04)
                | flag(self.dl_mbs_qfi_sequence_number.is_some(), 0x02),
        );
        out.push(flag(self.ppi.is_some(), 0x80) | flag(self.rqi, 0x40) | self.qfi);
        if let Some(ppi) = self.ppi {
            out.push(ppi << 5);
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
    /// when the New IE Flags announce any).
    pub unknown_new_ies: Option<UnknownNewIes>,
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
        let mut information = Self {
            qfi: octet & 0x3f,
            time_stamps,
            dl_delay_result,
            ul_delay_result,
            ul_qfi_sequence_number,
            n3_n9_delay_result,
            ..Self::default()
        };
        if octet & 0x40 != 0 {
            let mut flags = vec![reader.u8()?];
            while flags.last().is_some_and(|flags| flags & 0x80 != 0) {
                flags.push(reader.u8()?);
            }
            if flags[0] & 0x01 != 0 {
                information.d1_ul_pdcp_delay_result_ind = Some(reader.u8()? & 0x01 != 0);
            }
            information.ul_congestion_information = reader.u16_if(flags[0] & 0x02 != 0)?;
            information.dl_congestion_information = reader.u16_if(flags[0] & 0x04 != 0)?;
            flags[0] &= !0x07;
            if flags[0] != 0 {
                information.unknown_new_ies = Some(UnknownNewIes {
                    flags,
                    content: reader.0.to_vec(),
                });
            }
        }
        // Otherwise what follows the present fields is padding.
        Ok(information)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        check_qfi(self.qfi)?;
        check_u24(self.ul_qfi_sequence_number, "UL QFI Sequence Number")?;
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
                return Err(Error::OutOfRange("New IE Flags"));
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
                if (out.len() - start + 2) % 4 != 0 {
                    return Err(Error::InvalidLength("PDU Session Container"));
                }
            }
        }
        Ok(())
    }
}

fn flag(set: bool, bit: u8) -> u8 {
    if set { bit } else { 0 }
}

fn check_qfi(qfi: u8) -> Result<(), Error> {
    if qfi > 63 {
        return Err(Error::OutOfRange("QFI"));
    }
    Ok(())
}

fn check_u24(value: Option<u32>, what: &'static str) -> Result<(), Error> {
    if value.is_some_and(|value| value > 0xff_ffff) {
        return Err(Error::OutOfRange(what));
    }
    Ok(())
}

/// Big-endian fields of a PDU Session Container.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (field, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(Error::Truncated("PDU Session Container"))?;
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
