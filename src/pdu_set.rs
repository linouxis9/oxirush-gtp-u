//! The content of the PDU Set Information Container (TS 38.415 §6.5.2).

use std::fmt;

use crate::error::{header_length, truncated};
use crate::extension::{EncodeBuffer, U24, check};
use crate::types::Octets;
use crate::{Error, Part};

/// The content of a PDU Set Information Container (TS 38.415 §6.5.2): what
/// a UPF tells an NG-RAN node about the PDU Set of a downlink packet, such
/// as the frame of a video.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PduSetInformationContainer {
    /// DL PDU SET INFORMATION (PDU type 0).
    Downlink(DownlinkPduSetInformation),
    /// Another PDU type, kept as received: the content, from the PDU type
    /// octet to the padding. Its length is a multiple of 4 minus 2.
    Other(Vec<u8>),
}

/// DL PDU SET INFORMATION (TS 38.415 §6.5.2.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DownlinkPduSetInformation {
    /// QoS Flow Identifier, 0..=63.
    pub qfi: u8,
    /// End of Data Burst (EDB): the PDU is the last of a data burst.
    pub end_of_data_burst: bool,
    /// End PDU of the PDU Set (EPDU): the PDU is the last of its PDU Set.
    pub end_pdu: bool,
    /// PDU Set Sequence Number (PSSN), 10 bits: which PDU Set the PDU
    /// belongs to.
    pub pdu_set_sequence_number: u16,
    /// PDU Set Importance (PSI), 0..=15: 1 is the most important and 15 the
    /// least; 0 says that the sender cannot tell.
    pub pdu_set_importance: u8,
    /// PDU Sequence Number within a PDU Set (PSN), from 0 for its first
    /// PDU.
    pub pdu_sequence_number: u8,
    /// PDU Set Size (PSSize), the octets of all the PDUs of the PDU Set, 24
    /// bits (present when PSSI is set).
    pub pdu_set_size: Option<u32>,
}

impl DownlinkPduSetInformation {
    /// Information of QoS flow `qfi` (0..=63): the first PDU of PDU Set 0,
    /// of an importance that the sender cannot tell.
    pub fn new(qfi: u8) -> Self {
        Self {
            qfi,
            ..Self::default()
        }
    }

    fn decode(content: &[u8]) -> Result<Self, Error> {
        let container = Part::PduSetInformationContainer;
        let Some((&[flags, qfi, sequence, importance, pdu], rest)) = content.split_first_chunk()
        else {
            return Err(truncated(container, 5, content));
        };
        let pdu_set_size = match flags & 0x02 {
            0 => None,
            _ => match rest.first_chunk() {
                Some(&[a, b, c]) => Some(u32::from_be_bytes([0, a, b, c])),
                None => return Err(truncated(container, 3, rest)),
            },
        };
        // What follows the present fields is padding.
        Ok(Self {
            qfi: qfi >> 2,
            end_of_data_burst: flags & 0x08 != 0,
            end_pdu: flags & 0x04 != 0,
            pdu_set_sequence_number: u16::from_be_bytes([qfi & 0x03, sequence]),
            pdu_set_importance: importance & 0x0f,
            pdu_sequence_number: pdu,
            pdu_set_size,
        })
    }

    fn encode(&self, out: &mut impl EncodeBuffer) -> Result<(), Error> {
        check(Part::Qfi, Some(u32::from(self.qfi)), 63)?;
        let sequence = self.pdu_set_sequence_number;
        check(Part::PduSetSequenceNumber, Some(u32::from(sequence)), 0x3ff)?;
        let importance = self.pdu_set_importance;
        check(Part::PduSetImportance, Some(u32::from(importance)), 15)?;
        check(Part::PduSetSize, self.pdu_set_size, U24)?;
        let [high, low] = sequence.to_be_bytes();
        out.extend_from_slice(&[
            u8::from(self.end_of_data_burst) << 3
                | u8::from(self.end_pdu) << 2
                | u8::from(self.pdu_set_size.is_some()) << 1,
            self.qfi << 2 | high,
            low,
            importance,
            self.pdu_sequence_number,
        ]);
        if let Some(size) = self.pdu_set_size {
            out.extend_from_slice(&size.to_be_bytes()[1..]);
        }
        Ok(())
    }
}

impl PduSetInformationContainer {
    /// The QoS Flow Identifier of downlink information.
    pub fn qfi(&self) -> Option<u8> {
        match self {
            PduSetInformationContainer::Downlink(information) => Some(information.qfi),
            PduSetInformationContainer::Other(_) => None,
        }
    }

    pub(crate) fn decode(content: &[u8]) -> Result<Self, Error> {
        match content.first() {
            Some(first) if first >> 4 == 0 => {
                DownlinkPduSetInformation::decode(content).map(Self::Downlink)
            }
            Some(_) => Ok(Self::Other(content.to_vec())),
            None => Err(truncated(Part::PduSetInformationContainer, 5, content)),
        }
    }

    pub(crate) fn encode(&self, out: &mut impl EncodeBuffer) -> Result<(), Error> {
        match self {
            PduSetInformationContainer::Downlink(information) => information.encode(out),
            PduSetInformationContainer::Other(content) => match content.first() {
                Some(first) if (content.len() + 2).is_multiple_of(4) => {
                    if first >> 4 == 0 {
                        return Err(Error::InvalidType {
                            what: Part::PduSetInformationContainer,
                            kind: 0,
                        });
                    }
                    out.extend_from_slice(content);
                    Ok(())
                }
                _ => Err(header_length(
                    Part::PduSetInformationContainer,
                    content.len(),
                )),
            },
        }
    }
}

impl fmt::Debug for PduSetInformationContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PduSetInformationContainer::Downlink(information) => {
                f.debug_tuple("Downlink").field(information).finish()
            }
            PduSetInformationContainer::Other(content) => {
                f.debug_tuple("Other").field(&Octets(content)).finish()
            }
        }
    }
}
