//! GTP-U information elements (TS 29.281 §8), the content of signalling
//! messages.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Error;

/// A GTP-U information element (TS 29.281 §8).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InformationElement {
    /// Recovery: a restart counter, which GTP-U sends as 0 and ignores.
    Recovery(u8),
    /// TEID Data I: the TEID of the G-PDU that triggered an Error
    /// Indication.
    TeidDataI(u32),
    /// GTP-U Peer Address: the destination address of the G-PDU that
    /// triggered an Error Indication.
    GtpUPeerAddress(IpAddr),
    /// Extension Header Type List: the extension header types a node
    /// supports, at most 255.
    ExtensionHeaderTypeList(Vec<u8>),
    /// Private Extension: vendor or operator specific information.
    PrivateExtension {
        /// Extension Identifier, a private enterprise number.
        identifier: u16,
        /// Extension Value.
        value: Vec<u8>,
    },
    /// Any other TLV information element, kept as received: a type of 128
    /// or more, and not one with a variant above (133, 141 or 255). A later
    /// version may decode more types into variants of their own, which the
    /// encoder then refuses as `Other`.
    Other {
        /// Type.
        kind: u8,
        /// Value.
        value: Vec<u8>,
    },
}

impl InformationElement {
    /// Recovery, a TV element.
    pub const RECOVERY: u8 = 14;
    /// TEID Data I, a TV element.
    pub const TEID_DATA_I: u8 = 16;
    /// GTP-U Peer Address.
    pub const GTP_U_PEER_ADDRESS: u8 = 133;
    /// Extension Header Type List, a TLV element with a one-octet length.
    pub const EXTENSION_HEADER_TYPE_LIST: u8 = 141;
    /// GTP-U Tunnel Status Information, kept as [`Other`](Self::Other).
    pub const GTP_U_TUNNEL_STATUS_INFORMATION: u8 = 230;
    /// Recovery Time Stamp, kept as [`Other`](Self::Other): the start time
    /// of the sender, in the first four octets of an NTP timestamp.
    pub const RECOVERY_TIME_STAMP: u8 = 231;
    /// Private Extension.
    pub const PRIVATE_EXTENSION: u8 = 255;

    /// The information element type.
    pub fn kind(&self) -> u8 {
        match self {
            InformationElement::Recovery(_) => Self::RECOVERY,
            InformationElement::TeidDataI(_) => Self::TEID_DATA_I,
            InformationElement::GtpUPeerAddress(_) => Self::GTP_U_PEER_ADDRESS,
            InformationElement::ExtensionHeaderTypeList(_) => Self::EXTENSION_HEADER_TYPE_LIST,
            InformationElement::PrivateExtension { .. } => Self::PRIVATE_EXTENSION,
            InformationElement::Other { kind, .. } => *kind,
        }
    }

    /// Decode a sequence of information elements, such as the payload of
    /// a signalling message.
    pub fn decode_all(mut bytes: &[u8]) -> Result<Vec<Self>, Error> {
        let mut elements = Vec::new();
        while let Some((&kind, rest)) = bytes.split_first() {
            let (element, rest) = match kind {
                Self::RECOVERY => {
                    let (&counter, rest) =
                        rest.split_first().ok_or(Error::Truncated("Recovery"))?;
                    (InformationElement::Recovery(counter), rest)
                }
                Self::TEID_DATA_I => {
                    let (teid, rest) = rest
                        .split_first_chunk::<4>()
                        .ok_or(Error::Truncated("TEID Data I"))?;
                    (
                        InformationElement::TeidDataI(u32::from_be_bytes(*teid)),
                        rest,
                    )
                }
                Self::EXTENSION_HEADER_TYPE_LIST => {
                    let (&length, rest) = rest
                        .split_first()
                        .ok_or(Error::Truncated("Extension Header Type List"))?;
                    let (types, rest) = rest
                        .split_at_checked(usize::from(length))
                        .ok_or(Error::Truncated("Extension Header Type List"))?;
                    (
                        InformationElement::ExtensionHeaderTypeList(types.to_vec()),
                        rest,
                    )
                }
                128.. => {
                    let (length, rest) = rest
                        .split_first_chunk::<2>()
                        .ok_or(Error::Truncated("information element"))?;
                    let (value, rest) = rest
                        .split_at_checked(usize::from(u16::from_be_bytes(*length)))
                        .ok_or(Error::Truncated("information element"))?;
                    (Self::decode_tlv(kind, value)?, rest)
                }
                _ => return Err(Error::UnknownInformationElement(kind)),
            };
            elements.push(element);
            bytes = rest;
        }
        Ok(elements)
    }

    fn decode_tlv(kind: u8, value: &[u8]) -> Result<Self, Error> {
        Ok(match kind {
            Self::GTP_U_PEER_ADDRESS => InformationElement::GtpUPeerAddress(
                if let Ok(octets) = <[u8; 4]>::try_from(value) {
                    Ipv4Addr::from(octets).into()
                } else if let Ok(octets) = <[u8; 16]>::try_from(value) {
                    Ipv6Addr::from(octets).into()
                } else {
                    return Err(Error::InvalidLength("GTP-U Peer Address"));
                },
            ),
            Self::PRIVATE_EXTENSION => {
                let (identifier, value) = value
                    .split_first_chunk::<2>()
                    .ok_or(Error::InvalidLength("Private Extension"))?;
                InformationElement::PrivateExtension {
                    identifier: u16::from_be_bytes(*identifier),
                    value: value.to_vec(),
                }
            }
            _ => InformationElement::Other {
                kind,
                value: value.to_vec(),
            },
        })
    }

    /// Encode a sequence of information elements, in the given order.
    /// TS 29.281 §8.1 sends them in ascending order of type.
    pub fn encode_all(elements: &[Self]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for element in elements {
            element.encode(&mut out)?;
        }
        Ok(out)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.push(self.kind());
        match self {
            InformationElement::Recovery(counter) => out.push(*counter),
            InformationElement::TeidDataI(teid) => out.extend_from_slice(&teid.to_be_bytes()),
            InformationElement::ExtensionHeaderTypeList(types) => {
                let length = u8::try_from(types.len())
                    .map_err(|_| Error::OutOfRange("Extension Header Type List length"))?;
                out.push(length);
                out.extend_from_slice(types);
            }
            InformationElement::GtpUPeerAddress(IpAddr::V4(address)) => {
                push_tlv(out, &[&address.octets()])?;
            }
            InformationElement::GtpUPeerAddress(IpAddr::V6(address)) => {
                push_tlv(out, &[&address.octets()])?;
            }
            InformationElement::PrivateExtension { identifier, value } => {
                push_tlv(out, &[&identifier.to_be_bytes(), value])?;
            }
            InformationElement::Other { kind, value } => {
                if *kind < 128
                    || matches!(
                        *kind,
                        Self::GTP_U_PEER_ADDRESS
                            | Self::EXTENSION_HEADER_TYPE_LIST
                            | Self::PRIVATE_EXTENSION
                    )
                {
                    return Err(Error::OutOfRange("TLV information element type"));
                }
                push_tlv(out, &[value])?;
            }
        }
        Ok(())
    }
}

/// Append the two-octet length and the value made of `parts`.
fn push_tlv(out: &mut Vec<u8>, parts: &[&[u8]]) -> Result<(), Error> {
    let length = parts.iter().map(|part| part.len()).sum::<usize>();
    let length =
        u16::try_from(length).map_err(|_| Error::OutOfRange("information element length"))?;
    out.extend_from_slice(&length.to_be_bytes());
    for part in parts {
        out.extend_from_slice(part);
    }
    Ok(())
}
