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
    /// A TV information element defined by TS 29.060 table 37, but not
    /// expected in GTP-U signalling. Its known fixed length allows the
    /// receiver to skip it (TS 29.060 section 11.1.11).
    OtherTv {
        /// Type, excluding Recovery and TEID Data I.
        kind: u8,
        /// The fixed-length value, kept as received.
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
            InformationElement::OtherTv { kind, .. } => *kind,
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
                _ => {
                    let length = tv_length(kind).ok_or(Error::UnknownInformationElement(kind))?;
                    let (value, rest) = rest
                        .split_at_checked(length)
                        .ok_or(Error::Truncated("TV information element"))?;
                    (
                        InformationElement::OtherTv {
                            kind,
                            value: value.to_vec(),
                        },
                        rest,
                    )
                }
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
            InformationElement::OtherTv { kind, value } => {
                let length = tv_length(*kind)
                    .filter(|_| !matches!(*kind, Self::RECOVERY | Self::TEID_DATA_I))
                    .ok_or(Error::OutOfRange("TV information element type"))?;
                if value.len() != length {
                    return Err(Error::InvalidLength("TV information element"));
                }
                out.extend_from_slice(value);
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

/// Fixed value lengths of every TV IE in TS 29.060 V19.0.0 table 37.
fn tv_length(kind: u8) -> Option<usize> {
    match kind {
        1 | 8 | 11 | 13..=15 | 19..=21 | 23 | 24 | 29 => Some(1),
        2 => Some(8),
        3 => Some(6),
        4 | 5 | 16 | 17 | 127 => Some(4),
        9 => Some(28),
        12 => Some(3),
        18 => Some(5),
        22 => Some(9),
        25..=28 => Some(2),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_tv_ie_has_its_specified_length() {
        // TS 29.060 V19.0.0 table 37, excluding the separately typed
        // Recovery (14) and TEID Data I (16).
        let types = [
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
        ];
        for (kind, length) in types {
            let element = InformationElement::OtherTv {
                kind,
                value: vec![0xaa; length],
            };
            let mut wire = vec![kind];
            wire.extend_from_slice(&vec![0xaa; length]);
            assert_eq!(
                InformationElement::encode_all(std::slice::from_ref(&element)).unwrap(),
                wire
            );
            assert_eq!(
                InformationElement::decode_all(&wire).unwrap(),
                vec![element]
            );
            for cut in 1..wire.len() {
                assert_eq!(
                    InformationElement::decode_all(&wire[..cut]),
                    Err(Error::Truncated("TV information element"))
                );
            }
            for length in [length - 1, length + 1] {
                assert_eq!(
                    InformationElement::encode_all(&[InformationElement::OtherTv {
                        kind,
                        value: vec![0xaa; length]
                    }]),
                    Err(Error::InvalidLength("TV information element")),
                );
            }
        }
        for kind in [0, 6, 7, 10, 30, 116, 117, 126, 128, 255, 14, 16] {
            assert_eq!(
                InformationElement::encode_all(&[InformationElement::OtherTv {
                    kind,
                    value: vec![]
                }]),
                Err(Error::OutOfRange("TV information element type")),
            );
        }
    }
}
