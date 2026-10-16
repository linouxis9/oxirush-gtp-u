//! GTP-U information elements (TS 29.281 §8), the content of signalling
//! messages.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::truncated;
use crate::types::{Octets, Teid};
use crate::{Cause, Error, ExtensionHeaderType, InformationElementType, Part};

/// A GTP-U information element (TS 29.281 §8).
///
/// `Debug` prints a TEID and the octets of a value that is kept as received
/// in hexadecimal.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InformationElement {
    /// Cause (TS 29.060 §7.7.1): why a request is refused. GTP-U has it in
    /// the Echo Response to an Echo Request that is not well formed
    /// (TS 29.060 §11.1).
    Cause(Cause),
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
    ExtensionHeaderTypeList(Vec<ExtensionHeaderType>),
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
        /// Type, excluding Cause, Recovery and TEID Data I.
        kind: InformationElementType,
        /// The fixed-length value, kept as received.
        value: Vec<u8>,
    },
    /// Any other TLV information element, kept as received: a type of 128
    /// or more, and not one with a variant above (133, 141 or 255). A later
    /// version may decode more types into variants of their own, which the
    /// encoder then refuses as `Other`.
    Other {
        /// Type.
        kind: InformationElementType,
        /// Value.
        value: Vec<u8>,
    },
}

// The types with a variant, as the octets that the decoder matches.
const CAUSE: u8 = InformationElementType::CAUSE.0;
const RECOVERY: u8 = InformationElementType::RECOVERY.0;
const TEID_DATA_I: u8 = InformationElementType::TEID_DATA_I.0;
const GTP_U_PEER_ADDRESS: u8 = InformationElementType::GTP_U_PEER_ADDRESS.0;
const EXTENSION_HEADER_TYPE_LIST: u8 = InformationElementType::EXTENSION_HEADER_TYPE_LIST.0;
const PRIVATE_EXTENSION: u8 = InformationElementType::PRIVATE_EXTENSION.0;

impl InformationElement {
    /// The information element type.
    pub fn kind(&self) -> InformationElementType {
        match self {
            InformationElement::Cause(_) => InformationElementType::CAUSE,
            InformationElement::Recovery(_) => InformationElementType::RECOVERY,
            InformationElement::TeidDataI(_) => InformationElementType::TEID_DATA_I,
            InformationElement::GtpUPeerAddress(_) => InformationElementType::GTP_U_PEER_ADDRESS,
            InformationElement::ExtensionHeaderTypeList(_) => {
                InformationElementType::EXTENSION_HEADER_TYPE_LIST
            }
            InformationElement::PrivateExtension { .. } => {
                InformationElementType::PRIVATE_EXTENSION
            }
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
                CAUSE => {
                    let (&cause, rest) = rest
                        .split_first()
                        .ok_or_else(|| truncated(Part::Cause, 1, rest))?;
                    (InformationElement::Cause(Cause(cause)), rest)
                }
                RECOVERY => {
                    let (&counter, rest) = rest
                        .split_first()
                        .ok_or_else(|| truncated(Part::Recovery, 1, rest))?;
                    (InformationElement::Recovery(counter), rest)
                }
                TEID_DATA_I => {
                    let (teid, rest) = rest
                        .split_first_chunk::<4>()
                        .ok_or_else(|| truncated(Part::TeidDataI, 4, rest))?;
                    (
                        InformationElement::TeidDataI(u32::from_be_bytes(*teid)),
                        rest,
                    )
                }
                EXTENSION_HEADER_TYPE_LIST => {
                    let list = Part::ExtensionHeaderTypeList;
                    let (&length, rest) =
                        rest.split_first().ok_or_else(|| truncated(list, 1, rest))?;
                    let length = usize::from(length);
                    let (types, rest) = rest
                        .split_at_checked(length)
                        .ok_or_else(|| truncated(list, length, rest))?;
                    let types = types.iter().copied().map(ExtensionHeaderType).collect();
                    (InformationElement::ExtensionHeaderTypeList(types), rest)
                }
                128.. => {
                    let element = Part::InformationElement;
                    let (length, rest) = rest
                        .split_first_chunk::<2>()
                        .ok_or_else(|| truncated(element, 2, rest))?;
                    let length = usize::from(u16::from_be_bytes(*length));
                    let (value, rest) = rest
                        .split_at_checked(length)
                        .ok_or_else(|| truncated(element, length, rest))?;
                    (Self::decode_tlv(kind, value)?, rest)
                }
                _ => {
                    let length = tv_length(kind).ok_or(Error::UnknownInformationElement(
                        InformationElementType(kind),
                    ))?;
                    let (value, rest) = rest
                        .split_at_checked(length)
                        .ok_or_else(|| truncated(Part::InformationElement, length, rest))?;
                    (
                        InformationElement::OtherTv {
                            kind: InformationElementType(kind),
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
            GTP_U_PEER_ADDRESS => InformationElement::GtpUPeerAddress(
                if let Ok(octets) = <[u8; 4]>::try_from(value) {
                    Ipv4Addr::from(octets).into()
                } else if let Ok(octets) = <[u8; 16]>::try_from(value) {
                    Ipv6Addr::from(octets).into()
                } else {
                    // An IPv4 address or an IPv6 one.
                    return Err(Error::InvalidLength {
                        what: Part::GtpUPeerAddress,
                        length: value.len(),
                        expected: if value.len() < 10 { 4 } else { 16 },
                    });
                },
            ),
            PRIVATE_EXTENSION => {
                let (identifier, value) =
                    value.split_first_chunk::<2>().ok_or(Error::InvalidLength {
                        what: Part::PrivateExtension,
                        length: value.len(),
                        expected: 2,
                    })?;
                InformationElement::PrivateExtension {
                    identifier: u16::from_be_bytes(*identifier),
                    value: value.to_vec(),
                }
            }
            _ => InformationElement::Other {
                kind: InformationElementType(kind),
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
        out.push(self.kind().0);
        match self {
            InformationElement::Cause(cause) => out.push(cause.0),
            InformationElement::Recovery(counter) => out.push(*counter),
            InformationElement::TeidDataI(teid) => out.extend_from_slice(&teid.to_be_bytes()),
            InformationElement::ExtensionHeaderTypeList(types) => {
                let length = u8::try_from(types.len()).map_err(|_| Error::OutOfRange {
                    what: Part::ExtensionHeaderTypeList,
                    value: types.len() as u64,
                    max: u64::from(u8::MAX),
                })?;
                out.push(length);
                out.extend(types.iter().map(|kind| kind.0));
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
                let length = tv_length(kind.0)
                    .filter(|_| !matches!(kind.0, CAUSE | RECOVERY | TEID_DATA_I))
                    .ok_or(Error::InvalidType {
                        what: Part::InformationElement,
                        kind: kind.0,
                    })?;
                if value.len() != length {
                    return Err(Error::InvalidLength {
                        what: Part::InformationElement,
                        length: value.len(),
                        expected: length,
                    });
                }
                out.extend_from_slice(value);
            }
            InformationElement::Other { kind, value } => {
                if kind.0 < 128
                    || matches!(
                        kind.0,
                        GTP_U_PEER_ADDRESS | EXTENSION_HEADER_TYPE_LIST | PRIVATE_EXTENSION
                    )
                {
                    return Err(Error::InvalidType {
                        what: Part::InformationElement,
                        kind: kind.0,
                    });
                }
                push_tlv(out, &[value])?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for InformationElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InformationElement::Cause(cause) => f.debug_tuple("Cause").field(cause).finish(),
            InformationElement::Recovery(counter) => {
                f.debug_tuple("Recovery").field(counter).finish()
            }
            InformationElement::TeidDataI(teid) => {
                f.debug_tuple("TeidDataI").field(&Teid(*teid)).finish()
            }
            InformationElement::GtpUPeerAddress(address) => {
                f.debug_tuple("GtpUPeerAddress").field(address).finish()
            }
            InformationElement::ExtensionHeaderTypeList(types) => f
                .debug_tuple("ExtensionHeaderTypeList")
                .field(types)
                .finish(),
            InformationElement::PrivateExtension { identifier, value } => f
                .debug_struct("PrivateExtension")
                .field("identifier", identifier)
                .field("value", &Octets(value))
                .finish(),
            InformationElement::OtherTv { kind, value } => f
                .debug_struct("OtherTv")
                .field("kind", kind)
                .field("value", &Octets(value))
                .finish(),
            InformationElement::Other { kind, value } => f
                .debug_struct("Other")
                .field("kind", kind)
                .field("value", &Octets(value))
                .finish(),
        }
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
    let length = u16::try_from(length).map_err(|_| Error::OutOfRange {
        what: Part::InformationElement,
        value: length as u64,
        max: u64::from(u16::MAX),
    })?;
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
        // Cause (1), Recovery (14) and TEID Data I (16).
        let types = [
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
                kind: InformationElementType(kind),
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
                    Err(Error::Truncated {
                        what: Part::InformationElement,
                        needed: length,
                        available: cut - 1
                    })
                );
            }
            for wrong in [length - 1, length + 1] {
                assert_eq!(
                    InformationElement::encode_all(&[InformationElement::OtherTv {
                        kind: InformationElementType(kind),
                        value: vec![0xaa; wrong]
                    }]),
                    Err(Error::InvalidLength {
                        what: Part::InformationElement,
                        length: wrong,
                        expected: length
                    }),
                );
            }
        }
        for kind in [0, 6, 7, 10, 30, 116, 117, 126, 128, 255, 1, 14, 16] {
            assert_eq!(
                InformationElement::encode_all(&[InformationElement::OtherTv {
                    kind: InformationElementType(kind),
                    value: vec![]
                }]),
                Err(Error::InvalidType {
                    what: Part::InformationElement,
                    kind
                }),
            );
        }
    }
}
