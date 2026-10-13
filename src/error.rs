use std::fmt;

/// Why a GTP-U message, or an inner IPv4 packet, cannot be decoded or encoded.
///
/// An error names the part of the message that is wrong and has the numbers
/// that disagree:
///
/// ```
/// use oxirush_gtp_u::{Error, Packet, Part};
///
/// // A G-PDU of one octet, whose Length field says nine
/// let error = Packet::decode(&[0x30, 0xff, 0, 9, 0x12, 0x34, 0x56, 0x78, 0x45]).unwrap_err();
/// assert_eq!(
///     error,
///     Error::Truncated { what: Part::Message, needed: 9, available: 1 }
/// );
/// assert_eq!(
///     error.to_string(),
///     "truncated GTP-U message: the Length field says 9 octets after the header, \
///      the datagram has 1"
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ends inside `what`.
    Truncated {
        /// The part that is cut short.
        what: Part,
        /// The octets that it needs from where it starts, or that the field
        /// being read needs.
        needed: usize,
        /// The octets that are left there.
        available: usize,
    },
    /// `what` has a length that its content, its format or the input does
    /// not allow.
    InvalidLength {
        /// The part with that length.
        what: Part,
        /// The length that it has or states, in octets. That of an extension
        /// header counts its length and next type octets.
        length: usize,
        /// The length that it must have: the one that its content or the
        /// input gives, or the nearest one that its format allows.
        expected: usize,
    },
    /// The first octet is not that of a GTPv1-U message: version 1,
    /// protocol type GTP (not GTP').
    UnsupportedVersion(u8),
    /// `what` holds a value that its encoding cannot carry.
    OutOfRange {
        /// The field, or the part whose length is the value.
        what: Part,
        /// The value.
        value: u64,
        /// The largest value that the encoding carries.
        max: u64,
    },
    /// A value that is kept as octets (`Other`) has a type under which it
    /// cannot be kept: one that the format does not have, or one that has a
    /// variant of its own.
    InvalidType {
        /// What is kept as octets.
        what: Part,
        /// Its type.
        kind: u8,
    },
    /// A field is given without the one that says it is there: the Burst
    /// Size or the Time To Next Burst of DL PDU Session Information without
    /// its PPI, whose octet has their flags.
    Missing(Part),
    /// `what` is not as its format says: the New IE Flags of
    /// [`UnknownNewIes`](crate::UnknownNewIes).
    Malformed(Part),
    /// A TV information element of unknown type. Its length is not
    /// encoded, so the rest of the message cannot be parsed.
    UnknownInformationElement(u8),
    /// An IPv4 packet that is not what the helper handles.
    UnexpectedPacket(Expected),
    /// A checksum does not match.
    InvalidChecksum {
        /// What the checksum covers.
        what: Part,
        /// The checksum in the packet.
        received: u16,
        /// The one that its octets give.
        computed: u16,
    },
}

/// The part of a message that an [`Error`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Part {
    /// The mandatory header, 8 octets (TS 29.281 §5.1).
    Header,
    /// The message after its mandatory header: what the Length field counts.
    Message,
    /// The Length field of the header, 16 bits.
    Length,
    /// The Sequence Number, N-PDU Number and Next Extension Header Type,
    /// which are present together.
    OptionalHeader,
    /// An extension header (TS 29.281 §5.2.1).
    ExtensionHeader,
    /// The UDP Port extension header.
    UdpPort,
    /// The PDU Session Container (TS 38.415 §5.5.2).
    PduSessionContainer,
    /// The QoS Flow Identifier, 6 bits.
    Qfi,
    /// The Paging Policy Indicator, 3 bits.
    Ppi,
    /// The Burst Size, 24 bits.
    BurstSize,
    /// The DL QFI Sequence Number, 24 bits.
    DlQfiSequenceNumber,
    /// The UL QFI Sequence Number, 24 bits.
    UlQfiSequenceNumber,
    /// The New IE Flags of UL PDU Session Information.
    NewIeFlags,
    /// An information element (TS 29.281 §8).
    InformationElement,
    /// The Recovery information element.
    Recovery,
    /// The TEID Data I information element.
    TeidDataI,
    /// The GTP-U Peer Address information element.
    GtpUPeerAddress,
    /// The Extension Header Type List information element.
    ExtensionHeaderTypeList,
    /// The Private Extension information element.
    PrivateExtension,
    /// The header of an inner IPv4 packet.
    Ipv4Header,
    /// An inner IPv4 packet: what its Total Length counts.
    Ipv4Packet,
    /// The header of a UDP datagram.
    UdpHeader,
    /// A UDP datagram: what its Length counts.
    UdpDatagram,
    /// The header of an ICMP message.
    IcmpHeader,
    /// An ICMP message.
    IcmpMessage,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Part::Header => "GTP-U header",
            Part::Message => "GTP-U message",
            Part::Length => "GTP-U Length",
            Part::OptionalHeader => "GTP-U optional header",
            Part::ExtensionHeader => "extension header",
            Part::UdpPort => "UDP Port extension header",
            Part::PduSessionContainer => "PDU Session Container",
            Part::Qfi => "QFI",
            Part::Ppi => "PPI",
            Part::BurstSize => "Burst Size",
            Part::DlQfiSequenceNumber => "DL QFI Sequence Number",
            Part::UlQfiSequenceNumber => "UL QFI Sequence Number",
            Part::NewIeFlags => "New IE Flags",
            Part::InformationElement => "information element",
            Part::Recovery => "Recovery",
            Part::TeidDataI => "TEID Data I",
            Part::GtpUPeerAddress => "GTP-U Peer Address",
            Part::ExtensionHeaderTypeList => "Extension Header Type List",
            Part::PrivateExtension => "Private Extension",
            Part::Ipv4Header => "IPv4 header",
            Part::Ipv4Packet => "IPv4 packet",
            Part::UdpHeader => "UDP header",
            Part::UdpDatagram => "UDP datagram",
            Part::IcmpHeader => "ICMP header",
            Part::IcmpMessage => "ICMP message",
        })
    }
}

/// What an IPv4 helper expected of a packet that is something else
/// ([`Error::UnexpectedPacket`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Expected {
    /// IP version 4.
    Ipv4,
    /// A packet that is no fragment.
    Unfragmented,
    /// Protocol 17, UDP.
    Udp,
    /// Protocol 1, ICMP.
    Icmp,
    /// An ICMP Echo Request or Echo Reply, with code 0.
    IcmpEcho,
    /// An ICMP Echo Request.
    IcmpEchoRequest,
}

impl fmt::Display for Expected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Expected::Ipv4 => "not IPv4",
            Expected::Unfragmented => "fragmented",
            Expected::Udp => "not UDP",
            Expected::Icmp => "not ICMP",
            Expected::IcmpEcho => "not an ICMP Echo message",
            Expected::IcmpEchoRequest => "not an ICMP Echo Request",
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            // The two lengths of a message: the mistake of a vector written
            // by hand.
            Error::Truncated {
                what: Part::Message,
                needed,
                available,
            } => write!(
                f,
                "truncated GTP-U message: the Length field says {needed} octets after the \
                 header, the datagram has {available}"
            ),
            Error::InvalidLength {
                what: Part::Message,
                length,
                expected,
            } => write!(
                f,
                "invalid GTP-U message length: the Length field says {length} octets after \
                 the header, the datagram has {expected}"
            ),
            Error::Truncated {
                what,
                needed,
                available,
            } => write!(
                f,
                "truncated {what}: {needed} octets needed, {available} left"
            ),
            Error::InvalidLength {
                what,
                length,
                expected,
            } => write!(
                f,
                "invalid {what} length: {length} octets, expected {expected}"
            ),
            Error::UnsupportedVersion(flags) => {
                write!(f, "not a GTPv1-U message (first octet {flags:#04x})")
            }
            Error::OutOfRange { what, value, max } => {
                write!(f, "{what} out of range: {value}, at most {max}")
            }
            Error::InvalidType { what, kind } => {
                write!(f, "{what} kept as octets under type {kind} ({kind:#04x})")
            }
            Error::Missing(what) => write!(f, "{what} missing"),
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::UnknownInformationElement(kind) => {
                write!(f, "unknown TV information element type {kind}")
            }
            Error::UnexpectedPacket(expected) => write!(f, "unexpected IPv4 packet: {expected}"),
            Error::InvalidChecksum {
                what,
                received,
                computed,
            } => write!(
                f,
                "invalid {what} checksum: {received:#06x}, computed {computed:#06x}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// As [`InvalidData`](std::io::ErrorKind::InvalidData), so that `?` also
/// works on the codec's results where an endpoint's are returned.
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, error)
    }
}

/// `what` ends before the `needed` octets that `available` should have.
pub(crate) fn truncated(what: Part, needed: usize, available: &[u8]) -> Error {
    Error::Truncated {
        what,
        needed,
        available: available.len(),
    }
}

/// The length, counted in octets, of an extension header whose content is
/// `content` octets long, and the nearest one that the format allows: a
/// multiple of 4.
pub(crate) fn header_length(what: Part, content: usize) -> Error {
    let length = content + 2;
    Error::InvalidLength {
        what,
        length,
        expected: length.next_multiple_of(4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_io_error_keeps_the_codec_error() {
        let codec = Error::Truncated {
            what: Part::Header,
            needed: 8,
            available: 3,
        };
        let error = std::io::Error::from(codec.clone());
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.get_ref().and_then(|inner| inner.downcast_ref()),
            Some(&codec)
        );
    }

    #[test]
    fn an_error_says_its_part_and_its_numbers() {
        for (error, text) in [
            (
                Error::Truncated {
                    what: Part::ExtensionHeader,
                    needed: 8,
                    available: 5,
                },
                "truncated extension header: 8 octets needed, 5 left",
            ),
            (
                Error::InvalidLength {
                    what: Part::UdpPort,
                    length: 8,
                    expected: 4,
                },
                "invalid UDP Port extension header length: 8 octets, expected 4",
            ),
            (
                Error::UnsupportedVersion(0x50),
                "not a GTPv1-U message (first octet 0x50)",
            ),
            (
                Error::OutOfRange {
                    what: Part::Qfi,
                    value: 64,
                    max: 63,
                },
                "QFI out of range: 64, at most 63",
            ),
            (
                Error::InvalidType {
                    what: Part::ExtensionHeader,
                    kind: 0x85,
                },
                "extension header kept as octets under type 133 (0x85)",
            ),
            (Error::Missing(Part::Ppi), "PPI missing"),
            (Error::Malformed(Part::NewIeFlags), "malformed New IE Flags"),
            (
                Error::UnknownInformationElement(6),
                "unknown TV information element type 6",
            ),
            (
                Error::UnexpectedPacket(Expected::Udp),
                "unexpected IPv4 packet: not UDP",
            ),
            (
                Error::InvalidChecksum {
                    what: Part::UdpDatagram,
                    received: 0x1234,
                    computed: 0x0abc,
                },
                "invalid UDP datagram checksum: 0x1234, computed 0x0abc",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
    }
}
