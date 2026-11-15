//! ICMP Echo messages in IPv4 packets (RFC 792), as a UE pings through a
//! tunnel and a host on N6 answers: a request, the reply to it, and what a
//! receiver reads of either.
//!
//! ```
//! use oxirush_gtp_u::icmp::{self, EchoKind};
//!
//! // A ping of a UE, the reply of the server, and what the UE reads of it
//! let (ue, server) = ("10.45.0.2".parse().unwrap(), "192.0.2.1".parse().unwrap());
//! let request = icmp::echo_request(ue, server, 0x4f58, 1, b"ping")?;
//! let reply = icmp::reply_to(&request).unwrap();
//! let echo = icmp::parse_echo(&reply)?;
//! assert_eq!((echo.kind, echo.source, echo.destination), (EchoKind::Reply, server, ue));
//! assert_eq!((echo.identifier, echo.sequence, echo.payload), (0x4f58, 1, b"ping".as_slice()));
//! # Ok::<(), oxirush_gtp_u::Error>(())
//! ```

use std::net::Ipv4Addr;

use crate::error::truncated;
use crate::ip::{Expected, checksum, header, parse, total_length};
use crate::{Error, Part};

const ICMP: u8 = 1;
const HEADER_LEN: usize = 20;
const ECHO_HEADER_LEN: usize = 8;
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;

/// The type of an ICMP Echo message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EchoKind {
    /// Type 8, an Echo Request.
    Request,
    /// Type 0, an Echo Reply.
    Reply,
}

/// An ICMP Echo message that [`parse_echo`] read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo<'a> {
    /// The source of the IPv4 packet.
    pub source: Ipv4Addr,
    /// Its destination.
    pub destination: Ipv4Addr,
    /// A request or a reply.
    pub kind: EchoKind,
    /// The Identifier, which a reply has of its request.
    pub identifier: u16,
    /// The Sequence Number, which a reply has of its request.
    pub sequence: u16,
    /// The data, which a reply has of its request.
    pub payload: &'a [u8],
}

/// An IPv4 ICMP Echo message of `kind`, with the header of [`header`].
fn echo(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    kind: EchoKind,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let total_length = total_length(HEADER_LEN + ECHO_HEADER_LEN + payload.len())?;
    let mut bytes = header(source, destination, ICMP, total_length);
    let kind = match kind {
        EchoKind::Request => ECHO_REQUEST,
        EchoKind::Reply => ECHO_REPLY,
    };
    bytes.extend_from_slice(&[kind, 0, 0, 0]);
    bytes.extend_from_slice(&identifier.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(payload);
    let icmp_checksum = checksum(&[&bytes[HEADER_LEN..]]);
    bytes[HEADER_LEN + 2..HEADER_LEN + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(bytes)
}

/// An IPv4 ICMP Echo Request from `source` to `destination`, with the
/// header of [`ip::header`](crate::ip::header) and the ICMP checksum.
///
/// A payload that makes the packet longer than its Total Length can say is
/// [`Error::OutOfRange`].
pub fn echo_request(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    echo(
        source,
        destination,
        EchoKind::Request,
        identifier,
        sequence,
        payload,
    )
}

/// The ICMP Echo message of an IPv4 packet that is no fragment, whose
/// header checksum and ICMP checksum are valid, and whose ICMP type is 8 or
/// 0 with code 0.
///
/// ```
/// use oxirush_gtp_u::icmp;
/// use oxirush_gtp_u::ip::Expected;
/// use oxirush_gtp_u::{Error, Part};
///
/// let localhost = "127.0.0.1".parse().unwrap();
/// let mut request = icmp::echo_request(localhost, localhost, 1, 1, b"ping")?;
/// assert_eq!(icmp::parse_echo(&request)?.payload, b"ping");
///
/// // An octet changed in transit fails the ICMP checksum
/// request[30] ^= 1;
/// let error = icmp::parse_echo(&request).unwrap_err();
/// assert!(matches!(error, Error::InvalidChecksum { what: Part::IcmpMessage, .. }));
///
/// // A UDP packet is no ICMP message
/// let (source, destination) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
/// let udp = oxirush_gtp_u::ip::udp(source, destination, b"")?;
/// assert_eq!(icmp::parse_echo(&udp), Err(Error::UnexpectedPacket(Expected::Icmp)));
/// # Ok::<(), oxirush_gtp_u::Error>(())
/// ```
pub fn parse_echo(bytes: &[u8]) -> Result<Echo<'_>, Error> {
    let packet = parse(bytes)?;
    if packet.protocol != ICMP {
        return Err(Error::UnexpectedPacket(Expected::Icmp));
    }
    let icmp = packet.payload;
    let Some(echo_header) = icmp.first_chunk::<ECHO_HEADER_LEN>() else {
        return Err(truncated(Part::IcmpMessage, ECHO_HEADER_LEN, icmp));
    };
    let kind = match echo_header[..2] {
        [ECHO_REQUEST, 0] => EchoKind::Request,
        [ECHO_REPLY, 0] => EchoKind::Reply,
        _ => return Err(Error::UnexpectedPacket(Expected::Echo)),
    };
    if checksum(&[icmp]) != 0 {
        return Err(Error::InvalidChecksum {
            what: Part::IcmpMessage,
            received: u16::from_be_bytes([echo_header[2], echo_header[3]]),
            computed: checksum(&[&icmp[..2], &icmp[4..]]),
        });
    }
    Ok(Echo {
        source: packet.source,
        destination: packet.destination,
        kind,
        identifier: u16::from_be_bytes([echo_header[4], echo_header[5]]),
        sequence: u16::from_be_bytes([echo_header[6], echo_header[7]]),
        payload: &icmp[ECHO_HEADER_LEN..],
    })
}

/// The IPv4 ICMP Echo Reply to `request`, if it is an Echo Request that
/// [`parse_echo`] reads: the addresses swapped, the Identifier, the Sequence
/// Number and the data of the request, in a header of
/// [`ip::header`](crate::ip::header). The test UPF answers so on N6.
pub fn reply_to(request: &[u8]) -> Option<Vec<u8>> {
    let echo = parse_echo(request)
        .ok()
        .filter(|echo| echo.kind == EchoKind::Request)?;
    self::echo(
        echo.destination,
        echo.source,
        EchoKind::Reply,
        echo.identifier,
        echo.sequence,
        echo.payload,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(payload: &[u8]) -> Vec<u8> {
        let (source, destination) = (Ipv4Addr::new(10, 60, 0, 2), Ipv4Addr::new(192, 0, 2, 1));
        echo_request(source, destination, 0x1234, 7, payload).unwrap()
    }

    #[test]
    fn an_echo_request_has_its_reply() {
        crate::bounded(|| {
            let request = request(b"ping");
            let reply = reply_to(&request).unwrap();
            // The addresses swapped, type 0, the identifier, sequence number and
            // data of the request, and valid checksums.
            assert_eq!(reply[12..16], request[16..20]);
            assert_eq!(reply[16..20], request[12..16]);
            assert_eq!(reply[20..22], [ECHO_REPLY, 0]);
            assert_eq!(reply[24..], request[24..]);
            assert_eq!(checksum(&[&reply[..20]]), 0);
            assert_eq!(checksum(&[&reply[20..]]), 0);
            // A reply, a UDP packet, a cut or a corrupt request have none.
            assert_eq!(reply_to(&reply), None);
            let udp = crate::ip::udp(
                "10.60.0.2:1".parse().unwrap(),
                "192.0.2.1:2".parse().unwrap(),
                b"x",
            );
            assert_eq!(reply_to(&udp.unwrap()), None);
            assert_eq!(reply_to(&request[..27]), None);
            let mut corrupt = request.clone();
            corrupt[28] ^= 1;
            assert_eq!(reply_to(&corrupt), None);
            let mut code = request.clone();
            code[21] = 1;
            let sum = checksum(&[&code[20..22], &code[24..]]);
            code[22..24].copy_from_slice(&sum.to_be_bytes());
            assert_eq!(reply_to(&code), None);
        });
    }

    #[test]
    fn a_request_and_its_reply_read_as_they_were_written() {
        crate::bounded(|| {
            let (ue, server) = (Ipv4Addr::new(10, 60, 0, 2), Ipv4Addr::new(192, 0, 2, 1));
            // An odd payload: the ICMP checksum pads its last octet.
            let request = request(b"ping!");
            assert_eq!(request.len(), 20 + 8 + 5);
            let read = Echo {
                source: ue,
                destination: server,
                kind: EchoKind::Request,
                identifier: 0x1234,
                sequence: 7,
                payload: b"ping!",
            };
            assert_eq!(parse_echo(&request), Ok(read));
            let reply = reply_to(&request).unwrap();
            assert_eq!(
                parse_echo(&reply),
                Ok(Echo {
                    source: server,
                    destination: ue,
                    kind: EchoKind::Reply,
                    ..read
                })
            );
        });
    }

    #[test]
    fn what_is_no_echo_is_refused() {
        crate::bounded(|| {
            let request = request(b"ping");
            // The error has the checksum of the message and the one that its
            // octets give: that of a message made with them.
            let mut corrupt = request.clone();
            corrupt[31] ^= 1;
            let made = echo_request(
                Ipv4Addr::new(10, 60, 0, 2),
                Ipv4Addr::new(192, 0, 2, 1),
                0x1234,
                7,
                b"pinf",
            )
            .unwrap();
            let field = |packet: &[u8]| u16::from_be_bytes([packet[22], packet[23]]);
            assert_eq!(
                parse_echo(&corrupt),
                Err(Error::InvalidChecksum {
                    what: Part::IcmpMessage,
                    received: field(&request),
                    computed: field(&made),
                })
            );
            // An ICMP message shorter than the header of an Echo.
            let mut short = request[..27].to_vec();
            short[2..4].copy_from_slice(&27u16.to_be_bytes());
            short[10..12].fill(0);
            let sum = checksum(&[&short[..20]]);
            short[10..12].copy_from_slice(&sum.to_be_bytes());
            assert_eq!(
                parse_echo(&short),
                Err(Error::Truncated {
                    what: Part::IcmpMessage,
                    needed: 8,
                    available: 7,
                })
            );
            // Another type, or another code.
            let mut other = request.clone();
            other[20] = 3;
            assert_eq!(
                parse_echo(&other),
                Err(Error::UnexpectedPacket(Expected::Echo))
            );
            let mut code = request.clone();
            code[21] = 1;
            assert_eq!(
                parse_echo(&code),
                Err(Error::UnexpectedPacket(Expected::Echo))
            );
            // What the IPv4 header refuses is refused first.
            assert_eq!(
                parse_echo(&request[..19]),
                Err(Error::Truncated {
                    what: Part::Ipv4Header,
                    needed: 20,
                    available: 19,
                })
            );
        });
    }

    #[test]
    fn an_echo_longer_than_an_ipv4_packet_is_refused() {
        crate::bounded(|| {
            let localhost = Ipv4Addr::LOCALHOST;
            assert_eq!(
                echo_request(localhost, localhost, 0, 0, &[0; 65_536 - 28]),
                Err(Error::OutOfRange {
                    what: Part::Ipv4Packet,
                    value: 65_536,
                    max: 65_535,
                })
            );
            assert!(echo_request(localhost, localhost, 0, 0, &[0; 65_535 - 28]).is_ok());
        });
    }
}
