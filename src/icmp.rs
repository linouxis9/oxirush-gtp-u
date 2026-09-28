//! IPv4 ICMP Echo packets, for pings through a tunnel and the test UPF's
//! echo service.

use std::net::Ipv4Addr;

use crate::Error;
use crate::ipv4::{checksum, header, parse};

const ICMP: u8 = 1;
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;

/// Whether an ICMP Echo message is a request or a reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoKind {
    /// Echo Request (type 8).
    Request,
    /// Echo Reply (type 0).
    Reply,
}

/// A parsed IPv4 ICMP Echo message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct IcmpEcho<'a> {
    /// IPv4 source address.
    pub source: Ipv4Addr,
    /// IPv4 destination address.
    pub destination: Ipv4Addr,
    /// Request or reply.
    pub kind: EchoKind,
    /// Identifier.
    pub identifier: u16,
    /// Sequence number.
    pub sequence: u16,
    /// Data.
    pub payload: &'a [u8],
}

fn build(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    kind: EchoKind,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let total = 20 + 8 + payload.len();
    let total_length = u16::try_from(total).map_err(|_| Error::OutOfRange("IPv4 total length"))?;
    let mut bytes = header(source, destination, ICMP, total_length);
    let icmp_type = match kind {
        EchoKind::Request => ECHO_REQUEST,
        EchoKind::Reply => ECHO_REPLY,
    };
    bytes.extend_from_slice(&[icmp_type, 0, 0, 0]);
    bytes.extend_from_slice(&identifier.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(payload);
    let icmp_checksum = checksum(&[&bytes[20..]]);
    bytes[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(bytes)
}

/// Build an IPv4 ICMP Echo Request.
pub fn ipv4_icmp_echo_request(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    build(
        source,
        destination,
        EchoKind::Request,
        identifier,
        sequence,
        payload,
    )
}

/// Build the IPv4 ICMP Echo Reply to an Echo Request.
pub fn ipv4_icmp_echo_reply(request: &[u8]) -> Result<Vec<u8>, Error> {
    let echo = parse_ipv4_icmp_echo(request)?;
    if echo.kind != EchoKind::Request {
        return Err(Error::UnexpectedPacket("not an ICMP Echo Request"));
    }
    build(
        echo.destination,
        echo.source,
        EchoKind::Reply,
        echo.identifier,
        echo.sequence,
        echo.payload,
    )
}

/// Parse an IPv4 ICMP Echo Request or Reply. The IPv4 header and ICMP
/// checksums must be valid.
pub fn parse_ipv4_icmp_echo(bytes: &[u8]) -> Result<IcmpEcho<'_>, Error> {
    let packet = parse(bytes, ICMP)?;
    let icmp = packet.payload;
    let Some(icmp_header) = icmp.first_chunk::<8>() else {
        return Err(Error::Truncated("ICMP header"));
    };
    if checksum(&[icmp]) != 0 {
        return Err(Error::InvalidChecksum("ICMP"));
    }
    let kind = match (icmp_header[0], icmp_header[1]) {
        (ECHO_REQUEST, 0) => EchoKind::Request,
        (ECHO_REPLY, 0) => EchoKind::Reply,
        _ => return Err(Error::UnexpectedPacket("not an ICMP Echo message")),
    };
    Ok(IcmpEcho {
        source: packet.source,
        destination: packet.destination,
        kind,
        identifier: u16::from_be_bytes([icmp_header[4], icmp_header[5]]),
        sequence: u16::from_be_bytes([icmp_header[6], icmp_header[7]]),
        payload: &icmp[8..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_reply_round_trip_and_checksums() {
        let source = Ipv4Addr::new(10, 60, 0, 2);
        let destination = Ipv4Addr::new(192, 0, 2, 1);
        let request = ipv4_icmp_echo_request(source, destination, 0x1234, 7, b"ping").unwrap();
        let parsed = parse_ipv4_icmp_echo(&request).unwrap();
        assert_eq!(
            (parsed.source, parsed.destination, parsed.kind),
            (source, destination, EchoKind::Request)
        );
        assert_eq!(
            (parsed.identifier, parsed.sequence, parsed.payload),
            (0x1234, 7, b"ping".as_slice())
        );
        let reply = ipv4_icmp_echo_reply(&request).unwrap();
        let parsed = parse_ipv4_icmp_echo(&reply).unwrap();
        assert_eq!(
            (parsed.source, parsed.destination, parsed.kind),
            (destination, source, EchoKind::Reply)
        );
        assert_eq!(parsed.payload, b"ping");
        assert_eq!(
            ipv4_icmp_echo_reply(&reply),
            Err(Error::UnexpectedPacket("not an ICMP Echo Request"))
        );
    }

    #[test]
    fn rejects_corrupt_icmp_checksum() {
        let mut packet =
            ipv4_icmp_echo_request(Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 1), 1, 1, b"x")
                .unwrap();
        packet[28] ^= 1;
        assert_eq!(
            parse_ipv4_icmp_echo(&packet),
            Err(Error::InvalidChecksum("ICMP"))
        );
    }
}
