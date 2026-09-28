//! IPv4 UDP packets, to exercise a tunnel without a TUN device.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::Error;

const HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const UDP: u8 = 17;

/// Build an IPv4 UDP packet from `source` to `destination`.
pub fn ipv4_udp(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let total = HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let total_length = u16::try_from(total).map_err(|_| Error::OutOfRange("IPv4 total length"))?;
    let mut bytes = header(*source.ip(), *destination.ip(), UDP, total_length);
    let udp_length = total_length - HEADER_LEN as u16;
    bytes.extend_from_slice(&source.port().to_be_bytes());
    bytes.extend_from_slice(&destination.port().to_be_bytes());
    bytes.extend_from_slice(&udp_length.to_be_bytes());
    bytes.extend_from_slice(&[0, 0]); // checksum, set below
    bytes.extend_from_slice(payload);
    let checksum = match udp_checksum(*source.ip(), *destination.ip(), &bytes[HEADER_LEN..]) {
        0 => 0xffff, // 0 means "no checksum"
        checksum => checksum,
    };
    bytes[HEADER_LEN + 6..HEADER_LEN + 8].copy_from_slice(&checksum.to_be_bytes());
    Ok(bytes)
}

/// Parse an IPv4 UDP packet into its source, destination and payload. The
/// IPv4 header checksum, and the UDP checksum when not 0, must be valid.
pub fn parse_ipv4_udp(bytes: &[u8]) -> Result<(SocketAddrV4, SocketAddrV4, &[u8]), Error> {
    let packet = parse(bytes, UDP)?;
    let udp = packet.payload;
    let Some(udp_header) = udp.first_chunk::<UDP_HEADER_LEN>() else {
        return Err(Error::Truncated("UDP header"));
    };
    let udp_length = usize::from(u16::from_be_bytes([udp_header[4], udp_header[5]]));
    if udp_length < UDP_HEADER_LEN || udp_length > udp.len() {
        return Err(Error::InvalidLength("UDP"));
    }
    let udp = &udp[..udp_length];
    if udp_header[6..8] != [0, 0] && udp_checksum(packet.source, packet.destination, udp) != 0 {
        return Err(Error::InvalidChecksum("UDP"));
    }
    Ok((
        SocketAddrV4::new(
            packet.source,
            u16::from_be_bytes([udp_header[0], udp_header[1]]),
        ),
        SocketAddrV4::new(
            packet.destination,
            u16::from_be_bytes([udp_header[2], udp_header[3]]),
        ),
        &udp[UDP_HEADER_LEN..],
    ))
}

/// The fields of an IPv4 packet the helpers use.
pub(crate) struct Ipv4Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    /// The payload, without link padding after the total length.
    pub payload: &'a [u8],
}

/// Parse an unfragmented IPv4 packet of `protocol` with a valid header
/// checksum.
pub(crate) fn parse(bytes: &[u8], protocol: u8) -> Result<Ipv4Packet<'_>, Error> {
    let Some(header) = bytes.first_chunk::<HEADER_LEN>() else {
        return Err(Error::Truncated("IPv4 header"));
    };
    if header[0] >> 4 != 4 {
        return Err(Error::UnexpectedPacket("not IPv4"));
    }
    let header_len = usize::from(header[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if header_len < HEADER_LEN || total < header_len {
        return Err(Error::InvalidLength("IPv4 header"));
    }
    if total > bytes.len() {
        return Err(Error::Truncated("IPv4 packet"));
    }
    if header[9] != protocol {
        return Err(Error::UnexpectedPacket(match protocol {
            UDP => "not UDP",
            _ => "not ICMP",
        }));
    }
    // More Fragments, or a fragment offset.
    if header[6] & 0x3f != 0 || header[7] != 0 {
        return Err(Error::UnexpectedPacket("fragmented"));
    }
    if checksum(&[&bytes[..header_len]]) != 0 {
        return Err(Error::InvalidChecksum("IPv4 header"));
    }
    Ok(Ipv4Packet {
        source: Ipv4Addr::from([header[12], header[13], header[14], header[15]]),
        destination: Ipv4Addr::from([header[16], header[17], header[18], header[19]]),
        payload: &bytes[header_len..total],
    })
}

/// An IPv4 header without options, Don't Fragment set, TTL 64.
pub(crate) fn header(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    total_length: u16,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(usize::from(total_length));
    bytes.extend_from_slice(&[0x45, 0]);
    bytes.extend_from_slice(&total_length.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    let checksum = checksum(&[&bytes]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    // The segment length fits: the IPv4 total length is 16 bits.
    let length = (udp.len() as u16).to_be_bytes();
    checksum(&[
        &source.octets(),
        &destination.octets(),
        &[0, UDP],
        &length,
        udp,
    ])
}

/// The Internet checksum (RFC 1071) of the concatenated `parts`; only the
/// last part may have an odd length.
pub(crate) fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut words = part.chunks_exact(2);
        for word in words.by_ref() {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        if let [last] = words.remainder() {
            sum += u32::from(*last) << 8;
        }
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_round_trip_with_checksums() {
        let source = SocketAddrV4::new(Ipv4Addr::new(10, 60, 0, 2), 1234);
        let destination = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40900);
        let packet = ipv4_udp(source, destination, b"odd").unwrap();
        assert_eq!(
            parse_ipv4_udp(&packet).unwrap(),
            (source, destination, b"odd".as_slice())
        );
        let mut corrupt = packet.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(parse_ipv4_udp(&corrupt), Err(Error::InvalidChecksum("UDP")));
        // A zero UDP checksum means none.
        let mut unchecked = packet;
        unchecked[26..28].copy_from_slice(&[0, 0]);
        *unchecked.last_mut().unwrap() ^= 1;
        assert!(parse_ipv4_udp(&unchecked).is_ok());
    }

    #[test]
    fn known_checksum() {
        // RFC 1071 §3 example.
        let bytes = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&[&bytes]), 0x220d);
        assert_eq!(
            checksum(&[&bytes[..2], &bytes[2..7]]),
            checksum(&[&bytes[..7]])
        );
    }

    #[test]
    fn rejects_malformed_ipv4() {
        let source = SocketAddrV4::new(Ipv4Addr::new(10, 60, 0, 2), 1);
        let packet = ipv4_udp(source, source, b"x").unwrap();
        for length in 0..packet.len() {
            assert!(parse_ipv4_udp(&packet[..length]).is_err());
        }
        let mut fragment = packet.clone();
        fragment[6] |= 0x20; // More Fragments
        assert_eq!(
            parse_ipv4_udp(&fragment),
            Err(Error::UnexpectedPacket("fragmented"))
        );
        let mut icmp = packet;
        icmp[9] = 1;
        assert_eq!(
            parse_ipv4_udp(&icmp),
            Err(Error::UnexpectedPacket("not UDP"))
        );
    }
}
