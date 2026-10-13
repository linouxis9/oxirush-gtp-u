//! IPv4 UDP packets, to exercise a tunnel without a TUN device.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::error::truncated;
use crate::{Error, Expected, Part};

const HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const UDP: u8 = 17;

/// Build an IPv4 UDP packet from `source` to `destination`.
pub fn ipv4_udp(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let total_length = total_length(HEADER_LEN + UDP_HEADER_LEN + payload.len())?;
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
        return Err(truncated(Part::UdpHeader, UDP_HEADER_LEN, udp));
    };
    let udp_length = usize::from(u16::from_be_bytes([udp_header[4], udp_header[5]]));
    if udp_length < UDP_HEADER_LEN {
        return Err(Error::InvalidLength {
            what: Part::UdpDatagram,
            length: udp_length,
            expected: UDP_HEADER_LEN,
        });
    }
    if udp_length > udp.len() {
        return Err(truncated(Part::UdpDatagram, udp_length, udp));
    }
    let udp = &udp[..udp_length];
    if udp_header[6..8] != [0, 0] && udp_checksum(packet.source, packet.destination, udp) != 0 {
        // The checksum of the datagram without the one that it carries.
        let pseudo_header = pseudo_header(packet.source, packet.destination, udp.len());
        let computed = checksum(&[&pseudo_header, &udp[..6], &udp[8..]]);
        return Err(Error::InvalidChecksum {
            what: Part::UdpDatagram,
            received: u16::from_be_bytes([udp_header[6], udp_header[7]]),
            computed: if computed == 0 { 0xffff } else { computed },
        });
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
        return Err(truncated(Part::Ipv4Header, HEADER_LEN, bytes));
    };
    if header[0] >> 4 != 4 {
        return Err(Error::UnexpectedPacket(Expected::Ipv4));
    }
    let header_len = usize::from(header[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if header_len < HEADER_LEN {
        return Err(Error::InvalidLength {
            what: Part::Ipv4Header,
            length: header_len,
            expected: HEADER_LEN,
        });
    }
    if total < header_len {
        return Err(Error::InvalidLength {
            what: Part::Ipv4Packet,
            length: total,
            expected: header_len,
        });
    }
    if total > bytes.len() {
        return Err(truncated(Part::Ipv4Packet, total, bytes));
    }
    if header[9] != protocol {
        return Err(Error::UnexpectedPacket(match protocol {
            UDP => Expected::Udp,
            _ => Expected::Icmp,
        }));
    }
    // More Fragments, or a fragment offset.
    if header[6] & 0x3f != 0 || header[7] != 0 {
        return Err(Error::UnexpectedPacket(Expected::Unfragmented));
    }
    if checksum(&[&bytes[..header_len]]) != 0 {
        return Err(Error::InvalidChecksum {
            what: Part::Ipv4Header,
            received: u16::from_be_bytes([header[10], header[11]]),
            computed: checksum(&[&bytes[..10], &bytes[12..header_len]]),
        });
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

/// The Total Length of an IPv4 packet of `total` octets.
pub(crate) fn total_length(total: usize) -> Result<u16, Error> {
    u16::try_from(total).map_err(|_| Error::OutOfRange {
        what: Part::Ipv4Packet,
        value: total as u64,
        max: u64::from(u16::MAX),
    })
}

/// The pseudo header that the checksum of a UDP datagram of `length` octets
/// covers before it.
fn pseudo_header(source: Ipv4Addr, destination: Ipv4Addr, length: usize) -> [u8; 12] {
    let mut header = [0; 12];
    header[..4].copy_from_slice(&source.octets());
    header[4..8].copy_from_slice(&destination.octets());
    header[9] = UDP;
    // The segment length fits: the IPv4 total length is 16 bits.
    header[10..].copy_from_slice(&(length as u16).to_be_bytes());
    header
}

fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    checksum(&[&pseudo_header(source, destination, udp.len()), udp])
}

/// The Internet checksum (RFC 1071) of the concatenated `parts`; only the
/// last part may have an odd length.
pub(crate) fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let (words, last) = part.as_chunks::<2>();
        for word in words {
            sum += u32::from(u16::from_be_bytes(*word));
        }
        if let [last] = last {
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
        // The error has the checksum of the packet and the one that its
        // octets give: that of a packet made with them.
        let mut corrupt = packet.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let made = ipv4_udp(source, destination, b"ode").unwrap();
        assert_eq!(corrupt[28..], made[28..]);
        let field = |packet: &[u8]| u16::from_be_bytes([packet[26], packet[27]]);
        assert_ne!(field(&packet), field(&made));
        assert_eq!(
            parse_ipv4_udp(&corrupt),
            Err(Error::InvalidChecksum {
                what: Part::UdpDatagram,
                received: field(&packet),
                computed: field(&made)
            })
        );
        let mut header = packet.clone();
        header[8] = 63; // the TTL of a packet that crossed a router
        let received = u16::from_be_bytes([packet[10], packet[11]]);
        // One less in an octet of weight 256 is 256 more in the complement
        // of the sum, whose carry comes back at its low end.
        let more = u32::from(received) + 0x100;
        assert_eq!(
            parse_ipv4_udp(&header),
            Err(Error::InvalidChecksum {
                what: Part::Ipv4Header,
                received,
                computed: (more & 0xffff) as u16 + (more >> 16) as u16
            })
        );
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
            // The input ends in the header, or before the end that the
            // header says.
            let error = match length {
                ..20 => Error::Truncated {
                    what: Part::Ipv4Header,
                    needed: 20,
                    available: length,
                },
                _ => Error::Truncated {
                    what: Part::Ipv4Packet,
                    needed: 29,
                    available: length,
                },
            };
            assert_eq!(parse_ipv4_udp(&packet[..length]), Err(error));
        }
        // A packet whose total length ends inside the UDP header, and one
        // whose UDP length says more than the packet has, or less than a
        // header.
        let shorter = |total: u16, udp: u16| {
            let mut bytes = packet.clone();
            bytes[2..4].copy_from_slice(&total.to_be_bytes());
            bytes[24..26].copy_from_slice(&udp.to_be_bytes());
            bytes[10..12].copy_from_slice(&[0, 0]);
            let sum = checksum(&[&bytes[..20]]);
            bytes[10..12].copy_from_slice(&sum.to_be_bytes());
            parse_ipv4_udp(&bytes).unwrap_err()
        };
        assert_eq!(
            shorter(27, 9),
            Error::Truncated {
                what: Part::UdpHeader,
                needed: 8,
                available: 7
            }
        );
        assert_eq!(
            shorter(29, 10),
            Error::Truncated {
                what: Part::UdpDatagram,
                needed: 10,
                available: 9
            }
        );
        assert_eq!(
            shorter(29, 7),
            Error::InvalidLength {
                what: Part::UdpDatagram,
                length: 7,
                expected: 8
            }
        );
        assert_eq!(
            shorter(19, 9),
            Error::InvalidLength {
                what: Part::Ipv4Packet,
                length: 19,
                expected: 20
            }
        );
        let mut options = packet.clone();
        options[0] = 0x44;
        assert_eq!(
            parse_ipv4_udp(&options),
            Err(Error::InvalidLength {
                what: Part::Ipv4Header,
                length: 16,
                expected: 20
            })
        );
        let mut version = packet.clone();
        version[0] = 0x65;
        assert_eq!(
            parse_ipv4_udp(&version),
            Err(Error::UnexpectedPacket(Expected::Ipv4))
        );
        let mut fragment = packet.clone();
        fragment[6] |= 0x20; // More Fragments
        assert_eq!(
            parse_ipv4_udp(&fragment),
            Err(Error::UnexpectedPacket(Expected::Unfragmented))
        );
        let mut icmp = packet;
        icmp[9] = 1;
        assert_eq!(
            parse_ipv4_udp(&icmp),
            Err(Error::UnexpectedPacket(Expected::Udp))
        );
        // More than the Total Length holds.
        assert_eq!(
            ipv4_udp(source, source, &[0; 65508]),
            Err(Error::OutOfRange {
                what: Part::Ipv4Packet,
                value: 65536,
                max: 65535
            })
        );
        assert!(ipv4_udp(source, source, &[0; 65507]).is_ok());
    }
}
