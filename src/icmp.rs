//! The ICMP Echo Reply of the test UPF's echo service.

use std::net::Ipv4Addr;

use crate::ip::{checksum, header, parse, total_length};

const ICMP: u8 = 1;
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;

/// An IPv4 ICMP Echo message of `kind` (8 a request, 0 a reply).
fn echo(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    kind: u8,
    identifier_and_sequence: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    let total_length = total_length(20 + 8 + payload.len()).ok()?;
    let mut bytes = header(source, destination, ICMP, total_length);
    bytes.extend_from_slice(&[kind, 0, 0, 0]);
    bytes.extend_from_slice(identifier_and_sequence);
    bytes.extend_from_slice(payload);
    let icmp_checksum = checksum(&[&bytes[20..]]);
    bytes[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    Some(bytes)
}

/// The IPv4 ICMP Echo Reply to `request`, if it is an Echo Request whose
/// IPv4 header and ICMP checksums are valid.
pub(crate) fn echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    let packet = parse(request).ok()?;
    let icmp = packet.payload;
    let icmp_header = icmp.first_chunk::<8>()?;
    if packet.protocol != ICMP || icmp_header[..2] != [ECHO_REQUEST, 0] || checksum(&[icmp]) != 0 {
        return None;
    }
    echo(
        packet.destination,
        packet.source,
        ECHO_REPLY,
        &icmp_header[4..],
        &icmp[8..],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(payload: &[u8]) -> Vec<u8> {
        let (source, destination) = (Ipv4Addr::new(10, 60, 0, 2), Ipv4Addr::new(192, 0, 2, 1));
        echo(
            source,
            destination,
            ECHO_REQUEST,
            &[0x12, 0x34, 0, 7],
            payload,
        )
        .unwrap()
    }

    #[test]
    fn an_echo_request_has_its_reply() {
        let request = request(b"ping");
        let reply = echo_reply(&request).unwrap();
        // The addresses swapped, type 0, the identifier, sequence number and
        // data of the request, and valid checksums.
        assert_eq!(reply[12..16], request[16..20]);
        assert_eq!(reply[16..20], request[12..16]);
        assert_eq!(reply[20..22], [ECHO_REPLY, 0]);
        assert_eq!(reply[24..], request[24..]);
        assert_eq!(checksum(&[&reply[..20]]), 0);
        assert_eq!(checksum(&[&reply[20..]]), 0);
        // A reply, a UDP packet, a cut or a corrupt request have none.
        assert_eq!(echo_reply(&reply), None);
        let udp = crate::ip::udp(
            "10.60.0.2:1".parse().unwrap(),
            "192.0.2.1:2".parse().unwrap(),
            b"x",
        );
        assert_eq!(echo_reply(&udp.unwrap()), None);
        assert_eq!(echo_reply(&request[..27]), None);
        let mut corrupt = request.clone();
        corrupt[28] ^= 1;
        assert_eq!(echo_reply(&corrupt), None);
        let mut code = request.clone();
        code[21] = 1;
        let sum = checksum(&[&code[20..22], &code[24..]]);
        code[22..24].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(echo_reply(&code), None);
    }
}
