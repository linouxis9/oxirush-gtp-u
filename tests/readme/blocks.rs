// The Rust blocks of the README and of the documentation, each as a function.
// `tests/readme.rs` writes this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what its page shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    // The line is made first, where the block is: its arguments may have a
    // `?` or an `await`.
    ($($argument:tt)*) => {{
        let line = format!($($argument)*);
        PRINTED.with(|printed| {
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    }};
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

pub const BLOCKS: &[fn()] = &[
    block_1,
    block_2,
    block_3,
    block_4,
    block_5,
    block_6,
];

/// The Rust block 1 of README.md.
fn block_1() {
    use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};

    fn main() -> Result<(), oxirush_gtp_u::Error> {
        // An uplink G-PDU of QoS flow 9, as a gNB sends it on N3: the header,
        // the PDU Session Container, then the IP packet
        let uplink = Packet::uplink(0x1234_5678, 9, b"an IP packet".as_slice());
        let bytes = uplink.encode()?;
        println!("{:02x?}", &bytes[..16]);

        // Decode it. The payload stays in the datagram
        let decoded = Packet::decode_borrowed(&bytes)?;
        println!("TEID {:#x}, QFI {:?}", decoded.teid, decoded.qfi());
        println!("{:?}", String::from_utf8_lossy(decoded.payload));

        // A downlink G-PDU whose container has more than a QFI
        let mut information = DownlinkPduSessionInformation::new(9);
        information.rqi = true;
        let downlink = Packet::g_pdu(0x9abc_def0, b"an IP packet".as_slice())
            .with_pdu_session_container(PduSessionContainer::Downlink(information));
        let decoded = Packet::decode(&downlink.encode()?)?;
        if let Some(PduSessionContainer::Downlink(information)) = decoded.pdu_session_container() {
            println!("QFI {}, RQI {}", information.qfi, information.rqi);
        }
        Ok(())
    }
    main().unwrap();
}

/// The Rust block 2 of README.md.
fn block_2() {
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel, ipv4_udp, parse_ipv4_udp};

    #[tokio::main(flavor = "current_thread")]
    async fn main() -> std::io::Result<()> {
        let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
        let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;

        // What the control plane negotiates: the UPF receives the session's
        // uplink on TEID 0x1001, the gNB its downlink on the TEID it assigns
        // to RAN UE 1, PDU session 5
        let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
        upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9));

        // Uplink: an IP packet of the UE, which the UPF's echo service reflects
        let ue = "10.45.0.2:4000".parse().unwrap();
        let server = "192.0.2.1:7".parse().unwrap();
        gnb.send(1, 5, ipv4_udp(ue, server, b"hello")?).await?;
        let uplink = observed.recv().await.expect("the UPF is running");
        println!(
            "UPF: TEID {:#x}, QFI {:?}",
            uplink.uplink_teid,
            uplink.packet.qfi()
        );

        // Downlink: the reply, with the tunnel it arrived on
        let downlink = received.recv().await.expect("the endpoint is running");
        let (from, to, payload) = parse_ipv4_udp(&downlink.packet.payload)?;
        println!(
            "gNB: RAN UE {} session {}, QFI {:?}: {from} to {to}",
            downlink.ran_id,
            downlink.session_id,
            downlink.packet.qfi()
        );
        assert_eq!((from, to, payload), (server, ue, b"hello".as_slice()));
        Ok(())
    }
    main().unwrap();
}

/// The Rust block 3 of README.md.
fn block_3() {
    use oxirush_gtp_u::upf_sim::UpfSimulator;
    use oxirush_gtp_u::{Endpoint, Packet, RemoteTunnel};

    #[tokio::main(flavor = "current_thread")]
    async fn main() -> std::io::Result<()> {
        // An Error Indication goes to port 2152 of the sender of the G-PDU
        let (gnb, mut received) = Endpoint::bind("127.0.0.9:2152".parse().unwrap()).await?;
        let (upf, _observed) = UpfSimulator::bind("127.0.0.10:2152".parse().unwrap()).await?;

        // An endpoint answers an Echo Request by itself
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let request = Packet::echo_request(7).encode()?;
        peer.send_to(&request, gnb.local_addr()?).await?;
        let mut buffer = [0; 64];
        let (length, _) = peer.recv_from(&mut buffer).await?;
        let response = Packet::decode(&buffer[..length])?;
        println!(
            "{}, sequence number {:?}, {:?}",
            response.message_type,
            response.sequence,
            response.information_elements()?
        );

        // The UPF has no session with TEID 0x1001. It answers the G-PDU with an
        // Error Indication, which the receiver gets with its tunnel
        gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
        gnb.send(1, 5, b"an IP packet".as_slice()).await?;
        let indication = received.recv().await.expect("the endpoint is running");
        println!(
            "{} for RAN UE {} session {}: {:?}",
            indication.packet.message_type,
            indication.ran_id,
            indication.session_id,
            indication.packet.information_elements()?
        );
        Ok(())
    }
    main().unwrap();
}

/// The Rust block 4 of README.md.
fn block_4() {
    use oxirush_gtp_u::{ExtensionHeader, ExtensionHeaderType, Packet};

    fn main() -> Result<(), oxirush_gtp_u::Error> {
        // The container of an uplink G-PDU, then a header of a type that the
        // crate keeps as octets
        let mut packet = Packet::uplink(0x1234_5678, 9, b"an IP packet".to_vec());
        packet.extension_headers.push(ExtensionHeader::Other {
            kind: ExtensionHeaderType(0x21),
            content: vec![7, 0],
        });

        // A decoded message has them in their order
        let decoded = Packet::decode(&packet.encode()?)?;
        for header in &decoded.extension_headers {
            let required = header.comprehension_required();
            println!("{}, comprehension required: {required}", header.kind());
        }
        println!("{:?}", decoded.extension_headers[1]);
        Ok(())
    }
    main().unwrap();
}

/// The Rust block 5 of README.md.
fn block_5() {
    use oxirush_gtp_u::{ExtensionHeader, Packet, PduSessionContainer};

    fn main() -> Result<(), oxirush_gtp_u::Error> {
        // A downlink packet that the source gNB forwards to the target, with
        // the PDCP sequence number that it had given it
        let mut forwarded = Packet::downlink(0x2001, 9, b"an IP packet".to_vec());
        let number = ExtensionHeader::PdcpPduNumber(0x0abc);
        forwarded.extension_headers.push(number);
        println!("{:02x?}", &forwarded.encode()?[8..20]);

        // A sequence number of 18 bits has the long header
        let mut long = Packet::downlink(0x2001, 9, b"an IP packet".to_vec());
        long.extension_headers
            .push(ExtensionHeader::LongPdcpPduNumber {
                number: 0x2_abcd,
                legacy_type: false,
            });
        println!("{:02x?}", &long.encode()?[8..24]);

        // The End Marker of a forwarding tunnel between 5GS and EPS has the PDU
        // Session Container
        let container = PduSessionContainer::downlink(9);
        let marker = Packet::end_marker(0x2001).with_pdu_session_container(container);
        println!("{:02x?}", marker.encode()?);

        // The target reads the headers of what it receives
        let decoded = Packet::decode(&forwarded.encode()?)?;
        for header in &decoded.extension_headers {
            match header {
                ExtensionHeader::PdcpPduNumber(number) => println!("PDCP PDU Number {number:#x}"),
                other => println!("{}", other.kind()),
            }
        }
        Ok(())
    }
    main().unwrap();
}

/// The Rust block 1 of src/lib.rs.
fn block_6() {
    use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};

    fn main() -> Result<(), oxirush_gtp_u::Error> {
        // An uplink G-PDU of QoS flow 9, as a gNB sends it on N3: the header,
        // the PDU Session Container, then the IP packet
        let uplink = Packet::uplink(0x1234_5678, 9, b"an IP packet".as_slice());
        let bytes = uplink.encode()?;
        println!("{:02x?}", &bytes[..16]);

        // Decode it. The payload stays in the datagram
        let decoded = Packet::decode_borrowed(&bytes)?;
        println!("TEID {:#x}, QFI {:?}", decoded.teid, decoded.qfi());
        println!("{:?}", String::from_utf8_lossy(decoded.payload));

        // A downlink G-PDU whose container has more than a QFI
        let mut information = DownlinkPduSessionInformation::new(9);
        information.rqi = true;
        let downlink = Packet::g_pdu(0x9abc_def0, b"an IP packet".as_slice())
            .with_pdu_session_container(PduSessionContainer::Downlink(information));
        let decoded = Packet::decode(&downlink.encode()?)?;
        if let Some(PduSessionContainer::Downlink(information)) = decoded.pdu_session_container() {
            println!("QFI {}, RQI {}", information.qfi, information.rqi);
        }
        Ok(())
    }
    main().unwrap();
}
