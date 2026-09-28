//! Checks the encoder against Wireshark's GTP dissector, an independent
//! reading of TS 29.281 and TS 38.415. Needs `tshark`:
//! `cargo test --test wireshark -- --ignored`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use oxirush_gtp_u::{
    DownlinkPduSessionInformation, ExtensionHeader, Packet, PduSessionContainer,
    UplinkPduSessionInformation, UplinkTimeStamps, ipv4_udp,
};

/// Dissect `packet`, sent in UDP to port 2152, and return `fields` as
/// tshark prints them, plus its expert info.
fn dissect(packet: &Packet, fields: &[&str]) -> (Vec<String>, String) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let gtp = packet.encode().unwrap();
    let ip = ipv4_udp(
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 2152),
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 2152),
        &gtp,
    )
    .unwrap();
    // A pcap file with one raw IPv4 packet (link type 101).
    let mut pcap = Vec::new();
    for word in [0xa1b2_c3d4u32, 0x0004_0002, 0, 0, 65535, 101] {
        pcap.extend_from_slice(&word.to_le_bytes());
    }
    let length = u32::try_from(ip.len()).unwrap();
    for word in [0, 0, length, length] {
        pcap.extend_from_slice(&word.to_le_bytes());
    }
    pcap.extend_from_slice(&ip);
    let path = std::env::temp_dir().join(format!(
        "oxirush-gtp-u-{}-{}.pcap",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, pcap).unwrap();
    let mut command = Command::new("tshark");
    command.arg("-r").arg(&path).args([
        "-T",
        "fields",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=,",
        "-e",
        "_ws.expert",
    ]);
    for field in fields {
        command.args(["-e", field]);
    }
    let output = command.output().expect("tshark must be installed");
    std::fs::remove_file(&path).unwrap();
    assert!(
        output.status.success(),
        "tshark: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = String::from_utf8(output.stdout).unwrap();
    let mut values: Vec<String> = line
        .trim_end_matches('\n')
        .split('\t')
        .map(str::to_owned)
        .collect();
    let expert = values.remove(0);
    (values, expert)
}

fn check(packet: &Packet, expected: &[(&str, &str)]) {
    let fields: Vec<&str> = expected.iter().map(|(field, _)| *field).collect();
    let (values, expert) = dissect(packet, &fields);
    assert_eq!(expert, "", "Wireshark reports a problem with {packet:?}");
    for ((field, want), got) in expected.iter().zip(&values) {
        assert_eq!(got, want, "{field} of {packet:?}");
    }
    assert_eq!(
        Packet::decode(&packet.encode().unwrap()).as_ref(),
        Ok(packet)
    );
}

#[test]
#[ignore = "needs tshark"]
fn path_management_messages() {
    check(
        &Packet::echo_request(5),
        &[
            ("gtp.flags", "0x32"),
            ("gtp.message", "0x01"),
            ("gtp.teid", "0x00000000"),
            ("gtp.seq_number", "0x0005"),
        ],
    );
    check(
        &Packet::echo_response(5),
        &[
            ("gtp.flags", "0x32"),
            ("gtp.message", "0x02"),
            ("gtp.seq_number", "0x0005"),
            ("gtp.recovery", "0"),
        ],
    );
    check(
        &Packet::supported_extension_headers_notification(&[
            ExtensionHeader::UDP_PORT,
            ExtensionHeader::PDU_SESSION_CONTAINER,
        ]),
        &[
            ("gtp.message", "0x1f"),
            ("gtp.num_ext_hdr_types", "2"),
            ("gtp.ext_hdr_type", "64,133"),
        ],
    );
}

#[test]
#[ignore = "needs tshark"]
fn tunnel_management_messages() {
    let mut indication = Packet::error_indication(42, Ipv4Addr::new(192, 0, 2, 2).into());
    indication
        .extension_headers
        .push(ExtensionHeader::UdpPort(40000));
    check(
        &indication,
        &[
            ("gtp.flags", "0x36"),
            ("gtp.message", "0x1a"),
            ("gtp.teid", "0x00000000"),
            ("gtp.ext_hdr.next", "0x40,0x00"),
            ("gtp.ext_hdr.udp_port", "40000"),
            ("gtp.teid_data", "0x0000002a"),
            ("gtp.gsn_ipv4", "192.0.2.2"),
        ],
    );
    check(
        &Packet::error_indication(7, "2001:db8::2".parse().unwrap()),
        &[
            ("gtp.teid_data", "0x00000007"),
            ("gtp.gsn_ipv6", "2001:db8::2"),
        ],
    );
    check(
        &Packet::end_marker(7),
        &[
            ("gtp.flags", "0x30"),
            ("gtp.message", "0xfe"),
            ("gtp.length", "0"),
            ("gtp.teid", "0x00000007"),
        ],
    );
}

#[test]
#[ignore = "needs tshark"]
fn g_pdus_with_a_pdu_session_container() {
    check(
        &Packet::uplink(0x1234_5678, 9, vec![0x45]),
        &[
            ("gtp.flags", "0x34"),
            ("gtp.message", "0xff"),
            ("gtp.length", "9"),
            ("gtp.teid", "0x12345678"),
            ("gtp.ext_hdr.next", "0x85,0x00"),
            ("gtp.ext_hdr.length", "1"),
            ("gtp.ext_hdr.pdu_ses_con.pdu_type", "1"),
            ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", "9"),
        ],
    );
    check(
        &Packet::downlink(1, 63, vec![0x60]),
        &[
            ("gtp.ext_hdr.pdu_ses_con.pdu_type", "0"),
            ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", "63"),
            ("gtp.ext_hdr.pdu_ses_cont.rqi", "False"),
            ("gtp.ext_hdr.pdu_ses_cont.ppp", "False"),
        ],
    );
}

#[test]
#[ignore = "needs tshark"]
fn every_downlink_field() {
    // 2020-01-01 00:00:00 UTC as a 64-bit NTP timestamp.
    let new_year = 3_786_825_600u64 << 32;
    let mut downlink = DownlinkPduSessionInformation::new(5);
    downlink.rqi = true;
    downlink.ppi = Some(3);
    downlink.dl_sending_time_stamp = Some(new_year);
    downlink.dl_qfi_sequence_number = Some(0x0a_0b0c);
    downlink.dl_mbs_qfi_sequence_number = Some(0x1122_3344);
    let mut packet = Packet::g_pdu(1, vec![]);
    packet
        .extension_headers
        .push(ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Downlink(downlink),
        ));
    let (values, expert) = dissect(&packet, &["gtp.ext_hdr.pdu_ses_cont.dl_send_time_stamp"]);
    assert_eq!(expert, "");
    // "2020-01-01T00:00:00.000000000Z", or "Jan  1, 2020 00:00:00…" before 4.4.
    assert!(
        values[0].contains("2020") && values[0].contains("00:00:00.000000000"),
        "{values:?}"
    );
    check(
        &packet,
        &[
            ("gtp.ext_hdr.length", "5"),
            ("gtp.ext_hdr.pdu_ses_con.qmp", "True"),
            ("gtp.ext_hdr.pdu_ses_con.snp", "True"),
            ("gtp.ext_hdr.pdu_ses_con.msnp", "True"),
            ("gtp.ext_hdr.pdu_ses_cont.ppp", "True"),
            ("gtp.ext_hdr.pdu_ses_cont.rqi", "True"),
            ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", "5"),
            ("gtp.ext_hdr.pdu_ses_cont.ppi", "3"),
            ("gtp.ext_hdr.pdu_ses_cont.dl_qfi_sn", "658188"),
            ("gtp.ext_hdr.pdu_ses_cont.dl_mbs_qfi_sn", "287454020"),
        ],
    );
}

#[test]
#[ignore = "needs tshark"]
fn every_uplink_field() {
    let mut uplink = UplinkPduSessionInformation::new(7);
    uplink.time_stamps = Some(UplinkTimeStamps {
        dl_sending_repeated: 1,
        dl_received: 2,
        ul_sending: 3,
    });
    uplink.dl_delay_result = Some(4);
    uplink.ul_delay_result = Some(5);
    uplink.ul_qfi_sequence_number = Some(6);
    uplink.n3_n9_delay_result = Some(7);
    uplink.d1_ul_pdcp_delay_result_ind = Some(true);
    let mut packet = Packet::g_pdu(1, vec![]);
    packet
        .extension_headers
        .push(ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Uplink(uplink),
        ));
    check(
        &packet,
        &[
            ("gtp.ext_hdr.pdu_ses_con.pdu_type", "1"),
            ("gtp.ext_hdr.pdu_ses_con.qmp", "True"),
            ("gtp.ext_hdr.pdu_ses_con.dl_delay_ind", "True"),
            ("gtp.ext_hdr.pdu_ses_con.ul_delay_ind", "True"),
            ("gtp.ext_hdr.pdu_ses_con.snp", "True"),
            ("gtp.ext_hdr.pdu_ses_con.n3_n9_delay_ind", "True"),
            ("gtp.ext_hdr.pdu_ses_con.new_ie_flag", "True"),
            ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", "7"),
            ("gtp.ext_hdr.pdu_ses_cont.dl_delay_result", "4"),
            ("gtp.ext_hdr.pdu_ses_cont.ul_delay_result", "5"),
            ("gtp.ext_hdr.pdu_ses_cont.ul_qfi_sn", "6"),
            ("gtp.ext_hdr.pdu_ses_cont.n3_n9_delay_result", "7"),
            ("gtp.ext_hdr.pdu_ses_cont.new_ie_flag_0", "True"),
            (
                "gtp.ext_hdr.pdu_ses_cont.d1_ul_pdcp_delay_result_ind",
                "True",
            ),
        ],
    );
}

/// Wireshark stops after the D1 UL PDCP Delay Result Ind, but reads the
/// New IE Flags of the congestion information.
#[test]
#[ignore = "needs tshark"]
fn uplink_congestion_information_flags() {
    let mut uplink = UplinkPduSessionInformation::new(7);
    uplink.ul_congestion_information = Some(9574);
    uplink.dl_congestion_information = Some(1000);
    let mut packet = Packet::g_pdu(1, vec![]);
    packet
        .extension_headers
        .push(ExtensionHeader::PduSessionContainer(
            PduSessionContainer::Uplink(uplink),
        ));
    check(
        &packet,
        &[
            ("gtp.ext_hdr.pdu_ses_con.new_ie_flag", "True"),
            ("gtp.ext_hdr.pdu_ses_cont.new_ie_flag_0", "False"),
            ("gtp.ext_hdr.pdu_ses_cont.new_ie_flag_1", "True"),
            ("gtp.ext_hdr.pdu_ses_cont.new_ie_flag_2", "True"),
            ("gtp.ext_hdr.pdu_ses_cont.new_ie_flag_7", "False"),
        ],
    );
}

#[test]
#[ignore = "needs tshark"]
fn optional_fields_and_an_extension_header_chain() {
    let mut packet = Packet::g_pdu(3, vec![0xaa]);
    packet.sequence = Some(0x0102);
    packet.n_pdu_number = Some(0x33);
    packet.extension_headers = vec![
        ExtensionHeader::UdpPort(2152),
        ExtensionHeader::PduSessionContainer(PduSessionContainer::downlink(1)),
        ExtensionHeader::Other {
            kind: ExtensionHeader::LONG_PDCP_PDU_NUMBER,
            content: vec![0x01, 0x02, 0x03, 0x00, 0x00, 0x00],
        },
    ];
    check(
        &packet,
        &[
            ("gtp.flags", "0x37"),
            ("gtp.seq_number", "0x0102"),
            ("gtp.npdu_number", "0x33"),
            ("gtp.ext_hdr.next", "0x40,0x85,0x03,0x00"),
            ("gtp.ext_hdr.length", "1,1,2"),
            ("gtp.ext_hdr.udp_port", "2152"),
            ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", "1"),
        ],
    );
    // tshark 4.6 decodes the content of the legacy type only.
    packet.extension_headers[2] = ExtensionHeader::Other {
        kind: ExtensionHeader::LONG_PDCP_PDU_NUMBER_LEGACY,
        content: vec![0x01, 0x02, 0x03, 0x00, 0x00, 0x00],
    };
    check(
        &packet,
        &[
            ("gtp.ext_hdr.next", "0x40,0x85,0x82,0x00"),
            ("gtp.ext_hdr.long_pdcp_sn", "66051"),
        ],
    );
}
