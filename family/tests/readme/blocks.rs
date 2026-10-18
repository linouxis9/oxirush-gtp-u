// The blocks of the README that use other crates of the family, each as a
// function. `tests/readme.rs` writes this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what the README shows.
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
];

/// The block 1 of the README that uses other crates.
fn block_1() {
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel, ipv4_udp};
    use oxirush_ngap::ngap::*;
    use oxirush_ngap::{extract_ngap_ies, tree};
    use std::net::SocketAddr;

    #[tokio::main(flavor = "current_thread")]
    async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let (upf, mut observed) = UpfSimulator::bind("127.0.0.12:2152".parse()?).await?;
        let (gnb, mut received) = Endpoint::bind("127.0.0.11:2152".parse()?).await?;

        // The AMF: a PDU SESSION RESOURCE SETUP REQUEST, whose transfer has the
        // UPF's end of the tunnel and the QoS flow of the session
        let qos = tree!({
            "qosCharacteristics": {"nonDynamic5QI": {"fiveQI": 9}},
            "allocationAndRetentionPriority": {
                "priorityLevelARP": 8,
                "pre-emptionCapability": "shall-not-trigger-pre-emption",
                "pre-emptionVulnerability": "not-pre-emptable",
            },
        });
        let request = NGAP_PDU::from_tree(&tree!({"message": "PDUSessionResourceSetupRequest", "ies": [
            {"AMF-UE-NGAP-ID": 1},
            {"RAN-UE-NGAP-ID": 7},
            {"PDUSessionResourceSetupListSUReq": [{
                "pDUSessionID": 5,
                "s-NSSAI": {"sST": 1},
                "pDUSessionResourceSetupRequestTransfer": {"protocolIEs": [
                    {"UL-NGU-UP-TNLInformation": {
                        "gTPTunnel": {"transportLayerAddress": "127.0.0.12", "gTP-TEID": 4097},
                    }, "criticality": "reject"},
                    {"PDUSessionType": "ipv4", "criticality": "reject"},
                    {"QosFlowSetupRequestList": [
                        {"qosFlowIdentifier": 9, "qosFlowLevelQosParameters": qos},
                    ], "criticality": "reject"},
                ]},
            }]},
        ]}))?;

        // The gNB: the session, then the tunnel and the QoS flow in its transfer
        extract_ngap_ies!(request, PDUSessionResourceSetupRequest,
            req ran_id: u32 = RAN_UE_NGAP_ID(id),
            req sessions: PDUSessionResourceSetupListSUReq = PDUSessionResourceSetupListSUReq(list) => list,
        );
        let item = &sessions.0[0];
        let session = item.pdu_session_id.0;
        let transfer: PDUSessionResourceSetupRequestTransfer =
            decode_open_type(&item.pdu_session_resource_setup_request_transfer)?;
        extract_ngap_ies!(transfer, PDUSessionResourceSetupRequestTransfer,
            req uplink: UPTransportLayerInformation = UL_NGU_UP_TNLInformation(tunnel) => tunnel,
            req flows: QosFlowSetupRequestList = QosFlowSetupRequestList(flows) => flows,
        );
        let UPTransportLayerInformation::gTPTunnel(tunnel) = uplink else {
            unreachable!()
        };
        let address: [u8; 4] = tunnel.transport_layer_address.0.as_octets().try_into()?;
        let remote = RemoteTunnel::new(SocketAddr::from((address, 2152)), u32::from_be_bytes(tunnel.gtp_teid.0));
        let qfi = u8::try_from(flows.0[0].qos_flow_identifier.0)?;
        let teid = gnb.install(ran_id, session, remote, qfi)?;
        println!("RAN UE {ran_id} session {session}: to {} TEID {:#x}, QFI {qfi}", remote.address, remote.teid);

        // The gNB's end of the tunnel, in the PDU SESSION RESOURCE SETUP RESPONSE
        let response = NGAP_PDU::from_tree(&tree!({"message": "PDUSessionResourceSetupResponse", "ies": [
            {"AMF-UE-NGAP-ID": 1},
            {"RAN-UE-NGAP-ID": ran_id},
            {"PDUSessionResourceSetupListSURes": [{
                "pDUSessionID": session,
                "pDUSessionResourceSetupResponseTransfer": {"dLQosFlowPerTNLInformation": {
                    "uPTransportLayerInformation": {
                        "gTPTunnel": {"transportLayerAddress": "127.0.0.11", "gTP-TEID": teid},
                    },
                    "associatedQosFlowList": [{"qosFlowIdentifier": qfi}],
                }},
            }]},
        ]}))?;
        println!("PDU SESSION RESOURCE SETUP RESPONSE, {} deviations", response.check()?.len());

        // The UPF has the session from its control plane, and a packet of the UE
        // goes up the tunnel and back
        upf.set_session(Session::new(remote.teid, teid, gnb.local_addr()?, qfi))?;
        let packet = ipv4_udp("10.45.0.2:4000".parse()?, "192.0.2.1:7".parse()?, b"hello")?;
        gnb.send(ran_id, session, packet).await?;
        let uplink = observed.recv().await.expect("the UPF is running");
        let downlink = received.recv().await.expect("the endpoint is running");
        println!("UPF: TEID {:#x}, QFI {:?}", uplink.uplink_teid, uplink.packet.qfi());
        println!("gNB: RAN UE {} session {}", downlink.ran_id, downlink.session_id);
        Ok(())
    }
    main().unwrap();
}
