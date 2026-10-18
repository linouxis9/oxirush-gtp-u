# oxirush-gtp-u

[![Crates.io](https://img.shields.io/crates/v/oxirush-gtp-u.svg)](https://crates.io/crates/oxirush-gtp-u)
[![Documentation](https://docs.rs/oxirush-gtp-u/badge.svg)](https://docs.rs/oxirush-gtp-u)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

GTP-U, the protocol that tunnels user traffic in 5G and 4G networks, in
Rust, per 3GPP TS 29.281: a codec, an endpoint for the tunnels of a base
station, a UPF to test against, Linux TUN devices and an eBPF fast path.

```rust
use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
```

```text
[34, ff, 00, 14, 12, 34, 56, 78, 00, 00, 00, 85, 01, 10, 09, 00]
TEID 0x12345678, QFI Some(9)
"an IP packet"
QFI 9, RQI true
```

The text under a block is what the block prints.

This page describes oxirush-gtp-u 0.1.0, which is not on crates.io yet.

## Installation

```toml
[dependencies]
oxirush-gtp-u = "0.1"
tokio = { version = "1", features = ["macros", "rt", "net"] } # for the endpoint
# The codec alone, without a dependency:
# oxirush-gtp-u = { version = "0.1", default-features = false }
```

| Feature | Adds | Needs |
| ------- | ---- | ----- |
| none | the codec and the IPv4 helpers | no dependency |
| `endpoint`, the default | `Endpoint`, `upf_sim` | a Tokio runtime |
| `tun` | `tun`, and `attach_tun` of `Endpoint` and `UpfSimulator` | Linux, `CAP_NET_ADMIN` |
| `ebpf` | `ebpf` | Linux 6.6, `CAP_BPF` and `CAP_NET_ADMIN` |
| `serde` | `Serialize` and `Deserialize` for `RemoteTunnel` | |
| `cli` | the `oxirush-upf-sim` program | |

`ebpf` brings `tun`, and `tun`, `serde` and `cli` bring `endpoint`. Off
Linux, `tun` and `ebpf` build and add nothing, and so does `ebpf` on 32-bit
x86, which aya does not build for, and on big-endian architectures. The
eBPF programs are committed as an object: a build with `ebpf` needs no
nightly toolchain and no eBPF linker.

Until 0.1.0 is on crates.io, a program takes the crate from its repository:

```toml
[dependencies]
oxirush-gtp-u = { git = "https://github.com/linouxis9/oxirush-gtp-u" }
```

The minimum supported Rust version is 1.88.

## Carry a PDU session between a gNB and the test UPF

`Endpoint` is the N3 socket of a gNB, or the S1-U socket of an eNB, for
labs and test tools. A call gives a tunnel the TEIDs (Tunnel Endpoint
Identifiers), the addresses and the QoS flow that NGAP, S1AP or PFCP
would negotiate.

```rust
use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{Endpoint, PathEvent, RemoteTunnel, ipv4_udp, parse_ipv4_udp};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse()?).await?;
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse()?).await?;

    // What the control plane negotiates: the UPF receives the session's
    // uplink on TEID 0x1001, the gNB its downlink on the TEID it assigns
    // to RAN UE 1, PDU session 5, whose QoS flow is 9
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

    // Uplink: an IP packet of the UE, which the UPF's echo service reflects
    let ue = "10.45.0.2:4000".parse()?;
    let server = "192.0.2.1:7".parse()?;
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

    // The gNB asks whether its path to the UPF is alive, then supervises it:
    // `path_state` and `path_events` say when it goes down, and up again
    let mut events = gnb.path_events();
    gnb.echo(upf.local_addr()?).await?;
    if let Ok(PathEvent::EchoResponse { packet, .. }) = events.recv().await {
        println!("Echo Response: {:?}", packet.information_elements()?);
    }
    gnb.supervise(upf.local_addr()?)?;
    let state = gnb.path_state(upf.local_addr()?).expect("supervised");
    println!("path up: {}, unanswered: {}", state.up, state.unanswered);
    Ok(())
}
```

```text
UPF: TEID 0x1001, QFI Some(9)
gNB: RAN UE 1 session 5, QFI Some(9): 192.0.2.1:7 to 10.45.0.2:4000
Echo Response: [Recovery(0)]
path up: true, unanswered: 0
```

## Take the tunnel from NGAP

The TEIDs and the QoS flow of a tunnel come from the PDU SESSION RESOURCE
SETUP of NGAP, which
[oxirush-ngap](https://github.com/linouxis9/oxirush-ngap) decodes: the
request has the UPF's end of the tunnel in its transfer, and the response
gives the AMF the gNB's.

```rust,ignore
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
```

```text
RAN UE 7 session 5: to 127.0.0.12:2152 TEID 0x1001, QFI 9
PDU SESSION RESOURCE SETUP RESPONSE, 0 deviations
UPF: TEID 0x1001, QFI Some(9)
gNB: RAN UE 7 session 5
```

## Answer a peer: Echo and Error Indication

```rust
use oxirush_gtp_u::upf_sim::UpfSimulator;
use oxirush_gtp_u::{Endpoint, Packet, RemoteTunnel};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // An Error Indication goes to port 2152 of the sender of the G-PDU
    let (gnb, mut received) = Endpoint::bind("127.0.0.9:2152".parse()?).await?;
    let (upf, _observed) = UpfSimulator::bind("127.0.0.10:2152".parse()?).await?;

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
```

```text
Echo Response, sequence number Some(7), [Recovery(0)]
Error Indication for RAN UE 1 session 5: [TeidDataI(0x00001001), GtpUPeerAddress(127.0.0.10)]
```

An endpoint also sends an Error Indication for a G-PDU on a TEID that it
does not have. Whoever reaches the socket can send such G-PDUs, and Echo
Requests, from any address: an address gets 100 Error Indications a second
at most and 10 Echo Responses, and all addresses together 1,000 Error
Indications. `stats()` counts the replies that were not sent, the G-PDUs on
unknown TEIDs and the Error Indications that name no tunnel.

## Read and write extension headers

```rust
use oxirush_gtp_u::{ExtensionHeader, ExtensionHeaderType, Packet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Sent on with another TEID and QoS flow
    let mut forwarded = decoded;
    forwarded.teid = 0x9abc_def0;
    forwarded.set_qfi(5);
    println!("{:02x?}", &forwarded.encode()?[4..16]);
    Ok(())
}
```

```text
PDU Session Container, comprehension required: true
0x21, comprehension required: false
Other { kind: ExtensionHeaderType(0x21), content: 2 octets 0700 }
[9a, bc, de, f0, 00, 00, 00, 85, 01, 10, 05, 21]
```

Every extension header of TS 29.281 V19.2.0 has a variant; one of another
type is kept as its octets, `Other`. An endpoint delivers a message with
the headers that have a variant. It refuses one with a header that is kept
as octets and that a receiver must understand, as the specification
requires, and answers a G-PDU or an Echo Request that has one with the
list of the types that it knows. `examples/handover.rs` writes the headers
of a handover: the PDCP PDU Number of a forwarded packet, the long one, and
the End Marker of a forwarding tunnel.

## Give a tunnel a TUN

With the `tun` feature, on Linux, what a socket bound to the UE's address
sends is routed into the tunnel.

```rust,no_run
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::Ipv4Addr;

    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse()?).await?;
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse()?).await?;
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

    // The tunnel gets a TUN with the UE's address, and a rule that routes
    // what is sent from that address into it. The endpoint carries the
    // TUN's packets both ways, and closes the TUN with the tunnel.
    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    gnb.attach_tun(1, 5, TunConfig::new("ue0", routing))?;

    // A socket bound to the UE's address now goes through the tunnel. The
    // test UPF's echo service answers for any destination.
    let socket = tokio::net::UdpSocket::bind((ue, 0)).await?;
    socket.send_to(b"hello", "192.0.2.1:7").await?;
    let mut reply = [0; 16];
    let (length, from) = socket.recv_from(&mut reply).await?;
    let reply = String::from_utf8_lossy(&reply[..length]);
    println!("{from} answered {reply:?}");
    Ok(())
}
```

```text
192.0.2.1:7 answered "hello"
```

It creates an interface and a routing rule, which needs `CAP_NET_ADMIN`.
A user namespace and a network namespace of its own give it that without
root, and keep them off the host:

```sh
cargo build --features tun --example tun
unshare --user --map-root-user --net sh -c 'ip link set lo up && target/debug/examples/tun'
```

Where users may not make user namespaces, as Ubuntu restricts them, `sudo
unshare --net` does it in the place of `unshare --user --map-root-user
--net`.

## Carry the tunnel in the kernel

With the `ebpf` feature, on Linux 6.6, eBPF programs carry the packets of a
tunnel between its TUN and the network. The endpoint gets them before its
tunnels are installed, and `attach_tun` does the rest:

```rust,no_run
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::Ipv4Addr;

    use oxirush_gtp_u::ebpf::FastPath;
    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse()?).await?;
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse()?).await?;

    // Load the programs and give them to the endpoint before its tunnels:
    // installing a tunnel then prepares the interface it is routed through.
    let fast_path = FastPath::load()?;
    gnb.set_fast_path(fast_path.clone())?;

    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

    // As in the `tun` example. The endpoint has a fast path: the TUN is on
    // it, and the kernel carries the tunnel's packets.
    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    gnb.attach_tun(1, 5, TunConfig::new("ue0", routing))?;

    let socket = tokio::net::UdpSocket::bind((ue, 0)).await?;
    for _ in 0..5 {
        socket.send_to(b"hello", "192.0.2.1:7").await?;
        socket.recv_from(&mut [0; 16]).await?;
    }
    // What the programs carried. Userspace carries the first packets when
    // the tunnel's interface is still getting its program.
    println!("{:?}", fast_path.stats());
    Ok(())
}
```

Loading the programs needs root. The program is `examples/fast_path.rs`:

```sh
cargo build --features ebpf --example fast_path
sudo unshare --net sh -c 'ip link set lo up && target/debug/examples/fast_path'
```

## Run the test UPF as a program

The arguments are the N3 address of the UPF, that of the gNB, the uplink
TEID, the downlink TEID, decimal or hexadecimal, and the QFI. It serves that
session with an echo service, or as root with a TUN.

```sh
cargo run --features cli --bin oxirush-upf-sim -- 127.0.0.8:2152 127.0.0.1:2152 0x1001 0x2001 9

cargo build --features cli,tun --bin oxirush-upf-sim
sudo ./target/debug/oxirush-upf-sim \
  127.0.0.8:2152 127.0.0.1:2152 0x1001 0x2001 9 --tun oxupf0 10.45.0.2
```

## Limits

- Control plane: it has no NGAP, S1AP or PFCP.
- Untrusted peers: the endpoint and the test UPF are for labs and test
  tools. GTP-U has no authentication: whoever reaches a socket can send on
  its tunnels.
- A UPF for real traffic: the test UPF has no PFCP, QoS or charging.
- GTP' and the versions 0 and 2 of GTP.
- IPv6 in the helpers, the TUN routing and the fast path. The codec and the
  endpoint carry any payload.

## Performance

On one core of an AMD Ryzen 7 5700G (16 threads, Linux 7.0, Rust 1.98.1),
at 0d25889, measured on a quiet machine on 2026-10-18, a G-PDU with its PDU
Session Container and 1,400 octets of payload, the lowest of five runs:

| | Time |
|---|---|
| Build the G-PDU and encode it into a buffer that is used again | 45 ns |
| Decode, the payload left in the datagram | 22 ns |
| Decode, the payload copied | 57 ns |
| From an endpoint to the test UPF and back, over the loopback interface | 12.9 µs |

A message with one extension header at most is decoded without an
allocation. [`benches/`](benches/README.md)
has the benchmarks, the other figures and how to profile.

### Against go-gtp

[go-gtp](https://github.com/wmnsk/go-gtp) v0.8.12 on the same G-PDUs of
1,400 octets, built before they are timed, each program on core 2 of the
same machine (Go 1.27), at 0d25889. Times are the lowest of three runs,
and each figure the median of three runs of the script. Cycles and
instructions are per operation, from `perf stat`, user and kernel. Peak
memory is that of the whole program. The last column is the time of go-gtp
over this crate's, "about the same" where it is within the spread of the
three runs of its operation, 3 % at most.

| Operation | | ns | Cycles | Instructions | Allocations | Octets allocated | Peak memory | go-gtp / this crate |
|---|---|---|---|---|---|---|---|---|
| Encode, no extension header | oxirush-gtp-u | 17.8 | 82 | 305 | 0 | 0 | 2.6 MiB | |
| | go-gtp | 17.7 | 80 | 338 | 0 | 0 | 5.5 MiB | about the same |
| Encode, PDU Session Container | oxirush-gtp-u | 25.8 | 116 | 472 | 0 | 0 | 2.6 MiB | |
| | go-gtp | 26.1 | 117 | 525 | 0 | 0 | 5.5 MiB | 1.01x |
| Decode, no extension header | oxirush-gtp-u | 10.8 | 48 | 127 | 0 | 0 | 2.7 MiB | |
| | go-gtp | 4.1 | 18 | 88 | 0 | 0 | 5.4 MiB | 0.38x |
| Decode, PDU Session Container | oxirush-gtp-u | 24.0 | 110 | 251 | 0 | 0 | 2.7 MiB | |
| | go-gtp | 43.9 | 204 | 864 | 2 | 56 | 10.2 MiB | 1.83x |
| Endpoint to endpoint and back, no extension header, loopback | oxirush-gtp-u | 12,078 | 56,106 | 39,975 | 2 | 2,807 | 3.0 MiB | |
| | go-gtp | 23,900 | 109,192 | 85,322 | 82 | 8,736 | 10.3 MiB | 1.98x |

`decode_borrowed` returns a `Packet` of 136 octets, with room for one
extension header whether the message has one or not.
`benches/compare.sh 3` runs every row on core 3, and fetches go-gtp at the
version that it pins; perf may need `PERF="sudo -n perf"`.

## Tests and fuzzing

```sh
cargo test --all-features
# The TUN, each test in a network namespace of its own: in a user namespace,
# without root, or with sudo as the runner
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="unshare --user --map-root-user --net --" \
  cargo test --features tun --test tun_linux --test tun_cleanup -- --ignored
# As root, the fast path (Linux 6.6)
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo \
  cargo test --features ebpf --test ebpf_linux -- --ignored
# The encoder against Wireshark's dissector, with tshark 4.4 or later
cargo test --test wireshark -- --ignored
```

Property tests and a `cargo fuzz` target check that decoding never panics
and that what decodes encodes to a message that decodes to the same value.
CI rebuilds the eBPF object from its source and compares. The Rust blocks of
this page are checked with what they print
([`tests/readme.rs`](tests/readme.rs)). The blocks that use other crates of
the family run in the package of [`family/`](family/), which takes those
crates at the revisions that its manifest names.

[The documentation](https://docs.rs/oxirush-gtp-u) has the terms, what the
codec covers, and the reference of the endpoint, the test UPF, the TUN
routings and the fast path.

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.

## The OxiRush family

- [oxirush-utils](https://github.com/linouxis9/oxirush-utils): the 3GPP identities, and the JSON tree with its paths that the others share.
- [oxirush-aper](https://github.com/linouxis9/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
- [oxirush-nas](https://github.com/linouxis9/oxirush-nas): the NAS messages of 5GS and EPS.
- [oxirush-security](https://github.com/linouxis9/oxirush-security): NAS security, AKA and the derivation of keys.
- [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap): NGAP, between a gNB and an AMF.
- [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap): S1AP, between an eNB and an MME.
- [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u): GTP-U tunnels, with a test UPF.
- [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.

## License

Copyright 2025-2026 Valentin D'Emmanuele. Licensed under the Apache License,
Version 2.0: see [LICENSE](LICENSE).
