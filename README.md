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

Each example is followed by its output.

## Installation

```toml
[dependencies]
oxirush-gtp-u = "0.2"
tokio = { version = "1", features = ["macros", "rt", "net"] } # for the endpoint
# The codec alone, without a dependency:
# oxirush-gtp-u = { version = "0.2", default-features = false }
```

| Feature | Adds | Needs |
| ------- | ---- | ----- |
| none | the codec and the IPv4 helpers of `ip` | no dependency |
| `endpoint`, the default | `Endpoint`, `upf_sim` | a Tokio runtime |
| `tun` | `tun`, and `attach_tun` of `Endpoint` and `UpfSimulator` | Linux, `CAP_NET_ADMIN` |
| `ebpf` | `ebpf` | Linux 6.6, `CAP_BPF` and `CAP_NET_ADMIN` |

`ebpf` turns on `tun`, and `tun` turns on `endpoint`.
Off Linux, `tun` and `ebpf` build and add nothing; so does `ebpf` on 32-bit
x86 and on big-endian targets. The eBPF programs come prebuilt: a build
with `ebpf` needs no nightly toolchain and no eBPF linker.

The minimum supported Rust version is 1.88.

## Carry a PDU session between a gNB and the test UPF

`Endpoint` is the N3 socket of a gNB, or the S1-U socket of an eNB, for
labs and test tools. You give each tunnel the TEIDs (Tunnel Endpoint
Identifiers), the addresses and the QoS flow that NGAP, S1AP or PFCP would
negotiate.

```rust
use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{Endpoint, PathEvent, RemoteTunnel, ip};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse()?).await?;
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse()?).await?;

    // What the control plane negotiates: the UPF receives the session's
    // uplink on TEID 0x1001, the gNB its downlink on the TEID it assigns
    // to RAN UE 1, PDU session 5, whose QoS flow is 9
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), Some(9))?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

    // Uplink: an IP packet of the UE, which the UPF's echo service reflects
    let ue = "10.45.0.2:4000".parse()?;
    let server = "192.0.2.1:7".parse()?;
    gnb.send(1, 5, ip::udp(ue, server, b"hello")?).await?;
    let uplink = observed.recv().await.expect("the UPF is running");
    println!(
        "UPF: TEID {:#x}, QFI {:?}",
        uplink.uplink_teid,
        uplink.packet.qfi()
    );

    // Downlink: the reply, with the tunnel it arrived on
    let downlink = received.recv().await.expect("the endpoint is running");
    let (from, to, payload) = ip::parse_udp(&downlink.packet.payload)?;
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

The TEIDs, the addresses and the QoS flow of a tunnel come from the
control plane: in 5G, the PDU SESSION RESOURCE SETUP of NGAP, which
[oxirush-ngap](https://github.com/linouxis9/oxirush-ngap) decodes.

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
    gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), Some(9))?;
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

An endpoint, too, answers a G-PDU on a TEID it does not have with an Error
Indication. Since anyone who reaches the socket can send such G-PDUs
and Echo Requests from any address, the replies are limited: a socket sends
at most 1,000 Error Indications, Supported Extension Headers Notifications
and Echo Responses a second, after a burst of 1,000. `stats()` counts the
replies that were not sent, the G-PDUs on unknown TEIDs and the Error
Indications that name no tunnel.

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

Every extension header of TS 29.281 V19.2.0 has a variant, and a header of
another type is kept as its octets, in `Other`. An endpoint refuses a
message with such a header when a receiver must understand it, as the
specification requires, and answers a G-PDU or an Echo Request that has one
with the list of the types that it knows. `examples/handover.rs` writes the
headers of a handover: the PDCP PDU Number of a forwarded packet, the long
one, and the End Marker of a forwarding tunnel.

## Give a tunnel a TUN

With the `tun` feature, on Linux, what a socket bound to the UE's address
sends goes into the tunnel.

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
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), Some(9))?;
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

It creates an interface and a routing rule, which needs `CAP_NET_ADMIN`. A
user namespace with its own network namespace gives it that without root,
and keeps both off the host:

```sh
cargo build --features tun --example tun
unshare --user --map-root-user --net sh -c 'ip link set lo up && target/debug/examples/tun'
```

Where users may not create user namespaces, as on Ubuntu, use `sudo
unshare --net` instead of `unshare --user --map-root-user --net`.

## Carry the tunnel in the kernel

With the `ebpf` feature, on Linux 6.6, eBPF programs carry the packets of a
tunnel between its TUN and the network. The fast path is an object of its own,
which you give what you gave the endpoint: the TUN, and the tunnel's TEIDs,
addresses and QoS flow.

```rust,no_run
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use oxirush_gtp_u::ebpf::FastPath;
    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let local: SocketAddrV4 = "127.0.0.1:2152".parse()?;
    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse()?).await?;
    let (gnb, _received) = Endpoint::bind(local.into()).await?;
    let fast_path = FastPath::load()?;

    let remote = RemoteTunnel::new(upf.local_addr()?, 0x1001);
    let teid = gnb.install(1, 5, remote, Some(9))?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

    // As in the `tun` example, then the TUN goes on the fast path and the
    // tunnel through it: the kernel carries the tunnel's packets.
    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    let tun = gnb.attach_tun(1, 5, TunConfig::new("ue0", routing))?;
    fast_path.add_tun(tun)?;
    fast_path.shortcut(tun, local, teid, remote, Some(9))?;

    let socket = tokio::net::UdpSocket::bind((ue, 0)).await?;
    for _ in 0..5 {
        socket.send_to(b"hello", "192.0.2.1:7").await?;
        socket.recv_from(&mut [0; 16]).await?;
    }
    // What the programs carried: the Echo Replies of the echo service are
    // left to userspace.
    println!("{:?}", fast_path.stats());
    Ok(())
}
```

`shortcut` again after an `install` that changes the tunnel, and
`end_shortcut` and `remove_tun` before the tunnel and its TUN go.

Loading the programs needs root. The program is `examples/fast_path.rs`:

```sh
cargo build --features ebpf --example fast_path
sudo unshare --net sh -c 'ip link set lo up && target/debug/examples/fast_path'
```

## Limits

- It has no control plane: no NGAP, S1AP or PFCP.
- The endpoint and the test UPF are for labs and test tools, not for
  untrusted peers. GTP-U has no authentication: whoever reaches a socket can
  send on its tunnels.
- The test UPF is not one for real traffic: it has no PFCP, QoS or
  charging.
- It has no GTP' and no versions 0 and 2 of GTP.
- The helpers, the TUN routing and the fast path are IPv4 only. The codec
  and the endpoint carry any payload.

## Performance

On one core of an AMD Ryzen 7 5700G (Linux 7.0, Rust 1.98.1), at 0d25889 on
2026-10-18, for a G-PDU with its PDU Session Container and 1,400 octets of
payload:

| | Time |
|---|---|
| Build the G-PDU and encode it into a buffer that is used again | 45 ns |
| Decode, the payload left in the datagram | 22 ns |
| Decode, the payload copied | 57 ns |
| From an endpoint to the test UPF and back, over the loopback interface | 12.9 µs |

[`benches/`](benches/README.md) has the benchmarks, the other figures and
how to profile.

### Against go-gtp

[go-gtp](https://github.com/wmnsk/go-gtp) v0.8.12 on the same G-PDUs of
1,400 octets, at 0d25889 on core 2 of the same machine. A ratio is the time
of go-gtp over this crate's, and "about the same" is within 10 %:

| Operation | This crate | go-gtp / this crate |
|---|---|---|
| Encode, no extension header | 17.8 ns | about the same |
| Encode, PDU Session Container | 25.8 ns | about the same |
| Decode, no extension header | 10.8 ns | 0.38x |
| Decode, PDU Session Container | 24.0 ns | 1.8x |
| Endpoint to endpoint and back, no extension header, loopback | 12,078 ns | 2.0x |

[`benches/`](benches/README.md#against-go-gtp) has every figure, with cycles,
instructions, allocations and peak memory, and the method.
`benches/compare.sh 3` runs every row on core 3:

```sh
benches/compare.sh 3
```

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

Property tests and a `cargo fuzz` target check that decoding never panics,
and that what decodes encodes to a message that decodes to the same value;
another holds what a node answers, and the Echo Reply of the test UPF, to
TS 29.281 and to RFC 792. CI rebuilds the eBPF object from its source and compares. Each Rust block of
this page is checked with what it prints ([`readme/`](readme/build.rs) says
how).

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
