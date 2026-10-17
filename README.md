# oxirush-gtp-u

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/linouxis9/oxirush-gtp-u/blob/master/LICENSE)

GTP-U, the protocol that tunnels user traffic in 5G and 4G networks, in
Rust, per 3GPP TS 29.281: a codec, an endpoint for the tunnels of a base
station, a UPF to test against, Linux TUN devices and an eBPF fast path.

```rust
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
```

```text
[34, ff, 00, 14, 12, 34, 56, 78, 00, 00, 00, 85, 01, 10, 09, 00]
TEID 0x12345678, QFI Some(9)
"an IP packet"
QFI 9, RQI true
```

> This crate is not on crates.io yet.

## Install

```toml
[dependencies]
oxirush-gtp-u = { git = "https://github.com/linouxis9/oxirush-gtp-u" }
tokio = { version = "1", features = ["macros", "rt", "net"] } # for the endpoint
```

The codec needs no dependency and no feature: [Features](#features) has
the others.

## Carry a tunnel between an endpoint and the test UPF

`Endpoint` is the N3 socket of a gNB, or the S1-U socket of an eNB, for
labs and test tools. A call gives a tunnel the TEIDs (Tunnel Endpoint
Identifiers) and addresses that NGAP, S1AP or PFCP would negotiate.

```rust
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
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9))?;

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
```

```text
UPF: TEID 0x1001, QFI Some(9)
gNB: RAN UE 1 session 5, QFI Some(9): 192.0.2.1:7 to 10.45.0.2:4000
```

## Echo and Error Indication

```rust
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
```

```text
Echo Response, sequence number Some(7), [Recovery(0)]
Error Indication for RAN UE 1 session 5: [TeidDataI(0x00001001), GtpUPeerAddress(127.0.0.10)]
```

An endpoint also sends an Error Indication for a G-PDU on a TEID that it
does not have. Whoever reaches the socket can send such G-PDUs, and Echo
Requests, from any address: an address gets 100 Error Indications a second
at most and 10 Echo Responses, and all addresses together 1000 Error
Indications. `stats()` counts the replies that were not sent, the G-PDUs on
unknown TEIDs and the Error Indications that name no tunnel.

## Read and write extension headers

```rust
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
list of the types that it knows.

## The headers of a handover

```rust
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
```

```text
[00, 00, 00, 85, 01, 00, 09, c0, 01, 0a, bc, 00]
[00, 00, 00, 85, 01, 00, 09, 03, 02, 02, ab, cd, 00, 00, 00, 00]
[34, fe, 00, 08, 00, 00, 20, 01, 00, 00, 00, 85, 01, 00, 09, 00]
PDU Session Container
PDCP PDU Number 0xabc
```

## Give a tunnel a TUN

With the `tun` feature, on Linux, what a socket bound to the UE's address
sends is routed into the tunnel.

```rust,no_run
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    use std::net::Ipv4Addr;

    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse().unwrap()).await?;
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap()).await?;
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
async fn main() -> std::io::Result<()> {
    use std::net::Ipv4Addr;

    use oxirush_gtp_u::ebpf::FastPath;
    use oxirush_gtp_u::tun::{Routing, TunConfig};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse().unwrap()).await?;
    let (gnb, _received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap()).await?;

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

## Features

| Feature | Adds | Needs |
| ------- | ---- | ----- |
| none | the codec and the IPv4 helpers | no dependency |
| `endpoint`, the default | `Endpoint`, `upf_sim` | a Tokio runtime |
| `tun` | `tun`, and `attach_tun` of `Endpoint` and `UpfSimulator` | Linux, `CAP_NET_ADMIN` |
| `ebpf` | `ebpf` | Linux 6.6, `CAP_BPF` and `CAP_NET_ADMIN` |
| `serde` | `Serialize` and `Deserialize` for `RemoteTunnel` | |
| `cli` | the `oxirush-upf-sim` program | |

```toml
# The codec alone
oxirush-gtp-u = { git = "https://github.com/linouxis9/oxirush-gtp-u", default-features = false }
```

`ebpf` brings `tun`, and `tun` brings `endpoint`. Off Linux, `tun` and
`ebpf` build and add nothing, and so does `ebpf` on 32-bit x86, which aya
does not build for, and on big-endian architectures. The eBPF programs are
committed as an object: a build with `ebpf` needs no nightly toolchain and
no eBPF linker. The minimum supported Rust version is 1.88.

## What it does not do

- Control plane: it has no NGAP, S1AP or PFCP.
- Untrusted peers: the endpoint and the test UPF are for labs and test
  tools. GTP-U has no authentication: whoever reaches a socket can send on
  its tunnels.
- A UPF for real traffic: the test UPF has no PFCP, QoS or charging.
- GTP' and the versions 0 and 2 of GTP.
- IPv6 in the helpers, the TUN routing and the fast path. The codec and the
  endpoint carry any payload.

## Performance

On one core of an AMD Ryzen 7 5700G, a G-PDU with its PDU Session Container
and 1400 octets of payload:

| | Time |
|---|---|
| Encode into a buffer that is used again | 56 ns |
| Decode, the payload left in the datagram | 23 ns |
| Decode, the payload copied | 55 ns |
| From an endpoint to the test UPF and back, over the loopback interface | 13.3 µs |

A message with one extension header at most is decoded without an
allocation. [`benches/`](https://github.com/linouxis9/oxirush-gtp-u/blob/master/benches/README.md)
has the benchmarks, the other figures and how to profile.

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
CI rebuilds the eBPF object from its source and compares.

[The documentation](https://github.com/linouxis9/oxirush-gtp-u/blob/master/src/lib.rs)
has the terms, what the codec covers, and the reference of the endpoint,
the test UPF, the TUN routings and the fast path: `cargo doc --all-features
--open` builds it.

## The OxiRush family

[oxirush-nas](https://github.com/linouxis9/oxirush-nas) (NAS messages),
[oxirush-security](https://github.com/linouxis9/oxirush-security) (NAS
security), [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap)
(NGAP), [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap) (S1AP)
and [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp) (SCTP).

## Contributing

Open a pull request with a test for what it changes. The programs of this
page are those of `examples/`, and
[`tests/readme.rs`](https://github.com/linouxis9/oxirush-gtp-u/blob/master/tests/readme.rs)
checks what they print. A change to `src/ebpf/gtpu.o` comes with the change
of its source that produces it. Sign off your commits (`git commit -s`): by
contributing you agree to the
[Developer Certificate of Origin](https://developercertificate.org/).
[SECURITY.md](https://github.com/linouxis9/oxirush-gtp-u/blob/master/SECURITY.md)
says how to report a vulnerability.

## License

Copyright 2025-2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/linouxis9/oxirush-gtp-u/blob/master/LICENSE)
for details.
