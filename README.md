# oxirush-gtp-u

[![Crates.io](https://img.shields.io/crates/v/oxirush-gtp-u.svg)](https://crates.io/crates/oxirush-gtp-u)
[![Documentation](https://docs.rs/oxirush-gtp-u/badge.svg)](https://docs.rs/oxirush-gtp-u)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/linouxis9/oxirush-gtp-u/blob/master/LICENSE)

GTPv1-U, the protocol that tunnels user traffic in 4G and 5G networks, for
Rust:

- a **codec** for the messages of 3GPP TS 29.281, with the PDU Session
  Container of TS 38.415 that carries a 5G QoS flow identifier;
- **`Endpoint`**, a Tokio UDP socket for the tunnels of a gNB (N3) or an eNB
  (S1-U), which also answers what a GTP-U node must answer;
- **`upf_sim`**, a UPF to test against, as a type and as a program;
- **`tun`**, Linux TUN devices with the address and routes of a UE or of a
  UPF session;
- **`ebpf`**, an eBPF fast path that carries an endpoint's tunnels in the
  kernel, between a TUN and the network.

It is made for simulators and test tools. It has no control plane: tunnels
are set up by calls, with the TEIDs and addresses that NGAP, S1AP or PFCP
would negotiate. The test UPF is not a UPF for real traffic. GTP-U has no
authentication: anyone who reaches a socket can send on its tunnels.

## Requirements

```toml
[dependencies]
oxirush-gtp-u = "0.1"
```

Rust 1.87 or later, and for each part:

| Part | Feature | Needs |
| ---- | ------- | ----- |
| Codec, IPv4 helpers | none | nothing |
| `Endpoint`, `upf_sim` | `endpoint` (default) | a Tokio runtime |
| `tun`, `UpfSimulator::attach_tun` | `tun` (default, through `ebpf`) | Linux, `CAP_NET_ADMIN` |
| `ebpf` | `ebpf` (default) | Linux 6.6, `CAP_BPF` and `CAP_NET_ADMIN` |
| `Serialize` and `Deserialize` for `RemoteTunnel` | `serde` | |

With `default-features = false` the crate is the codec and has no
dependencies. The `tun` and `ebpf` modules exist on Linux only; elsewhere
their features build and add nothing to `endpoint`. The fast path's
programs are committed as an object: building the crate needs no nightly
toolchain and no eBPF linker.

## Usage

The programs below are those of `examples/`; a test compares them with this
page. The asynchronous ones also need `tokio` with its `macros`, `rt` and
`net` features.

### Encode and decode

```rust
use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};

fn main() -> Result<(), oxirush_gtp_u::Error> {
    // An uplink G-PDU of QoS flow 9, as a gNB sends it on N3.
    let uplink = Packet::uplink(0x1234_5678, 9, b"an IP packet".to_vec());
    let bytes = uplink.encode()?;
    let decoded = Packet::decode(&bytes)?;
    assert_eq!(decoded, uplink);
    assert_eq!(decoded.qfi(), Some(9));

    // A downlink one whose container has more than a QFI.
    let mut information = DownlinkPduSessionInformation::new(9);
    information.rqi = true;
    let container = PduSessionContainer::Downlink(information);
    let downlink = Packet::g_pdu(0x9abc_def0, b"an IP packet".as_slice())
        .with_pdu_session_container(container.clone());
    let bytes = downlink.encode()?;

    // The payload of a borrowed message stays in the datagram.
    let decoded = Packet::decode_borrowed(&bytes)?;
    assert_eq!(decoded.pdu_session_container(), Some(&container));
    assert_eq!(decoded.payload, b"an IP packet");
    Ok(())
}
```

### An endpoint and the test UPF

```rust,ignore
use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{Endpoint, RemoteTunnel, ipv4_udp, parse_ipv4_udp};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let (upf, mut observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap()).await?;
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:0".parse().unwrap()).await?;

    // What the control plane negotiates: the UPF receives the session's
    // uplink on TEID 0x1001, the gNB its downlink on the TEID it assigns
    // to RAN UE 1, PDU session 5.
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9));

    // Uplink: an IP packet of the UE, which the UPF's echo service reflects.
    let ue = "10.45.0.2:4000".parse().unwrap();
    let server = "192.0.2.1:7".parse().unwrap();
    gnb.send(1, 5, ipv4_udp(ue, server, b"hello")?).await?;
    let uplink = observed.recv().await.expect("the UPF is running");
    println!("UPF: TEID {:#x} from {}", uplink.uplink_teid, uplink.from);

    // Downlink: the reply, with the tunnel it arrived on.
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

```sh
cargo run --example endpoint
```

### A TUN for a UE

With a TUN, applications use a tunnel through Linux: what a socket bound to
the UE's address sends is routed into the TUN.

```rust,ignore
#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    use std::net::Ipv4Addr;

    use oxirush_gtp_u::tun::{Routing, TunConfig, TunPort};
    use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
    use oxirush_gtp_u::{Endpoint, G_PDU, RemoteTunnel};

    let (upf, _observed) = UpfSimulator::bind("127.0.0.8:2152".parse().unwrap()).await?;
    let (gnb, mut received) = Endpoint::bind("127.0.0.1:2152".parse().unwrap()).await?;
    let teid = gnb.install(1, 5, RemoteTunnel::new(upf.local_addr()?, 0x1001), 9)?;
    upf.set_session(Session::new(0x1001, teid, gnb.local_addr()?, 9));

    // The TUN gets the UE's address, and a rule routes what is sent from
    // that address into it.
    let ue = Ipv4Addr::new(10, 45, 0, 2);
    let routing = Routing::UePolicy {
        address: ue,
        table: 100,
        priority: 100,
    };
    let tun = TunPort::create(TunConfig::new("ue0", routing))?;

    // Uplink: what Linux routes into the TUN goes into the tunnel.
    let (reader, uplink) = (tun.clone(), gnb.clone());
    tokio::spawn(async move {
        let mut packet = vec![0; 65535];
        while let Ok(length) = reader.recv(&mut packet).await {
            let _ = uplink.send(1, 5, &packet[..length]).await;
        }
    });
    // Downlink: the IP packets of the tunnel's G-PDUs go to Linux.
    let writer = tun.clone();
    tokio::spawn(async move {
        while let Some(message) = received.recv().await {
            if message.packet.message_type == G_PDU {
                let _ = writer.send(&message.packet.payload).await;
            }
        }
    });

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

It creates an interface and a routing rule, which needs root. A network
namespace of its own keeps them off the host:

```sh
cargo build --example tun
sudo unshare --net sh -c 'ip link set lo up && target/debug/examples/tun'
```

### The eBPF fast path

In the program above every packet crosses userspace twice, through the
TUN's reader and the endpoint's socket. With the fast path, eBPF programs
carry a tunnel's packets in the kernel instead, and userspace keeps
carrying what they leave. `examples/fast_path.rs` is the program above with
three additions. It loads the programs and gives them to the endpoint,
before its tunnels are installed:

```rust,ignore
    let fast_path = FastPath::load()?;
    gnb.set_fast_path(fast_path.clone())?;
```

It puts the TUN on the fast path:

```rust,ignore
    let tun = TunPort::create(TunConfig::new("ue0", routing))?;
    // Put the TUN on the fast path once, when it is created.
    fast_path.add_tun(tun.index())?;
```

And it asks for the tunnel's short-cut whenever userspace carried a packet
of it:

```rust,ignore
        while let Ok(length) = reader.recv(&mut packet).await {
            let _ = uplink.send(1, 5, &packet[..length]).await;
            // Userspace carried a packet of the tunnel: have the kernel carry
            // the next ones. While the tunnel's interface is still getting
            // its program this is `WouldBlock`, and the next packet asks again.
            if let Err(error) = uplink.shortcut(1, 5, reader.index()) {
                eprintln!("still in userspace: {error}");
            }
        }
```

It runs like the `tun` example and prints `FastPath::stats`, the packets
that the programs carried.

### The test UPF as a program

```sh
cargo run --bin oxirush-upf-sim -- 127.0.0.8:2152 127.0.0.1:2152 1001 2001 9
```

The arguments are the UPF's N3 address, the gNB's N3 address, the uplink
TEID, the downlink TEID and the QFI. It serves that one session until
Ctrl-C or SIGTERM, with the echo service as N6, or as root with a TUN:

```sh
cargo build --bin oxirush-upf-sim
sudo ./target/debug/oxirush-upf-sim \
  127.0.0.8:2152 127.0.0.1:2152 1001 2001 9 --tun oxupf0 10.45.0.2
```

## Reference

### Codec

`Packet` has every header field of TS 29.281 §5.1, the chain of extension
headers and the payload. There are constructors for G-PDU, Echo Request and
Response, Error Indication, Supported Extension Headers Notification and End
Marker; `Packet::new` and `InformationElement::encode_all` build any other
message. The PDU Session Container has the downlink and uplink PDU Session
Information of TS 38.415 V18 §5.5.2, with the QoS monitoring, sequence
number, delay and congestion fields, and the downlink Burst Size and Time
To Next Burst.

Decoding follows the receiver rules of §5.1: the flags decide which
optional fields are read and the spare bit is ignored. Extension headers,
TLV information elements and uplink New IEs that have no type of their own
are kept as received. A TV information element imported from TS 29.060 is
kept when its fixed length is known; an unknown TV type is an error. What
decodes encodes to a message that decodes to the same value.

`Packet<P>` takes any payload that is `AsRef<[u8]>`, `Vec<u8>` by default.
`decode_borrowed` returns a `Packet<&[u8]>` whose payload stays in the
datagram, and `into_owned` copies it. `encoded_len` gives the wire length
without encoding. `encode_into` appends to a `Vec<u8>` and leaves it as it
was on an error. The codec's `Error` converts into a `std::io::Error`, for
`?` next to an endpoint's calls.

`ipv4_udp` and `ipv4_icmp_echo_request` build inner packets, and
`parse_ipv4_udp` and `parse_ipv4_icmp_echo` read them, to exercise a tunnel
without a TUN. They are IPv4 only; any payload, IPv6 included, is carried
as it is.

### Endpoint

`Endpoint::bind` opens the socket and returns the receiver of the tunnels'
messages: G-PDUs, End Markers and the peer's Error Indications, each with
its tunnel and source address. The TEID alone identifies a tunnel, so a
peer may send from another address than its F-TEID's.

- `install` sets up the tunnel of a RAN UE and PDU session toward a remote
  TEID and returns the local TEID to give the peer; on an existing tunnel
  it updates the remote end and the QFI. A QFI above 63 is `InvalidInput`.
  `install_s1u` does so for an eNB's E-RAB, whose G-PDUs carry no PDU
  Session Container, and cannot fail. `install_with_teid` takes a local
  TEID that something else assigned.
- `send` sends an IP packet in a tunnel. `send_to` sends any `Packet` from
  the endpoint's socket, with its sequence number and extension headers.
- `remove` and `remove_ran` remove tunnels; `local_teid` looks one up.

The endpoint does the path management of TS 29.281 §7 by itself. It answers
Echo Requests, sends an Error Indication for a G-PDU on an unknown TEID and
a Supported Extension Headers Notification for an extension header it must
understand and does not. The last two go to port 2152, as the specification
requires. A slow receiver never delays these replies: past 256 queued
messages new ones are dropped and counted, and a dropped receiver changes
nothing else.

Bind a specific address: a wildcard is refused with `InvalidInput`, so that
replies leave from the address the request reached. Bind port 2152 to
receive the peer's Error Indications, which TS 29.281 §4.4.2.4 sends there
whatever port the G-PDUs came from.

`stats` has the receive and drop counters and `is_running` the state of the
background task. `shutdown` stops it for all clones and waits for it; the
port stays bound until the last clone is dropped.

### Test UPF

`UpfSimulator` is an N3 peer whose sessions are set with `set_session`.
Uplink packets go to the echo service, which reflects IPv4 UDP and answers
ICMP Echo Requests, or to the TUN that `attach_tun` gives the session.
`send_downlink` sends a packet to the UE. The receiver of `bind` observes
the uplink G-PDUs.

`switch_downlink` moves a session's downlink to another gNB address and
TEID and sends an End Marker on the old path. When that send fails or is
cancelled the new path stays, the marker stays pending
(`pending_end_marker`) and the next call sends it first.

`shutdown` also closes the attached TUNs and returns what could not be
cleaned up; call it again to retry.

### TUN devices

`TunPort::create` makes the TUN and sets up one of three routings over
rtnetlink:

- `Routing::UePolicy` gives the TUN a UE's address, and a rule sends what
  comes from that address to a table of its own, whose default route is the
  TUN.
- `Routing::UeVrf` gives the TUN a UE's address and puts it in a new VRF,
  whose table has the TUN as its default route.
- `Routing::Upf` routes one UE address to the TUN in the main table, so
  that Linux is the UPF's N6. To reach another network, enable IPv4
  forwarding and add the routes or NAT that network needs.

The routing is IPv4 and the TUN has no IPv6 address, so Linux sends nothing
through it unasked. `recv` and `send` exchange raw IP packets with Linux.
A `TunPort` is `Clone`, for a task that reads it and one that writes.

Dropping the last clone removes the TUN and its routing, as does `close`
at once; `try_close` reports what could not be removed and keeps it for
another call. Removal happens in the network namespace of the creation. A
process that ends without running destructors, as on SIGKILL, leaves the
rule or the VRF behind; the TUN goes with the process.

### Fast path

`FastPath::load` loads three TCX programs:

- `uplink`, at the egress of a TUN, hands the IPv4 packets of a short-cut
  tunnel to the stage. The stage is a veth pair without checksum offload,
  so that Linux splits the large segments of the UE's TCP stack and
  completes their checksums before the encapsulation. It has the largest
  MTU: whatever a TUN lets through crosses it.
- `encap`, at the far end of the stage, writes the IPv4, UDP and GTP-U
  headers, with the PDU Session Container of an N3 tunnel, and sends the
  G-PDU out of the N3 interface. The G-PDU is the one the codec encodes.
- `decap`, at the ingress of the N3 interface, delivers the G-PDUs of
  short-cut tunnels to their TUN.

The N3 interface of a tunnel is the one Linux routes it through, from the
endpoint's address to the peer's: the loopback interface for a peer on the
same host. It gets `decap` when a first tunnel through it is installed, on
a blocking thread of the Tokio runtime, so that the task that installs the
tunnel does not wait for it (outside a runtime the caller attaches it).
Until it is there `Endpoint::shortcut` fails with `WouldBlock`.
`FastPath::add_tun` attaches `uplink` to a TUN in the caller's thread.

A short-cut follows its tunnel. `install` on the tunnel updates it;
`remove` and the endpoint's `shutdown` end it, and so does giving the TUN
another tunnel or the tunnel another TUN. `FastPath::end_shortcut` leaves
a TUN's tunnel to userspace until the next `shortcut`, as when its UE moves
to another endpoint. `FastPath::remove_tun` also takes the TUN off the fast
path: call it before closing the TUN. When `shortcut` fails the tunnel stays
in userspace.

The programs leave to userspace, which keeps working underneath: other
messages than G-PDUs, unknown TEIDs, extension headers other than one PDU
Session Container, fragments, inner packets that are not IPv4, G-PDUs
longer than the N3 MTU (the socket fragments them), and ICMP Echo Replies,
which a caller that pings through the endpoint expects on its receiver.
What they leave also goes on to the interface's other TCX programs and tc
filters (`TC_ACT_UNSPEC`), so several fast paths or other tools can share
an N3 interface. `FastPath::stats` counts the packets carried, returned as
too long and dropped.

The endpoint must be bound to an IPv4 address and port 2152, and a
tunnel's peer must be IPv4 on port 2152 too. Everything happens in the
network namespace `load` was called in. `load` fails without TCX or the
capabilities and then leaves nothing behind. The programs' links go with
the process, whatever ends it. The stage, `oxs` with eight hexadecimal
digits, outlives a killed process; the next `load` in that namespace
removes it, as an `oxs` veth that is up and whose far end has no program
left.

`load` and `add_tun` also spread what the stage's far end and the TUN
receive over the CPUs the process may use (RPS), when `/sys` shows the
process's network namespace. After `unshare --net` alone it shows the former
one, and nothing is steered.

The programs' source is `src/ebpf/programs.rs` and their object
`src/ebpf/gtpu.o`. `ebpf/build.sh` rebuilds the object, with the nightly
toolchain that `ebpf/rust-toolchain.toml` pins, `rust-src` and
`bpf-linker`; CI rebuilds it the same way with bpf-linker 0.11.1 and fails
when it differs from the committed one.

### Source layout

```text
src/
├── packet.rs              owned and borrowed messages (TS 29.281 §5.1, §6, §7)
├── extension.rs           extension headers and PDU Session Container (TS 38.415)
├── ie.rs, error.rs         information elements and codec errors
├── ipv4.rs, icmp.rs        inner IPv4 UDP and ICMP Echo packets
├── datagram.rs, path.rs    shared UDP receive and path management (endpoint)
├── endpoint.rs            gNB endpoint and forwarding (endpoint)
├── endpoint/routes.rs     tunnel identity and route indexes (endpoint)
├── stats.rs               receive/drop counters (endpoint)
├── upf_sim.rs             test UPF and forwarding (endpoint)
├── upf_sim/sessions.rs     session generations and handover state (endpoint)
├── tun.rs                 public TUN API (tun)
├── tun/device.rs          TUN descriptor and packet I/O (tun)
├── tun/routing.rs         routing ownership and cleanup (tun)
├── tun/error.rs           contextual I/O errors (tun)
├── netlink.rs             rtnetlink operations (tun)
├── ebpf.rs                loader of the fast path and its tunnels (ebpf)
├── ebpf/layout.rs         map layouts shared with the programs (ebpf)
├── ebpf/programs.rs       the TCX programs: uplink, encap, decap
├── ebpf/gtpu.o            their object, built by ../ebpf (ebpf)
└── bin/oxirush-upf-sim.rs
ebpf/                      the crate that builds programs.rs for eBPF
examples/                  the programs of this page
```

### Tests

```bash
cargo test --all-features
# The TUN tests need root and run each in its own network namespace; the
# runner variable names the target, here x86_64 Linux.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo \
  cargo test --features tun --test tun_linux -- --ignored
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo \
  cargo test --features tun --test tun_cleanup -- --ignored
# The fast path tests too, on Linux 6.6: they load the programs.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo \
  cargo test --features ebpf --test ebpf_linux -- --ignored
# Compare the wire format with Wireshark's dissector (needs tshark).
cargo test --test wireshark -- --ignored
```

Property tests check the codec for panics and for decode, encode, decode
equality, and `fuzz/` has a cargo-fuzz target for the same.

### 3GPP references

- 3GPP TS 29.281: GTPv1-U (header, extension headers, messages, information
  elements, path management)
- 3GPP TS 38.415: NG-RAN PDU Session User Plane protocol (PDU Session
  Container)
- 3GPP TS 29.060: imported TV information elements and receive rules

## Documentation

Full API reference: **<https://docs.rs/oxirush-gtp-u>**

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Sign off your commits (`git commit -s`)
4. Open a Pull Request

A change to `src/ebpf/gtpu.o` is only accepted with the change to
`src/ebpf/programs.rs`, `src/ebpf/layout.rs` or the build files in `ebpf/`
that produces it: CI rebuilds the object and compares.

### Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means that you have the right to submit your contributions and you agree to license them according to the project's license.

All commits should be signed-off with `git commit -s` to indicate your agreement to the DCO.

## License

Copyright 2025 - 2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/linouxis9/oxirush-gtp-u/blob/master/LICENSE) for details.
