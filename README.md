# oxirush-gtp-u

[![Crates.io](https://img.shields.io/crates/v/oxirush-gtp-u.svg)](https://crates.io/crates/oxirush-gtp-u)
[![Documentation](https://docs.rs/oxirush-gtp-u/badge.svg)](https://docs.rs/oxirush-gtp-u)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

GTPv1-U for Rust: a codec for 3GPP TS 29.281 with the PDU Session Container
of TS 38.415, a Tokio endpoint for the N3 side of a gNB, a UPF for tests,
and Linux TUN devices routed for a UE or a UPF session.

## Features

The codec handles every header field of TS 29.281 §5.1, chains of
extension headers, and the information elements of §8. It builds Echo
Request and Response, Error Indication, Supported Extension Headers
Notification, End Marker, Tunnel Status and G-PDU messages. The PDU Session
Container carries the downlink and uplink PDU Session Information of TS 38.415 V18
§5.5.2, with the QoS monitoring, sequence number, delay and congestion
fields, plus downlink Burst Size and Time To Next Burst. Later uplink IEs
are kept as received when their format is not yet typed.

Decoding follows the receiver rules of §5.1: the flags decide which
optional fields are read, the spare bit is ignored, and extension headers
and unknown TLV IEs are kept. TV IEs imported from TS 29.060 are kept when
their fixed length is known; an unknown TV type returns an error. Property
tests and a fuzz target check for panics and decode/encode/decode equality,
and the tests compare the wire format with Wireshark's dissector.
The codec has also exchanged traffic with the free5GC and
Open5GS UPFs.

`Endpoint` is one UDP socket for all the tunnels of a gNB, keyed by a RAN
UE identifier and a PDU session ID. It does the path management of
TS 29.281 §7 by itself: it answers Echo Requests, sends an Error Indication
for a G-PDU on an unknown TEID and a Supported Extension Headers
Notification for an unsupported comprehension-required extension header,
to port 2152 as the specification requires. It identifies a tunnel by its
TEID alone, so peers may send from another address than their F-TEID's.
A slow consumer never delays those replies: past 256 queued messages it
drops new ones, as a full socket buffer would.

`upf_sim::UpfSimulator` is a UPF for tests, with sessions provisioned
through its API. Uplink packets go to a built-in N6 service that reflects
IPv4 UDP and ICMP Echo Request packets, or to a TUN device. It sends an End
Marker when a session's downlink moves to another gNB address.

`tun::TunPort` creates a TUN device and sets up, over rtnetlink, the
address and routes of a UE session (a source-address policy rule or a VRF)
or of a UPF session. Dropping it removes them.

`ipv4_udp` and `ipv4_icmp_echo_request` build inner IPv4 packets, and
`parse_ipv4_udp` and `parse_ipv4_icmp_echo` read them, to exercise tunnels
without a TUN.

### Limitations

- No PFCP: the test UPF's sessions are set with `set_session`, or by the
  arguments of the `oxirush-upf-sim` binary.
- The inner-packet helpers are IPv4 only. IPv6 T-PDUs are carried like any
  other payload.
- TUN devices are Linux only.
- GTP-U has no authentication: anyone who reaches the socket can send on a
  tunnel or report an Error Indication for it.

## Quick start

```toml
[dependencies]
oxirush-gtp-u = "0.1"
```

### Feature flags

| Feature    | Default | Adds |
| ---------- | ------- | ---- |
| `endpoint` | yes     | `Endpoint` and `upf_sim`, on Tokio |
| `tun`      | no      | `tun` and `UpfSimulator::attach_tun`, on Linux |
| `serde`    | no      | `Serialize` and `Deserialize` for `RemoteTunnel`, with `endpoint` |

Without default features the crate is the codec and the IPv4 helpers, with
no dependencies. The minimum supported Rust version is 1.85.

## Usage

### Encoding and decoding

```rust
use oxirush_gtp_u::{Packet, PduSessionContainer};

fn main() -> Result<(), oxirush_gtp_u::Error> {
    // An uplink G-PDU of QoS flow 9, as a gNB sends it on N3.
    let packet = Packet::uplink(0x1234_5678, 9, b"an IP packet".to_vec());
    let bytes = packet.encode()?;

    let decoded = Packet::decode(&bytes)?;
    assert_eq!(decoded, packet);
    assert!(matches!(
        decoded.pdu_session_container(),
        Some(PduSessionContainer::Uplink(information)) if information.qfi == 9
    ));
    Ok(())
}
```

`Packet::encoded_len` validates the wire length without allocating output.
`encode_into` appends to a reusable `Vec<u8>` and leaves it unchanged on
validation error; clear the buffer first to replace its previous contents.

`Packet<P>` accepts any payload implementing `AsRef<[u8]>`, with `Vec<u8>`
as the default. `Packet::decode_borrowed` returns a `Packet<&[u8]>` whose
payload refers to the input datagram; extension headers are still owned.
Call `into_owned` when the packet must outlive that datagram.

```rust
use oxirush_gtp_u::Packet;

fn main() -> Result<(), oxirush_gtp_u::Error> {
    let packet = Packet::uplink(0x1234_5678, 9, b"an IP packet".as_slice());
    let bytes = packet.encode()?;
    let borrowed = Packet::decode_borrowed(&bytes)?;
    assert_eq!(borrowed.encode()?, bytes);
    Ok(())
}
```

### Tunnels on an endpoint

`Endpoint::bind` opens the socket and returns a receiver for the tunnels'
messages. `install` adds the tunnel of a RAN UE and PDU session to a remote
F-TEID and returns the local TEID to give the peer; `send` sends a G-PDU on
it. `install_s1u` adds an eNB's S1-U tunnel instead, whose G-PDUs carry no
PDU Session Container. The [`Endpoint` documentation](https://docs.rs/oxirush-gtp-u/latest/oxirush_gtp_u/struct.Endpoint.html)
has a complete example with two endpoints.

`install_with_teid` accepts a local TEID assigned by another control-plane
component. `send_to` sends a custom `Packet` from the endpoint's bound socket,
including its sequence number and extension headers.
`send`, `send_to` and `UpfSimulator::send_downlink` accept borrowed payloads
as well as owned buffers.

Both `Endpoint` and `UpfSimulator` expose receive/drop counters through `stats`,
worker health through `is_running`, and an async `shutdown` that stops background
processing for all clones and waits for their receiver. The UDP port stays bound
until the final clone is dropped. Slow or closed application receivers do not stop
path replies. UPF shutdown also waits for TUN forwarding tasks and reports cleanup
failures; retry shutdown after resolving the error to finish releasing resources.

Bind port 2152 to receive the peer's Error Indications, which TS 29.281
§4.4.2.4 sends there whatever port the G-PDUs came from, and bind a
specific address: `Endpoint::bind` and `UpfSimulator::bind` reject wildcard
addresses with `InvalidInput` so replies use the address that received the
request.

### The test UPF

The binary runs one session:

```bash
cargo run --bin oxirush-upf-sim -- 127.0.0.8:2152 127.0.0.1:2152 1001 2001 9
```

The arguments are the UPF's N3 address, the gNB's N3 address, the uplink
TEID, the downlink TEID and the QFI; the gNB uses the same TEIDs the other
way round. Tests that change sessions as they run, or move a session's
downlink with `switch_downlink`, use the Rust API instead.

A failed or cancelled `switch_downlink` can leave the new route installed.
The old path's End Marker remains pending and a retry to the same target
attempts it again. `session` and `pending_end_marker` expose those outcomes;
UDP send success does not guarantee delivery. The binary handles Ctrl-C and
SIGTERM by awaiting shutdown and closing attached TUNs.

### TUN devices

`TunPort` needs `CAP_NET_ADMIN` and sets up one of three routings:

- `Routing::UePolicy` gives a UE session an address and a source-address
  rule to its own table, whose default route is the TUN.
- `Routing::UeVrf` puts the TUN in a new VRF with its own table.
- `Routing::Upf` routes one UE address to the TUN in the main table, so
  that Linux handles N6, including forwarding when the host enables it.

`try_close` reports cleanup failures and retains failed resources for retry.
Cleanup uses the network namespace where the port was created, even when
another thread or namespace closes it. `close` and `Drop` perform best-effort
cleanup using the same operation.

`UpfSimulator::attach_tun` connects such a TUN to a session:

```bash
cargo build --features tun --bin oxirush-upf-sim
sudo ./target/debug/oxirush-upf-sim \
  127.0.0.8:2152 127.0.0.1:2152 1001 2001 9 --tun oxupf0 10.45.0.2
```

To reach another network over N6, enable IPv4 forwarding and add the routes
or NAT that network needs. The TUN device always goes away with the
process, but the policy rule or VRF stays behind when the process ends
without running destructors: on SIGKILL, `process::exit`, or a panic with
`panic = "abort"`.

## Architecture

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
└── bin/oxirush-upf-sim.rs
```

`Endpoint` and `UpfSimulator` use the same datagram receive path. It handles malformed
packets and path replies before tunnel dispatch, and copies a payload only
after reserving space in the application receiver. Session changes remain
atomic with the nonblocking send that uses them. TUN routing cleanup runs
before its device descriptor is released.

## Tests

```bash
cargo test --all-features
# The TUN tests need root and run each in its own network namespace; the
# runner variable names the target, here x86_64 Linux.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo \
  cargo test --features tun --test tun_linux -- --ignored
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo \
  cargo test --features tun --test tun_cleanup -- --ignored
# Compare the wire format with Wireshark's dissector (needs tshark).
cargo test --test wireshark -- --ignored
```

`fuzz/` has a cargo-fuzz target for the decoders.

## 3GPP references

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

### Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means that you have the right to submit your contributions and you agree to license them according to the project's license.

All commits should be signed-off with `git commit -s` to indicate your agreement to the DCO.

## License

Copyright 2025 - 2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
