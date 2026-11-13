# Changelog

All notable changes to `oxirush-gtp-u` are recorded here.

## Unreleased

### Changed

- `upf_sim::Session::qfi` is an `Option<u8>`, and `Session::s1_u` makes the
  session of an E-RAB on S1-U, whose downlink G-PDUs carry no PDU Session
  Container. `Session::new` makes one of N3, of its QFI.

### Removed

- The `oxirush-upf-sim` program and its feature `cli`. The test UPF is
  `upf_sim::UpfSimulator`, which a program of a few lines starts. A build
  that names the feature no longer resolves.
- `PduSetInformationContainer` and `DownlinkPduSetInformation`, the fields
  of the frame of TS 38.415 §6.5.2. The extension header keeps its variant
  and carries the frame as octets, as the RAN containers carry theirs:
  `ExtensionHeader::PduSetInformationContainer { content, legacy_type }`,
  where it had `information`. `Part::PduSetSequenceNumber`,
  `Part::PduSetImportance` and `Part::PduSetSize` go with the fields. Not
  source compatible.

## 0.2.0 - 2026-11-07

### Changed

- `Packet::extension_headers` is a `Vec<ExtensionHeader>`. A decoded message
  with extension headers allocates their list.
- `Endpoint::install` takes the QFI as an `Option<u8>`: `None` for an E-RAB of
  S1-U, whose G-PDUs carry no PDU Session Container.
- `ebpf::FastPath` is driven by the program: `shortcut(tun, local, local_teid,
  remote, qfi)` carries a tunnel in the kernel, after `install` and again after
  an `install` that changes it, and `end_shortcut` before `remove`. The first
  short-cut through an N3 interface attaches its program, which blocks for
  milliseconds. `Endpoint::attach_tun` returns the TUN's interface index for
  it, and no longer short-cuts the tunnel by itself.
- `Endpoint::send_to` sends what it is given. A peer's Supported Extension
  Headers Notification is a `PathEvent`, and only `echo` and the supervised
  paths await Echo Responses.
- A socket sends 1,000 Error Indications, Supported Extension Headers
  Notifications and Echo Responses a second at most, after a burst of 1,000,
  in place of limits by address and by kind; `ReceiveStats::suppressed_replies`
  counts all three. What a peer causes is logged at the `debug` level, once a
  line.
- `InformationElement::Other` is any element kept as received: a TV element of
  a known length below type 128, a TLV element from 128 on.
- The IPv4 helpers are in the module `ip`: `ip::udp`, `ip::parse_udp` and
  `ip::Expected`.
- `upf_sim::UpfSimulator::switch_downlink` sends the End Marker once and
  returns its error; the session stays switched. Downlink sends and switches
  of a session are not ordered with each other. `shutdown` closes the TUNs as
  it can, and logs what it could not remove.
- `tun::TunPort::close` tries each resource once and returns the first
  failure.
- `tracing` is built without its default features.
- The keywords take `gtp` in the place of `3gpp`, and the description says 5GS
  and EPS (5G and 4G LTE).

### Removed

- `ExtensionHeaders` and `ExtensionHeadersIntoIter`; `ExtensionHeaders::MAX` is
  `MAX_EXTENSION_HEADERS`.
- `Endpoint::install_s1u`, `Endpoint::supported_extension_headers`,
  `Endpoint::forget_supported_extension_headers`, `Endpoint::set_fast_path`,
  `Endpoint::shortcut` and `FastPath::has_shortcut`.
- `InformationElement::OtherTv`.
- `ipv4_icmp_echo_request`, `ipv4_icmp_echo_reply`, `parse_ipv4_icmp_echo`,
  `EchoKind` and `IcmpEcho`. The echo service of the test UPF still answers
  ICMP Echo Requests.
- `ReceiveStats::suppressed_echo_responses`.
- `UpfSimulator::pending_end_marker`.
- `TunPort::try_close`.
- The feature `serde`.

### Migration from 0.1

| 0.1 | 0.2 |
|-----|-----|
| `ExtensionHeaders::from(vec)`, `vec.into()`, `ExtensionHeaders::new()` | `vec`, `Vec::new()` |
| `ExtensionHeaders::MAX` | `MAX_EXTENSION_HEADERS` |
| `endpoint.install(ran, session, remote, qfi)?` | `endpoint.install(ran, session, remote, Some(qfi))?` |
| `endpoint.install_s1u(ran, erab, remote)` | `endpoint.install(ran, erab, remote, None)?` |
| `endpoint.set_fast_path(fast_path)?` | nothing: keep the `FastPath` |
| `endpoint.shortcut(ran, session, tun)?` | `fast_path.shortcut(tun, local, local_teid, remote, qfi)?` |
| `fast_path.has_shortcut(tun)` | the program knows what it short-cut |
| `endpoint.attach_tun(ran, session, config)?` on an endpoint with a fast path | `let tun = endpoint.attach_tun(ran, session, config)?; fast_path.add_tun(tun)?; fast_path.shortcut(tun, ..)?` |
| `endpoint.supported_extension_headers(peer)` | `PathEvent::SupportedExtensionHeaders` from `path_events()` |
| `InformationElement::OtherTv { kind, value }` | `InformationElement::Other { kind, value }` |
| `ipv4_udp(..)`, `parse_ipv4_udp(..)`, `Expected` | `ip::udp(..)`, `ip::parse_udp(..)`, `ip::Expected` |
| `ipv4_icmp_echo_request(..)`, `parse_ipv4_icmp_echo(..)` | an ICMP builder of the program's own |
| `stats.suppressed_echo_responses` | `stats.suppressed_replies` |
| `upf.pending_end_marker(teid)` | the error of `switch_downlink` |
| `port.try_close()?` | `port.close()?` |
| `port.close()` | `let _ = port.close();` |
| `features = ["serde"]` | none |

## 0.1.0 - 2026-10-24

First release.

- A GTPv1-U codec (TS 29.281): every header field, the chain of extension
  headers with a variant for each type of V19.2.0 §5.2.2, the information
  elements, the PDU Session Container of TS 38.415 V19.1.0 §5.5.2 and the
  PDU Set Information Container of §6.5.2. Decoding never panics, and what
  it decodes encodes to a message that decodes to the same value. A
  message with one extension header at most, as a G-PDU on N3, is decoded
  and encoded without an allocation, and an endpoint sends it without one.
  An `Error` names the `Part` of the message and has the numbers that
  disagree.
- `MessageType`, `ExtensionHeaderType`, `InformationElementType` and
  `Cause`, with the names of the specification.
- `Endpoint`: the N3 socket of a gNB, or the S1-U socket of an eNB, and its
  tunnels, with the replies that TS 29.281 §7 asks of it, within limits
  for what a peer without a tunnel can make it send and log. It sends Echo
  Requests with T3-RESPONSE and N3-REQUESTS, supervises paths as TS 23.007
  §20.3.1 has it, and delivers its peers' path messages (`echo`,
  `supervise`, `path_events`).
- `upf_sim::UpfSimulator` and the `oxirush-upf-sim` program: a UPF to test
  against, without PFCP, with an echo service that a program which
  answers the UE itself turns off.
- `tun` (Linux): TUN devices and their routing, over rtnetlink, for the
  tunnels of an endpoint and the sessions of the test UPF.
- `ebpf` (Linux 6.6, little-endian): TCX programs that carry an
  endpoint's tunnels in the kernel. Their object is committed with its
  source; CI rebuilds it.
- Features `endpoint` (the default), `tun`, `ebpf`, `serde`, and `cli` for
  the program. Without the default features the crate has no dependency.
  Rust 1.88 or later.
