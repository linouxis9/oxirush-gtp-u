# Changelog

## 0.1.0 (unreleased)

First release.

- GTPv1-U codec (TS 29.281): every header field, extension header chains,
  information elements, and constructors for Echo Request and Response, Error
  Indication, Supported Extension Headers Notification, End Marker and
  G-PDUs. Decoding follows the receiver rules of §5.1 and never panics;
  what it produces encodes to a message that decodes to the same value.
  Its `Error` names the part of the message that is wrong (`Part`) and has
  the numbers that disagree, as in "truncated GTP-U message: the Length
  field says 9 octets after the header, the datagram has 1". It converts
  into a `std::io::Error`.
- `MessageType`, `ExtensionHeaderType`, `InformationElementType` and
  `Cause`: the numbers that say what a message, an extension header, an
  information element or a cause is, with a constant for each that the
  specification names. Any number is a value; `Display` prints the name or
  the number, and `Debug` both, as `G-PDU (255)`. `Debug` of a message
  prints its TEID in hexadecimal and its payload as its length and all its
  octets in hexadecimal, as it does for every TEID and for what is kept as
  received.
- `ExtensionHeaders`, the list of a message's extension headers
  (`Packet::extension_headers`): a slice to read and to change, `push`,
  `extend` and `clear`; it is made from a `Vec`, an array or one header,
  and gives its headers back as a `Vec`. It keeps its first header in
  itself. A message without extension header,
  or with one, such as the PDU Session Container of a G-PDU on N3, is
  decoded with its payload left in the datagram, and made and encoded into a
  buffer that is used again, without an allocation
  (`tests/allocations.rs`). A second header allocates the list; a header
  and a PDU type that are kept as received, and the new IEs of a later
  release, allocate their octets. A message is decoded and encoded with 16
  extension headers at most (`ExtensionHeaders::MAX`): the specification
  sets no limit and its types make eight at most, and a datagram that is
  nothing but headers, of which it holds more than 16 000, is refused at
  its seventeenth, as `Error::TooManyExtensionHeaders`.
- Every extension header of TS 29.281 V19.2.0 §5.2.2 has a variant of
  `ExtensionHeader`: the UDP Port, the PDU Session Container, the PDCP PDU
  Number and the Long PDCP PDU Number of a handover, the Service Class
  Indicator, the RAN Container, the Xw RAN Container and the NR RAN
  Container, whose frames stay octets, and the PDU Set Information
  Container with the downlink PDU Set Information of TS 38.415 §6.5.2. A
  header of another type is kept as its octets. `examples/handover.rs` has
  the headers of a handover.
- PDU Session Container (TS 38.415 V19.1.0 §5.5.2): downlink and uplink
  PDU Session Information with their QoS monitoring, sequence number, delay
  and congestion fields, and the uplink UL and DL Available Bitrate; new IEs
  of later releases are kept as received. A test
  compares the wire format with Wireshark's dissector (`tests/wireshark.rs`,
  which CI runs).
- Downlink Burst Size and Time To Next Burst are typed and preserved with
  their BSSI/TTNBI flags. Imported TS 29.060 TV IEs retain their values and
  signaling IEs use the required order; Echo Response includes the rejection
  Cause when mandatory Echo Request fields are missing.
- `Endpoint`: a gNB's N3 socket and tunnels. It answers Echo Requests,
  sends Error Indication and Supported Extension Headers Notification to
  port 2152, and delivers G-PDUs, End Markers and the peer's Error
  Indications with their source address; the TEID alone identifies a
  tunnel. A G-PDU is delivered with every extension header that has a
  variant, so with those of a handover and of the RAN protocols, and one
  without a packet goes to the receiver of a tunnel that has a TUN. `install_s1u` gives an eNB's S1-U tunnels, without a PDU Session
  Container. `install` returns an `io::Result`: a QFI above 63 is
  `InvalidInput`, as with `install_with_teid`.
- An endpoint finds the tunnel that an Error Indication names, and the
  tunnels of a UE for `remove_ran`, in an index: neither walks through the
  tunnels, so an Error Indication, which anyone who reaches the socket can
  send, costs with 100 000 tunnels what it costs with 1 000. Of several
  tunnels to one TEID of a peer, the Error Indication is delivered for the
  first by RAN UE and session.
- Endpoint and test-UPF binding require a specific local IP address;
  wildcard addresses return `InvalidInput` to preserve reply source addresses.
  TUN attachment and session replacement check the session's identity so a
  concurrent operation cannot attach a device to a replacement session.
- `upf_sim::UpfSimulator` and the `oxirush-upf-sim` binary: a test UPF with
  an IPv4 UDP and ICMP echo service, End Marker on a path switch, and an
  optional TUN per session.
- `tun::TunPort` (Linux, `tun` feature): TUN devices with policy, VRF or UPF
  routing set up over rtnetlink, and without IPv6 addresses, so Linux sends
  nothing through them unasked. A `TunPort` is `Clone`: clones share the
  device, and the TUN goes with the last one or on `close`.
- `Endpoint::attach_tun` (Linux, `tun` feature): gives a tunnel a TUN and
  carries its packets both ways, as `UpfSimulator::attach_tun` does for a
  session. The tunnel's G-PDUs then go to Linux instead of the receiver.
  The TUN closes with its tunnel, on the endpoint's `shutdown` and with its
  last clone.
- IPv4 UDP and ICMP Echo helpers to exercise tunnels without a TUN.
- `ebpf::FastPath` (Linux 6.6, `ebpf` feature): three TCX programs carry an
  endpoint's tunnels in the kernel between a TUN and N3
  (`FastPath::load`, `add_tun`, `remove_tun`, `end_shortcut` and `stats`,
  `Endpoint::set_fast_path`, `Endpoint::shortcut`, `TunPort::index`); on an
  endpoint with a fast path `attach_tun` does it for the TUN it makes. The
  tunnel's route updates and ends its short-cut, as does the endpoint's
  `shutdown`; a tunnel has one short-cut. What the programs leave
  alone still goes through the endpoint's socket and the TUN's reader, and
  on to the interface's other TCX programs and tc filters. N3 is the
  interface Linux routes the tunnel through; it gets its program when a
  first tunnel through it is installed, off the caller's task. The
  programs' object is committed next to its source
  (`src/ebpf/programs.rs`), and `ebpf/` has what rebuilds it, in the
  repository and in the published crate; CI rebuilds it and compares.
- Examples: `codec`, `extension_headers`, `endpoint`, `path` (echo and
  Error Indication), and on Linux as root `tun` and `fast_path`. The README
  shows them: a test compares the two, and what those that need no root
  print with the text that the README shows under them.
- Features: `endpoint` (the default), `tun`, `ebpf` and `serde`. Without
  default features the crate has no dependencies. The fast path is not a
  default feature: a crate that only decodes packets would otherwise build
  an eBPF loader and the rtnetlink crates. The minimum supported Rust
  version is 1.88.
- A `SECURITY.md` that says how to report a vulnerability.
- `benches/`, a package of its own that times a G-PDU through the codec
  and through an endpoint with criterion and profiles them with pprof. The
  published crate does not have it.

### For a program written against this repository before the release

The repository was public before this first release. What changed since its
revision `ac3a019` for a program that uses the crate:

- The fast path is the `ebpf` feature, which was a default feature and is
  not any more: `features = ["ebpf"]` asks for it.
- `Packet::extension_headers` was a `Vec<ExtensionHeader>` and is an
  `ExtensionHeaders`:
  - reading it is written as before: `iter`, `len`, `is_empty`, `first`,
    an index, `for header in &packet.extension_headers`, and `==` with a
    `Vec`, a slice or an array of headers on its right;
  - so are `push`, `extend`, `clear`, `iter_mut` and an assignment to an
    index;
  - `packet.extension_headers = vec![a, b]` becomes `= vec![a, b].into()`
    or `= ExtensionHeaders::from([a, b])`, and `Vec::new()` becomes
    `ExtensionHeaders::new()`;
  - what a `Vec` has and a slice has not (`pop`, `insert`, `remove`,
    `retain`, `truncate`, `drain`) goes through a `Vec`:
    `Vec::from(list)`, then `.into()` back;
  - `for header in packet.extension_headers` still gives the headers by
    value, from an `ExtensionHeadersIntoIter` where it was a
    `std::vec::IntoIter<ExtensionHeader>`;
  - a function that took the field as `&Vec<ExtensionHeader>` takes
    `&[ExtensionHeader]`, or `&ExtensionHeaders`.
- `UplinkPduSessionInformation::unknown_new_ies` was an
  `Option<UnknownNewIes>` and is an `Option<Box<UnknownNewIes>>`:
  `Some(UnknownNewIes { .. })` becomes `Some(Box::new(UnknownNewIes { .. }))`,
  and reading its `flags` and `content` is written as before. An
  `ExtensionHeader` is 104 octets where it was 128.
- `UplinkPduSessionInformation` has `ul_available_bitrate` and
  `dl_available_bitrate`, the New IEs of Flags 3 and 4 of TS 38.415 V19:
  a container that has them decodes to these fields, where they were in
  `unknown_new_ies` with the flags `0x08` and `0x10`, which the encoder now
  refuses there.
- A `Packet` is 80 octets longer in memory, 144 with a `Vec<u8>` payload:
  the header that its list keeps.
- The variants of `Error` named their part with a text, which a program
  could only compare. They name it with a `Part` and have their numbers:
  - `Truncated("extension header")` is `Truncated { what:
    Part::ExtensionHeader, needed, available }`, and likewise for the other
    parts. A UDP datagram whose length says more than its packet has is
    `Truncated` too, where it was `InvalidLength("UDP")`.
  - `InvalidLength("GTP-U message")` is `InvalidLength { what:
    Part::Message, length, expected }`. The lengths of an extension header
    count its length and next type octets.
  - `OutOfRange("QFI")` is `OutOfRange { what: Part::Qfi, value, max }`;
    `OutOfRange("GTP-U length")` has `Part::Length`, and
    `OutOfRange("extension header length")` `Part::ExtensionHeader`, with
    its octets.
  - A value kept as octets under a type that is not its own was
    `OutOfRange("extension header type")`, `("TV information element
    type")`, `("TLV information element type")` or `("PDU Session Container
    PDU type")`: it is `InvalidType { what, kind }`.
  - `OutOfRange("burst information without PPI")` is
    `Missing(Part::Ppi)`, and `OutOfRange("New IE Flags")` is
    `Malformed(Part::NewIeFlags)`.
  - `UnexpectedPacket("not UDP")` is `UnexpectedPacket(Expected::Udp)`,
    and likewise `Ipv4`, `Icmp`, `Unfragmented`, `IcmpEcho` and
    `IcmpEchoRequest`.
  - `InvalidChecksum("UDP")` is `InvalidChecksum { what:
    Part::UdpDatagram, received, computed }`, and likewise
    `Part::Ipv4Header` and `Part::IcmpMessage`.
  - What `Display` prints has these numbers after the text that it printed.
- The types of messages, extension headers and information elements were
  `u8`, with constants in three places. They are types of their own:
  - `G_PDU`, `ECHO_REQUEST`, `ECHO_RESPONSE`, `ERROR_INDICATION`,
    `SUPPORTED_EXTENSION_HEADERS_NOTIFICATION`, `TUNNEL_STATUS` and
    `END_MARKER` are `MessageType::G_PDU` and so on. `Packet::message_type`
    is a `MessageType`, and `Packet::new` takes one: `MessageType(77)` for
    a number without a name, `.0` for the number of a value.
  - `ExtensionHeader::UDP_PORT` and the other constants of
    `ExtensionHeader` are `ExtensionHeaderType::UDP_PORT` and so on.
    `ExtensionHeader::kind` returns an `ExtensionHeaderType`, and so is
    the `kind` of `ExtensionHeader::Other`.
  - `InformationElement::RECOVERY` and the other constants of
    `InformationElement` are `InformationElementType::RECOVERY` and so on.
    `InformationElement::kind` returns an `InformationElementType`, and
    so are the `kind` of `OtherTv` and `Other` and the value of
    `Error::UnknownInformationElement`.
  - `InformationElement::ExtensionHeaderTypeList` holds a
    `Vec<ExtensionHeaderType>`, and
    `Packet::supported_extension_headers_notification` takes a
    `&[ExtensionHeaderType]`.
  - A Cause (type 1) is decoded as `InformationElement::Cause(Cause)`,
    where it was `OtherTv { kind: 1, value }`, which the encoder now
    refuses. The Echo Response to an Echo Request that is not well formed
    has `Cause::INVALID_MESSAGE_FORMAT`.
- `ExtensionHeader` has variants for the types that it kept as
  `Other { kind, content }`: `PdcpPduNumber(u16)` (0xc0),
  `LongPdcpPduNumber { number, legacy_type }` (0x03, and 0x82 with
  `legacy_type`), `ServiceClassIndicator(u8)` (0x20), `RanContainer`,
  `XwRanContainer` and `NrRanContainer` with the octets that were the
  `content` (0x81, 0x83, 0x84), and `PduSetInformationContainer {
  information, legacy_type }` (0x04, and 0x86). A message with one of these
  decodes to its variant, and the encoder refuses the type as `Other`. A
  PDCP PDU Number, a Long PDCP PDU Number or a Service Class Indicator of
  another length than its own is an error, where any length was kept, and
  the spare bits of the last two are not kept.
- An `Endpoint` and the test UPF refused a message whose PDCP PDU Number,
  RAN, Xw RAN or NR RAN Container, or Long PDCP PDU Number or PDU Set
  Information Container of the earlier type, they did not know, and
  answered a G-PDU with a Supported Extension Headers Notification. They
  deliver it, and the notification lists the eleven types
  (`ExtensionHeader::TYPES`).
- `Packet` is `Debug` for a payload that is `AsRef<[u8]>`, where it was for
  one that is `Debug`. What `Debug` prints changed for `Packet`,
  `ExtensionHeader`, `PduSessionContainer`, `UnknownNewIes`,
  `InformationElement`, `RemoteTunnel`, `upf_sim::Session` and
  `upf_sim::UplinkPacket`: names, TEIDs in hexadecimal, octets as
  `2 octets 0700`.
