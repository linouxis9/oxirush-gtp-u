# Changelog

## 0.1.0 (unreleased)

First release.

- A GTPv1-U codec (TS 29.281): every header field, the chain of extension
  headers with a variant for each type of V19.2.0 §5.2.2, the information
  elements, the PDU Session Container of TS 38.415 V19.1.0 §5.5.2 and the
  PDU Set Information Container of §6.5.2. Decoding never panics, and what
  it decodes encodes to a message that decodes to the same value. A
  message with one extension header at most, as a G-PDU on N3, is decoded
  and encoded without an allocation. An `Error` names the `Part` of the
  message and has the numbers that disagree.
- `MessageType`, `ExtensionHeaderType`, `InformationElementType` and
  `Cause`, with the names of the specification.
- `Endpoint`: the N3 socket of a gNB, or the S1-U socket of an eNB, and its
  tunnels, with the replies that TS 29.281 §7 asks of it, within limits
  for what a peer without a tunnel can make it send and log.
- `upf_sim::UpfSimulator` and the `oxirush-upf-sim` program: a UPF to test
  against, without PFCP.
- `tun` (Linux): TUN devices and their routing, over rtnetlink, for the
  tunnels of an endpoint and the sessions of the test UPF.
- `ebpf` (Linux 6.6, little-endian): TCX programs that carry an
  endpoint's tunnels in the kernel. Their object is committed with its
  source; CI rebuilds it.
- Features `endpoint` (the default), `tun`, `ebpf`, `serde`, and `cli` for
  the program. Without the default features the crate has no dependency.
  Rust 1.88 or later.

### For a program written against this repository before the release

The repository was public before this first release. What changed since its
revision `ac3a019` for a program that uses the crate:

- The fast path is the `ebpf` feature, which was a default feature and is
  not any more: `features = ["ebpf"]` asks for it.
- `ebpf` adds nothing on a big-endian target, such as s390x, where the
  module `ebpf` was built and could not load its object, which is for
  little-endian eBPF.
- The `oxirush-upf-sim` program needs the `cli` feature, which turns on
  the `macros` and `signal` features of Tokio: the library does not use
  them, and its default features turned them on for every program.
  `cargo install --features cli` installs it.
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
- `UpfSimulator::set_session` returns an `io::Result<()>`, where it
  returned nothing and panicked for a QFI above 63: `set_session(..)?`.
  `Session::new` no longer panics for one: the session is refused where it
  is given.
- The local TEIDs that `Endpoint::install` and `install_s1u` return were
  1, 2, 3 and on, and are drawn at random: a program that expected the
  first to be 1 no longer finds it.
- An `Endpoint` and the test UPF answered every G-PDU on a TEID without a
  tunnel with an Error Indication, and every message with an unknown header
  that must be understood with a notification, and logged a line for each
  at DEBUG or WARN. Past 100 replies a second they send none and count them
  in `ReceiveStats::suppressed_replies`, and they log a line once a second
  for each kind.
- `Packet` is `Debug` for a payload that is `AsRef<[u8]>`, where it was for
  one that is `Debug`. What `Debug` prints changed for `Packet`,
  `ExtensionHeader`, `PduSessionContainer`, `UnknownNewIes`,
  `InformationElement`, `RemoteTunnel`, `upf_sim::Session` and
  `upf_sim::UplinkPacket`: names, TEIDs in hexadecimal, octets as
  `2 octets 0700`.
- The rtnetlink requests of the TUN and of the fast path return `TimedOut`
  when the kernel's answer does not come within a second, where they
  waited for ever.
- `FastPath::load` removes the stage that a killed process left only when
  its far end has the alias `oxirush-gtp-u fast path stage`. A stage left
  by an earlier revision has none: `ip link del oxsXXXXXXXXa` removes it.
