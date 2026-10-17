//! GTP-U for the user plane of 5G and 4G, per 3GPP TS 29.281, with the PDU
//! Session Container of TS 38.415: a codec, an endpoint for the tunnels of a
//! base station, a UPF to test against, Linux TUN devices and an eBPF fast
//! path.
//!
//! ```rust
//! use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};
//!
//! fn main() -> Result<(), oxirush_gtp_u::Error> {
//!     // An uplink G-PDU of QoS flow 9, as a gNB sends it on N3: the header,
//!     // the PDU Session Container, then the IP packet
//!     let uplink = Packet::uplink(0x1234_5678, 9, b"an IP packet".as_slice());
//!     let bytes = uplink.encode()?;
//!     println!("{:02x?}", &bytes[..16]);
//!
//!     // Decode it. The payload stays in the datagram
//!     let decoded = Packet::decode_borrowed(&bytes)?;
//!     println!("TEID {:#x}, QFI {:?}", decoded.teid, decoded.qfi());
//!     println!("{:?}", String::from_utf8_lossy(decoded.payload));
//!
//!     // A downlink G-PDU whose container has more than a QFI
//!     let mut information = DownlinkPduSessionInformation::new(9);
//!     information.rqi = true;
//!     let downlink = Packet::g_pdu(0x9abc_def0, b"an IP packet".as_slice())
//!         .with_pdu_session_container(PduSessionContainer::Downlink(information));
//!     let decoded = Packet::decode(&downlink.encode()?)?;
//!     if let Some(PduSessionContainer::Downlink(information)) = decoded.pdu_session_container() {
//!         println!("QFI {}, RQI {}", information.qfi, information.rqi);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ```text
//! [34, ff, 00, 14, 12, 34, 56, 78, 00, 00, 00, 85, 01, 10, 09, 00]
//! TEID 0x12345678, QFI Some(9)
//! "an IP packet"
//! QFI 9, RQI true
//! ```
//!
//! The [README](https://github.com/linouxis9/oxirush-gtp-u#readme) has a
//! program for each task: a tunnel between an endpoint and the test UPF, echo
//! and Error Indication, the extension headers, a TUN, the fast path.
//!
//! It is made for simulators and test tools. It has no control plane: tunnels
//! are set up by calls, with the identifiers and addresses that NGAP, S1AP or
//! PFCP would negotiate.
//!
//! # Where things are
//!
//! | Part | Feature | Needs |
//! | ---- | ------- | ----- |
//! | The codec ([`Packet`], [`ExtensionHeader`], [`InformationElement`]) and the IPv4 helpers | none | no dependency |
//! | `Endpoint`, `upf_sim` | `endpoint`, the default | a Tokio runtime |
//! | `tun`, and `attach_tun` of `Endpoint` and `UpfSimulator` | `tun` | Linux, `CAP_NET_ADMIN` |
//! | `ebpf` | `ebpf` | Linux 6.6, `CAP_BPF` and `CAP_NET_ADMIN` |
//! | `Serialize` and `Deserialize` for `RemoteTunnel` | `serde` | |
//! | The `oxirush-upf-sim` program | `cli` | |
//!
//! `ebpf` brings `tun`, and `tun` brings `endpoint`. The `tun` and `ebpf`
//! modules exist on Linux only; elsewhere their features build and add nothing
//! to `endpoint`. So does `ebpf` on an architecture that its loader, aya, does
//! not build for, such as 32-bit x86: it has 64-bit x86, ARM, AArch64,
//! RISC-V 64, LoongArch 64, MIPS, PowerPC 64 and s390x. The reference of each
//! part is with it: `Endpoint`, and the modules `upf_sim`, `tun` and `ebpf`.
//!
//! # Codec
//!
//! [`Packet`] has every header field of TS 29.281 §5.1, the chain of extension
//! headers and the payload. There are constructors for G-PDU, Echo Request and
//! Response, Error Indication, Supported Extension Headers Notification and End
//! Marker; [`Packet::new`] and [`InformationElement::encode_all`] build any
//! other message.
//!
//! Every extension header of TS 29.281 V19.2.0 §5.2.2 is a variant of
//! [`ExtensionHeader`]. The PDU Session Container has the downlink and uplink
//! PDU Session Information of TS 38.415 V19.1.0 §5.5.2, with the QoS
//! monitoring, sequence number, delay and congestion fields, the downlink
//! Burst Size and Time To Next Burst, and the uplink Available Bitrates. The
//! PDCP PDU Number, the long one and the Service Class Indicator are their
//! numbers. The PDU Set Information Container has the downlink PDU Set
//! Information of TS 38.415 §6.5.2. The RAN Container, the Xw RAN Container
//! and the NR RAN Container are the octets of a frame of TS 36.425, TS 36.465
//! or TS 38.425, which the crate does not read.
//!
//! The numbers that say what a message, an extension header, an information
//! element or a cause is are types that know the names of the specification:
//! [`MessageType`], [`ExtensionHeaderType`], [`InformationElementType`] and
//! [`Cause`]. `Debug` prints these names, a TEID in hexadecimal, and a payload
//! or a value that is kept as received as its length and all its octets in
//! hexadecimal.
//!
//! Decoding follows the receiver rules of §5.1: the flags decide which
//! optional fields are read and the spare bit is ignored. Extension headers,
//! TLV information elements and uplink New IEs that have no type of their own
//! are kept as received. A TV information element imported from TS 29.060 is
//! kept when its fixed length is known; an unknown TV type is an error. What
//! decodes encodes to a message that decodes to the same value.
//!
//! [`Packet::extension_headers`] is an [`ExtensionHeaders`], the chain in its
//! order on the wire: a slice to read and to change, `push` to add a header,
//! and `From` a `Vec` and back for the rest. It keeps its first header in the
//! list itself. A message without extension header, or with one, such as the
//! PDU Session Container of a G-PDU on N3, is decoded and made without an
//! allocation; a second header allocates the list, and a header or a PDU type
//! that is kept as received allocates its octets.
//!
//! `Packet<P>` takes any payload that is `AsRef<[u8]>`, `Vec<u8>` by default.
//! [`Packet::decode_borrowed`] returns a `Packet<&[u8]>` whose payload stays
//! in the datagram, and `into_owned` copies it. `encoded_len` gives the wire
//! length without encoding. `encode_into` appends to a `Vec<u8>` and leaves it
//! as it was on an error. The codec's [`Error`] names the [`Part`] of the
//! message that is wrong and has the numbers that disagree. It converts into
//! a `std::io::Error`, for `?` next to an endpoint's calls.
//!
//! [`ipv4_udp`] and [`ipv4_icmp_echo_request`] build inner packets, and
//! [`parse_ipv4_udp`] and [`parse_ipv4_icmp_echo`] read them, to exercise a
//! tunnel without a TUN. They are IPv4 only; any payload, IPv6 included, is
//! carried as it is.
//!
//! # What it covers
//!
//! | What | API | Specification |
//! |------|-----|---------------|
//! | Messages | `Packet`: every header field, the chain of extension headers, the information elements, and constructors for G-PDU, Echo Request and Response, Error Indication, Supported Extension Headers Notification and End Marker | TS 29.281 §5, §7 and §8 |
//! | Extension headers | `ExtensionHeader`: the UDP Port, the PDCP PDU Number and the long one, the Service Class Indicator, the RAN, Xw RAN and NR RAN containers as octets, and the two below; a header of another type is kept as octets | TS 29.281 §5.2 |
//! | PDU Session Container | `PduSessionContainer`: the downlink and the uplink PDU Session Information, with their QoS monitoring, sequence number, delay and congestion fields | TS 38.415 §5.5.2 |
//! | PDU Set Information Container | `PduSetInformationContainer`: the downlink PDU Set Information | TS 38.415 §6.5.2 |
//! | Tunnels of a gNB or an eNB | `Endpoint`: tunnels by UE and PDU session or E-RAB, and the replies that a node owes its peer | TS 29.281 §4.4 and §7 |
//! | A UPF to test against | `upf_sim::UpfSimulator` and the `oxirush-upf-sim` program: sessions, an echo service, an End Marker on a path switch | |
//! | Linux as the device or as N6 | `tun::TunPort`, `Endpoint::attach_tun`, `UpfSimulator::attach_tun` | |
//! | The tunnels in the kernel | `ebpf::FastPath` | |
//! | Inner packets for tests | `ipv4_udp`, `ipv4_icmp_echo_request` and their parsers | |
//!
//! # Limits
//!
//! | Subject | Limit |
//! |---------|-------|
//! | Control plane | None: no NGAP, S1AP or PFCP. A call gives a tunnel its TEIDs and addresses. |
//! | Authentication | GTP-U has none: anyone who reaches a socket can send on its tunnels. |
//! | A UPF for real traffic | The test UPF serves the sessions that calls give it, with an echo service or a TUN. It has no PFCP, QoS or charging. |
//! | Other GTP | GTP' and the versions 0 and 2 are refused, as `UnsupportedVersion`. |
//! | IPv6 in the helpers, the TUN routing and the fast path | They are IPv4. The codec and the endpoint carry any payload, and an endpoint binds an IPv4 or an IPv6 address. |
//! | Transport QoS and load balancing | Every G-PDU, through the socket or the fast path, has DSCP 0 and source port 2152. TS 29.281 §4.4.1 asks for the DSCP of the QoS flow's 5QI, which a call does not give, and §4.4.2.0 for source ports that vary, which one socket cannot have. |
//! | Portability | `tun` and `ebpf` are Linux only, and `ebpf` adds nothing on 32-bit x86, which aya does not build for. |
//!
//! # Terms
//!
//! | Term | Meaning |
//! |------|---------|
//! | UE, gNB, eNB | The device (User Equipment), and the base station of 5G and of 4G |
//! | UPF | User Plane Function: the node of the 5G core network that carries the traffic of the devices |
//! | N3, S1-U, N6 | The interface between a gNB and a UPF, the one between an eNB and the gateway of a 4G core network, and the one between a UPF and the network that the devices reach |
//! | Tunnel | The path of one PDU session of 5G, or of one bearer of 4G (an E-RAB), between two GTP-U nodes |
//! | TEID | Tunnel Endpoint Identifier: the 32 bits in a GTP-U header that name the tunnel to the node that receives the message. Each end chooses the one it receives on |
//! | G-PDU | The GTP-U message that carries one packet of a device, here an IP packet |
//! | QFI | QoS Flow Identifier: the 6 bits that name the QoS flow of a packet in a 5G tunnel |
//! | PDU Session Container | The extension header of a G-PDU that carries the QFI on N3 (TS 38.415) |
//! | Echo, Error Indication, End Marker | The messages with which GTP-U nodes test a path, refuse a G-PDU of an unknown tunnel and close the old path of a handover |
//! | TUN | A network interface of Linux whose packets a program reads and writes |
//! | TCX | The attachment of eBPF programs to the ingress and the egress of an interface, since Linux 6.6 |
//!
//! # Specifications
//!
//! - 3GPP TS 29.281: GTPv1-U (header, extension headers, messages, information
//!   elements, path management)
//! - 3GPP TS 38.415: NG-RAN PDU Session User Plane protocol (PDU Session
//!   Container, PDU Set Information Container)
//! - 3GPP TS 29.060: imported TV information elements and receive rules
//!
//! # Source layout
//!
//! ```text
//! src/
//! ├── packet.rs              owned and borrowed messages (TS 29.281 §5.1, §6, §7)
//! ├── types.rs               message, header and element types, and causes, by name
//! ├── extension.rs           extension headers and PDU Session Container (TS 38.415)
//! ├── pdu_set.rs             PDU Set Information Container (TS 38.415)
//! ├── headers.rs             the list of the extension headers of a message
//! ├── ie.rs, error.rs         information elements and codec errors
//! ├── ipv4.rs, icmp.rs        inner IPv4 UDP and ICMP Echo packets
//! ├── datagram.rs, path.rs    shared UDP receive and path management (endpoint)
//! ├── limit.rs               the limits of replies and log lines (endpoint)
//! ├── endpoint.rs            gNB endpoint and forwarding (endpoint)
//! ├── endpoint/routes.rs     tunnel identity, route indexes and TUNs (endpoint)
//! ├── stats.rs               receive/drop counters (endpoint)
//! ├── upf_sim.rs             test UPF and forwarding (endpoint)
//! ├── upf_sim/sessions.rs     session generations and handover state (endpoint)
//! ├── tun.rs                 public TUN API (tun)
//! ├── tun/device.rs          TUN descriptor and packet I/O (tun)
//! ├── tun/routing.rs         routing ownership and cleanup (tun)
//! ├── tun/error.rs           contextual I/O errors (tun)
//! ├── netlink.rs             rtnetlink operations (tun)
//! ├── ebpf.rs                loader of the fast path and its tunnels (ebpf)
//! ├── ebpf/layout.rs         map layouts shared with the programs (ebpf)
//! ├── ebpf/programs.rs       the TCX programs: uplink, encap, decap
//! ├── ebpf/gtpu.o            their object, built by ../ebpf (ebpf)
//! └── bin/oxirush-upf-sim.rs
//! ebpf/                      what builds programs.rs for eBPF: build.sh and its manifest
//! examples/                  the programs of the README
//! benches/                   the benchmarks, a package of their own
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod extension;
mod headers;
mod icmp;
mod ie;
mod ipv4;
mod packet;
mod pdu_set;
mod types;

#[cfg(feature = "endpoint")]
mod datagram;
// The `ebpf` feature on Linux, on an architecture of aya: see build.rs.
#[cfg(fast_path)]
#[cfg_attr(docsrs, doc(cfg(all(target_os = "linux", feature = "ebpf"))))]
#[allow(unsafe_code)]
pub mod ebpf;
#[cfg(feature = "endpoint")]
mod endpoint;
#[cfg(feature = "endpoint")]
mod limit;
#[cfg(all(target_os = "linux", feature = "tun"))]
#[allow(unsafe_code)]
mod netlink;
#[cfg(feature = "endpoint")]
mod path;
#[cfg(feature = "endpoint")]
mod stats;
#[cfg(all(target_os = "linux", feature = "tun"))]
#[allow(unsafe_code)]
pub mod tun;
#[cfg(feature = "endpoint")]
pub mod upf_sim;

#[cfg(feature = "endpoint")]
pub use endpoint::{Endpoint, ReceivedPacket, RemoteTunnel};
pub use error::{Error, Expected, Part};
pub use extension::{
    DownlinkPduSessionInformation, ExtensionHeader, PduSessionContainer, UnknownNewIes,
    UplinkPduSessionInformation, UplinkTimeStamps,
};
pub use headers::{ExtensionHeaders, ExtensionHeadersIntoIter};
pub use icmp::{
    EchoKind, IcmpEcho, ipv4_icmp_echo_reply, ipv4_icmp_echo_request, parse_ipv4_icmp_echo,
};
pub use ie::InformationElement;
pub use ipv4::{ipv4_udp, parse_ipv4_udp};
pub use packet::Packet;
pub use pdu_set::{DownlinkPduSetInformation, PduSetInformationContainer};
#[cfg(feature = "endpoint")]
pub use stats::ReceiveStats;
pub use types::{Cause, ExtensionHeaderType, InformationElementType, MessageType};

/// The UDP port of GTP-U.
pub const PORT: u16 = 2152;
