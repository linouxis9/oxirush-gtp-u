//! GTP-U for the user plane of 5G and 4G, per 3GPP TS 29.281, with the PDU
//! Session Container of TS 38.415: a codec, an endpoint for the tunnels of a
//! base station, a UPF to test against, Linux TUN devices and an eBPF fast
//! path.
//!
//! ```rust
//! use oxirush_gtp_u::{DownlinkPduSessionInformation, Packet, PduSessionContainer};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
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
//! # Tasks
//!
//! The [README](https://github.com/linouxis9/oxirush-gtp-u#readme) has a
//! program for each, with what it prints.
//!
//! | Task | Items |
//! |------|-------|
//! | Encode and decode a G-PDU | [`Packet`], [`Packet::uplink`], [`Packet::decode_borrowed`], [`PduSessionContainer`] |
//! | Carry a PDU session between a gNB and the test UPF | [`Endpoint`], [`Endpoint::install`], [`Endpoint::send`], [`upf_sim::UpfSimulator`], [`upf_sim::Session`], [`ip::udp`] |
//! | Supervise the path to a peer | [`Endpoint::echo`], [`Endpoint::supervise`], [`Endpoint::path_state`], [`Endpoint::path_events`], [`PathEvent`] |
//! | Answer a peer: Echo and Error Indication | [`Packet::echo_request`], [`InformationElement`] |
//! | Read and write extension headers | [`ExtensionHeader`], [`ExtensionHeaderType`] |
//! | The headers of a handover | [`ExtensionHeader::PdcpPduNumber`], [`Packet::end_marker`] |
//! | Give a tunnel a TUN, on Linux | [`tun::TunConfig`], [`tun::Routing`], [`Endpoint::attach_tun`] |
//! | Carry the tunnel in the kernel, on Linux | [`ebpf::FastPath`], [`ebpf::FastPath::shortcut`] |
//!
// Without its feature an item of the tasks is plain text: the links are checked in the
// build of every feature on Linux, which docs.rs makes.
#![cfg_attr(
    not(all(target_os = "linux", feature = "ebpf")),
    allow(rustdoc::broken_intra_doc_links)
)]
//!
//! It is made for simulators and test tools. It has no control plane: tunnels
//! are set up by calls, with the identifiers and addresses that NGAP, S1AP or
//! PFCP would negotiate.
//!
//! # Features
//!
//! | Part | Feature | Needs |
//! | ---- | ------- | ----- |
//! | The codec ([`Packet`], [`ExtensionHeader`], [`InformationElement`]) and the IPv4 helpers of [`ip`] | none | no dependency |
//! | [`Endpoint`], [`upf_sim`] | `endpoint`, the default | a Tokio runtime |
//! | [`tun`], and `attach_tun` of [`Endpoint`] and [`UpfSimulator`](upf_sim::UpfSimulator) | `tun` | Linux, `CAP_NET_ADMIN` |
//! | [`ebpf`] | `ebpf` | Linux 6.6, `CAP_BPF` and `CAP_NET_ADMIN` |
//!
//! `ebpf` brings `tun`, and `tun` brings `endpoint`. Off
//! Linux, `tun` and `ebpf` build and add nothing; so does `ebpf` on an
//! architecture that its loader, aya, does not build for, such as 32-bit x86,
//! and on a big-endian one, as the programs' object is for little-endian eBPF.
//!
//! # Codec
//!
//! [`Packet`] has every header field of TS 29.281 §5.1, the extension headers
//! in their order and the payload, which is any `AsRef<[u8]>`:
//! [`Packet::decode_borrowed`] leaves it in the datagram. Every extension
//! header of TS 29.281 V19.2.0 §5.2.2 is a variant of [`ExtensionHeader`], with
//! the PDU Session Container of TS 38.415 V19.1.0; the containers of the
//! other frames keep them as octets. Decoding follows the receiver rules of §5.1, keeps what
//! it does not know as received, and never panics; what decodes encodes to a
//! message that decodes to the same value. [`Error`] names the [`Part`] of the
//! message that is wrong, and converts into a `std::io::Error`.
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
//! | Echo, Error Indication, End Marker | The messages with which GTP-U nodes test a path, refuse a G-PDU of an unknown tunnel and close the old path of a handover |
//! | TUN | A network interface of Linux whose packets a program reads and writes |
//!
//! # The OxiRush family
//!
//! - [oxirush-utils](https://docs.rs/oxirush-utils): the 3GPP identities, and the JSON tree with its paths that the others share.
//! - [oxirush-aper](https://docs.rs/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
//! - [oxirush-nas](https://docs.rs/oxirush-nas): the NAS messages of 5GS and EPS.
//! - [oxirush-security](https://docs.rs/oxirush-security): NAS security, AKA and the derivation of keys.
//! - [oxirush-ngap](https://docs.rs/oxirush-ngap): NGAP, between a gNB and an AMF.
//! - [oxirush-s1ap](https://docs.rs/oxirush-s1ap): S1AP, between an eNB and an MME.
//! - [oxirush-gtp-u](https://docs.rs/oxirush-gtp-u): GTP-U tunnels, with a test UPF.
//! - [oxirush-sctp](https://docs.rs/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod extension;
mod ie;
pub mod ip;
mod packet;
mod types;

#[cfg(feature = "endpoint")]
mod datagram;
#[cfg(feature = "endpoint")]
mod icmp;
// The `ebpf` feature on Linux, on a little-endian architecture of aya: see
// build.rs.
#[cfg(fast_path)]
#[cfg_attr(docsrs, doc(cfg(all(target_os = "linux", feature = "ebpf"))))]
#[allow(unsafe_code)]
pub mod ebpf;
#[cfg(feature = "endpoint")]
mod endpoint;
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
pub use endpoint::{Endpoint, PathEvent, PathState, PathTimers, ReceivedPacket, RemoteTunnel};
pub use error::{Error, Part};
pub use extension::{
    DownlinkPduSessionInformation, ExtensionHeader, PduSessionContainer, UnknownNewIes,
    UplinkPduSessionInformation, UplinkTimeStamps,
};
pub use ie::InformationElement;
pub use packet::Packet;
#[cfg(feature = "endpoint")]
pub use stats::ReceiveStats;
pub use types::{Cause, ExtensionHeaderType, InformationElementType, MessageType};

/// The UDP port of GTP-U.
pub const PORT: u16 = 2152;

// What `cargo fuzz` drives, which builds the crate with `--cfg fuzzing`: what a node
// answers, without its socket.
#[cfg(all(fuzzing, feature = "endpoint"))]
#[doc(hidden)]
pub mod fuzzing {
    use std::net::SocketAddr;

    use crate::Packet;

    /// What the endpoint sends for `packet` from `from`, and where, and whether the
    /// packet goes no further: an Echo Response, a Supported Extension Headers
    /// Notification, or none.
    pub fn answer(
        packet: &Packet<&[u8]>,
        from: SocketAddr,
    ) -> (Option<(Packet, SocketAddr)>, bool) {
        crate::path::reply(packet, from)
    }

    /// The Echo Response that answers octets which do not decode for their length: an
    /// Echo Request of a length that is not its own.
    pub fn length_error_response(bytes: &[u8]) -> Option<Packet> {
        crate::path::length_error_response(bytes)
    }

    /// The ICMP Echo Reply of the test UPF to an IPv4 packet.
    pub fn echo_reply(request: &[u8]) -> Option<Vec<u8>> {
        crate::icmp::echo_reply(request)
    }
}

/// The most extension headers that a message is decoded or encoded with: a
/// longer chain is [`Error::TooManyExtensionHeaders`].
///
/// The specification sets no limit. TS 29.281 V19.2.0 has eleven types, which
/// make eight headers at most in one message: two headers have a second type
/// from an earlier release, and a message has the PDCP PDU Number or the long
/// one. Twice that leaves room for the types of later releases, and a datagram
/// that is nothing but headers costs its receiver the first of them and no
/// more.
pub const MAX_EXTENSION_HEADERS: usize = 16;

/// The blocks of the README, which are compiled, and run unless they need
/// privileges, with the documentation tests.
#[cfg(all(doctest, fast_path))]
#[doc = include_str!("../README.md")]
struct _Readme;

/// Runs the unit test `test` on a thread of its own, and ends the run when it takes more
/// than 10 s. A thread that loops for good cannot be stopped, and the run waits for every
/// test: failing the test instead would leave its thread spinning on a processor while the
/// bounded tests after it time out one by one. The tests that the mutants of such a loop
/// hold are bounded so.
#[cfg(test)]
fn bounded(test: impl FnOnce() + Send + 'static) {
    use std::io::Write;
    let name = std::thread::current().name().unwrap_or("a test").to_owned();
    let (done, finished) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        test();
        let _ = done.send(());
    });
    let bound = std::time::Duration::from_secs(10);
    if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = finished.recv_timeout(bound) {
        let _ = writeln!(std::io::stderr(), "{name} still runs after {bound:?}");
        std::process::exit(101);
    }
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}
