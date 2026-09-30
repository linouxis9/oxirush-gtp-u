#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod extension;
mod icmp;
mod ie;
mod ipv4;
mod packet;

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
pub use endpoint::{Endpoint, ReceivedPacket, RemoteTunnel};
pub use error::Error;
pub use extension::{
    DownlinkPduSessionInformation, ExtensionHeader, PduSessionContainer, UnknownNewIes,
    UplinkPduSessionInformation, UplinkTimeStamps,
};
pub use icmp::{
    EchoKind, IcmpEcho, ipv4_icmp_echo_reply, ipv4_icmp_echo_request, parse_ipv4_icmp_echo,
};
pub use ie::InformationElement;
pub use ipv4::{ipv4_udp, parse_ipv4_udp};
pub use packet::{
    ECHO_REQUEST, ECHO_RESPONSE, END_MARKER, ERROR_INDICATION, G_PDU, Packet,
    SUPPORTED_EXTENSION_HEADERS_NOTIFICATION, TUNNEL_STATUS,
};
#[cfg(feature = "endpoint")]
pub use stats::ReceiveStats;

/// The UDP port of GTP-U.
pub const PORT: u16 = 2152;
