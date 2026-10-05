// What the eBPF programs (`programs.rs`, which includes this file) and
// their loader share: the map layouts and the counters.

/// Map `UPLINKS`, by TUN interface: the tunnel its packets leave in.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Uplink {
    /// The N3 address of the RAN node, in network order.
    pub local: [u8; 4],
    /// The N3 address of the peer, in network order.
    pub peer: [u8; 4],
    /// The peer's TEID, in network order.
    pub teid: [u8; 4],
    /// The N3 interface.
    pub n3: u32,
    /// Its MTU: a longer G-PDU is left to the endpoint's socket, which
    /// fragments it.
    pub mtu: u16,
    /// The QFI of the PDU Session Container, or [`NO_CONTAINER`].
    pub qfi: u8,
    pub padding: u8,
}

/// The key of map `DOWNLINKS`, whose value is the tunnel's TUN interface.
#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
pub struct DownlinkKey {
    /// The N3 address of the RAN node, in network order.
    pub local: [u8; 4],
    /// The RAN node's TEID, in network order.
    pub teid: [u8; 4],
}

/// The QFI of a tunnel whose G-PDUs carry no PDU Session Container (S1-U).
pub const NO_CONTAINER: u8 = 0xff;

// The indexes of per-CPU map `STATS`.
/// Packets encapsulated and sent out of N3.
pub const UPLINK_PACKETS: u32 = 0;
/// Packets too long for N3 once encapsulated, returned to the TUN's reader.
pub const UPLINK_OVERSIZED: u32 = 1;
/// Packets a program dropped: a failed helper, or a tunnel removed meanwhile.
pub const UPLINK_DROPS: u32 = 2;
/// Packets decapsulated and delivered to their TUN.
pub const DOWNLINK_PACKETS: u32 = 3;
