//! GTP-U fast path of the N3 endpoint. What these programs leave alone still
//! goes through userspace: the endpoint's socket and the TUN's reader.
//!
//! This file is no module of `oxirush-gtp-u`: the crate in `ebpf/` builds it
//! for the eBPF target, and `ebpf/build.sh` rebuilds the object the loader
//! embeds, `gtpu.o`.
#![no_std]
#![no_main]

use core::ptr;

use aya_ebpf::Global;
use aya_ebpf::bindings::bpf_adj_room_mode::BPF_ADJ_ROOM_MAC;
use aya_ebpf::bindings::{
    __sk_buff, BPF_F_ADJ_ROOM_DECAP_L3_IPV4, BPF_F_ADJ_ROOM_ENCAP_L3_IPV4,
    BPF_F_ADJ_ROOM_ENCAP_L4_UDP, BPF_F_INGRESS, TC_ACT_SHOT, TC_ACT_UNSPEC,
};
use aya_ebpf::helpers::{
    bpf_redirect, bpf_redirect_neigh, bpf_skb_change_head, bpf_skb_change_type, bpf_skb_load_bytes,
};
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::programs::TcContext;

#[path = "layout.rs"]
mod layout;
use layout::*;

const ETH: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IP: usize = 20;
const UDP: usize = 8;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
const PACKET_HOST: u32 = 0;
const GTPU_PORT: u16 = 2152;
const G_PDU: u8 = 255;
/// PDU Session Container extension header, TS 38.415.
const PSC: u8 = 0x85;
/// The mark of a packet `encap` returns to its TUN, for the TUN's reader.
const TO_READER: u32 = u32::MAX;
/// What a program does not handle goes on to the next TCX program and to the
/// tc filters of the interface: `TC_ACT_OK` would end the chain there.
const NEXT: i32 = TC_ACT_UNSPEC;
/// Tunnels each map holds.
const MAX_TUNNELS: u32 = 65536;

#[map]
static UPLINKS: HashMap<u32, Uplink> = HashMap::with_max_entries(MAX_TUNNELS, 0);

#[map]
static DOWNLINKS: HashMap<DownlinkKey, u32> = HashMap::with_max_entries(MAX_TUNNELS, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DOWNLINK_PACKETS + 1, 0);

/// A veth without checksum offload: the kernel splits the large segments of
/// the UE's TCP stack and completes their checksums when it transmits
/// through it.
#[unsafe(no_mangle)]
static STAGE: Global<u32> = Global::new(0);

#[inline(always)]
fn count(counter: u32) {
    if let Some(value) = STATS.get_ptr_mut(counter) {
        // SAFETY: the map gives each CPU its own value.
        unsafe { *value += 1 };
    }
}

#[inline(always)]
fn load(skb: *mut __sk_buff, offset: usize, to: &mut [u8]) -> bool {
    // SAFETY: the helper fills `to` or fails.
    unsafe {
        bpf_skb_load_bytes(
            skb.cast(),
            offset as u32,
            to.as_mut_ptr().cast(),
            to.len() as u32,
        ) == 0
    }
}

/// Egress of a UE TUN: hand the IPv4 packets of a short-cut tunnel over to
/// the stage, as Ethernet frames. Anything else goes to the TUN's reader.
#[classifier]
pub fn uplink(ctx: TcContext) -> i32 {
    let skb = ctx.skb.skb;
    // SAFETY: the context is this program's packet.
    let (tun, mark, protocol) = unsafe { ((*skb).ifindex, (*skb).mark, (*skb).protocol) };
    if mark == TO_READER
        || protocol != u32::from(ETH_P_IP.to_be())
        || UPLINKS.get_ptr(&tun).is_none()
    {
        return NEXT;
    }
    let mut eth = [0u8; ETH];
    eth[12] = (ETH_P_IP >> 8) as u8;
    eth[13] = ETH_P_IP as u8;
    // SAFETY: helpers on this program's packet.
    unsafe {
        if bpf_skb_change_head(skb, ETH as u32, 0) != 0 || ctx.store(0, &eth, 0).is_err() {
            count(UPLINK_DROPS);
            return TC_ACT_SHOT as i32;
        }
        (*skb).mark = tun;
        bpf_redirect(STAGE.load(), 0) as i32
    }
}

/// Ingress of the stage's far end: encapsulate the packet and route it out
/// of N3.
#[classifier]
pub fn encap(ctx: TcContext) -> i32 {
    let skb = ctx.skb.skb;
    // SAFETY: the context is this program's packet.
    let tun = unsafe { (*skb).mark };
    let Some(up) = UPLINKS.get_ptr(&tun) else {
        // Its tunnel went away meanwhile; unmarked frames are the stage's own.
        if tun != 0 {
            count(UPLINK_DROPS);
        }
        return TC_ACT_SHOT as i32;
    };
    // SAFETY: a map value, valid for this run of the program.
    let up = unsafe { *up };
    let inner = ctx.len() - ETH as u32;
    let gtp: u32 = if up.qfi == NO_CONTAINER { 8 } else { 16 };
    let size = (IP + UDP) as u32 + gtp;
    if inner + size > u32::from(up.mtu) {
        count(UPLINK_OVERSIZED);
        // SAFETY: as above. Egress of a TUN drops the Ethernet header.
        return unsafe {
            (*skb).mark = TO_READER;
            bpf_redirect(tun, 0) as i32
        };
    }

    let mut h = [0u8; IP + UDP + 16];
    h[0] = 0x45;
    h[2] = ((inner + size) >> 8) as u8;
    h[3] = (inner + size) as u8;
    h[6] = 0x40; // don't fragment
    h[8] = 64;
    h[9] = IPPROTO_UDP;
    h[12] = up.local[0];
    h[13] = up.local[1];
    h[14] = up.local[2];
    h[15] = up.local[3];
    h[16] = up.peer[0];
    h[17] = up.peer[1];
    h[18] = up.peer[2];
    h[19] = up.peer[3];
    let mut sum = 0u32;
    let mut word = 0;
    while word < IP {
        sum += (u32::from(h[word]) << 8) | u32::from(h[word + 1]);
        word += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = !((sum & 0xffff) + (sum >> 16));
    h[10] = (sum >> 8) as u8;
    h[11] = sum as u8;
    h[IP] = (GTPU_PORT >> 8) as u8;
    h[IP + 1] = GTPU_PORT as u8;
    h[IP + 2] = (GTPU_PORT >> 8) as u8;
    h[IP + 3] = GTPU_PORT as u8;
    h[IP + 4] = ((inner + UDP as u32 + gtp) >> 8) as u8;
    h[IP + 5] = (inner + UDP as u32 + gtp) as u8;
    // TS 29.281 §5.1: version 1, GTP; with the E flag, the three optional
    // fields and the container: UL PDU SESSION INFORMATION and the QFI.
    let g = IP + UDP;
    h[g] = if gtp == 8 { 0x30 } else { 0x34 };
    h[g + 1] = G_PDU;
    h[g + 2] = ((inner + gtp - 8) >> 8) as u8;
    h[g + 3] = (inner + gtp - 8) as u8;
    h[g + 4] = up.teid[0];
    h[g + 5] = up.teid[1];
    h[g + 6] = up.teid[2];
    h[g + 7] = up.teid[3];
    h[g + 11] = PSC;
    h[g + 12] = 1;
    h[g + 13] = 0x10;
    h[g + 14] = up.qfi;

    let flags = u64::from(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP);
    let stored = ctx
        .adjust_room(size as i32, BPF_ADJ_ROOM_MAC, flags)
        .is_ok()
        && if gtp == 8 {
            // SAFETY: the first 36 octets of `h`.
            ctx.store(ETH, unsafe { &*h.as_ptr().cast::<[u8; IP + UDP + 8]>() }, 0)
                .is_ok()
        } else {
            ctx.store(ETH, &h, 0).is_ok()
        };
    // SAFETY: helpers on this program's packet. The stage's far end took the
    // frame for another host's: a loopback N3 would drop it as such.
    unsafe {
        if !stored || bpf_skb_change_type(skb, PACKET_HOST) != 0 {
            count(UPLINK_DROPS);
            return TC_ACT_SHOT as i32;
        }
        (*skb).mark = 0;
        count(UPLINK_PACKETS);
        bpf_redirect_neigh(up.n3, ptr::null_mut(), 0, 0) as i32
    }
}

/// Ingress of N3: decapsulate the G-PDUs of short-cut tunnels into their
/// TUN.
#[classifier]
pub fn decap(ctx: TcContext) -> i32 {
    let skb = ctx.skb.skb;
    let pass = NEXT;
    // SAFETY: the context is this program's packet.
    let (protocol, segments) = unsafe { ((*skb).protocol, (*skb).gso_segs) };
    // Up to an inner IPv4 header behind the shortest GTP-U header.
    let mut h = [0u8; ETH + IP + UDP + 8 + IP];
    if protocol != u32::from(ETH_P_IP.to_be()) || segments > 1 || !load(skb, 0, &mut h) {
        return pass;
    }
    let (ip, udp, g) = (ETH, ETH + IP, ETH + IP + UDP);
    let fragment = (u16::from(h[ip + 6]) << 8 | u16::from(h[ip + 7])) & 0x3fff;
    let port = u16::from(h[udp + 2]) << 8 | u16::from(h[udp + 3]);
    if h[ip] != 0x45 || h[ip + 9] != IPPROTO_UDP || fragment != 0 || port != GTPU_PORT {
        return pass;
    }
    // Version 1, GTP. With any of the E, S and PN flags the three optional
    // fields are present; the only extension header handled here is a PDU
    // Session Container.
    let flags = h[g];
    if flags & 0xf0 != 0x30 || h[g + 1] != G_PDU {
        return pass;
    }
    let gtp = if flags & 0x07 == 0 {
        8
    } else if flags & 0x04 == 0 {
        12
    } else if h[g + 11] == PSC && h[g + 12] == 1 && h[g + 15] == 0 {
        16
    } else {
        return pass;
    };
    // The decoder in userspace judges a message that is not as long as it says.
    let datagram = u32::from(h[udp + 4]) << 8 | u32::from(h[udp + 5]);
    let message = u32::from(h[g + 2]) << 8 | u32::from(h[g + 3]);
    if message + 8 + UDP as u32 != datagram {
        return pass;
    }
    let key = DownlinkKey {
        local: [h[ip + 16], h[ip + 17], h[ip + 18], h[ip + 19]],
        teid: [h[g + 4], h[g + 5], h[g + 6], h[g + 7]],
    };
    let Some(tun) = DOWNLINKS.get_ptr(&key) else {
        return pass;
    };
    // SAFETY: a map value, valid for this run of the program.
    let tun = unsafe { *tun };

    // IPv4 only. ICMP Echo Replies stay in userspace, which hands them to the
    // TUN and to whoever pings through the endpoint.
    let size = IP + UDP + gtp;
    let mut inner = [0u8; IP];
    if !load(skb, ETH + size, &mut inner) || inner[0] >> 4 != 4 {
        return pass;
    }
    if inner[9] == IPPROTO_ICMP {
        let mut kind = [0u8; 1];
        let header = usize::from(inner[0] & 0x0f) * 4;
        if !load(skb, ETH + size + header, &mut kind) || kind[0] == 0 {
            return pass;
        }
    }
    let flags = u64::from(BPF_F_ADJ_ROOM_DECAP_L3_IPV4);
    if ctx
        .adjust_room(-(size as i32), BPF_ADJ_ROOM_MAC, flags)
        .is_err()
    {
        return pass;
    }
    count(DOWNLINK_PACKETS);
    // SAFETY: a helper.
    unsafe { bpf_redirect(tun, u64::from(BPF_F_INGRESS)) as i32 }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 11] = *b"Apache-2.0\0";
