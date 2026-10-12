//! What the codec asks of the allocator for one message: nothing for a
//! G-PDU without extension header or with one, the payload left in the
//! datagram, and nothing to make such a message and encode it into a buffer
//! that is used again.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use oxirush_gtp_u::{
    DownlinkPduSessionInformation, Error, ExtensionHeader, Packet, PduSessionContainer,
    UnknownNewIes, UplinkPduSessionInformation, UplinkTimeStamps,
};

thread_local! {
    /// The allocations and reallocations that this thread has made.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, which counts what each thread asks of it.
struct Counting;

fn count() {
    // A `Cell` with a constant initializer and no destructor: reading it
    // allocates nothing, and it is there for as long as the thread.
    let _ = ALLOCATIONS.try_with(|allocations| allocations.set(allocations.get() + 1));
}

// SAFETY: every method passes its arguments to the system allocator as it got
// them and returns what that allocator returns, so the contract of
// `GlobalAlloc` is the one that `System` keeps.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller's layout, unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller's layout, unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count();
        // SAFETY: the caller's block, layout and new size, unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller's block and layout, unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// What `work` returns, and the allocations that it made on this thread.
fn allocations<R>(work: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.get();
    let result = work();
    (result, ALLOCATIONS.get() - before)
}

/// A G-PDU as it is on S1-U, on N3 in both directions, with every field of
/// a PDU Session Container that this crate decodes, and an Error Indication
/// with its UDP Port.
fn usual_messages(payload: &[u8]) -> Vec<Packet> {
    let mut downlink = DownlinkPduSessionInformation::new(9);
    downlink.rqi = true;
    downlink.ppi = Some(3);
    downlink.dl_sending_time_stamp = Some(0x0102_0304_0506_0708);
    downlink.dl_qfi_sequence_number = Some(0x0a_0b0c);
    downlink.dl_mbs_qfi_sequence_number = Some(0x1122_3344);
    downlink.burst_size = Some(0x01_0203);
    downlink.time_to_next_burst = Some(0x0405);
    let mut uplink = UplinkPduSessionInformation::new(9);
    uplink.time_stamps = Some(UplinkTimeStamps {
        dl_sending_repeated: 1,
        dl_received: 2,
        ul_sending: 3,
    });
    uplink.dl_delay_result = Some(4);
    uplink.ul_delay_result = Some(5);
    uplink.ul_qfi_sequence_number = Some(6);
    uplink.n3_n9_delay_result = Some(7);
    uplink.d1_ul_pdcp_delay_result_ind = Some(true);
    uplink.ul_congestion_information = Some(9574);
    uplink.dl_congestion_information = Some(1000);
    let mut indication = Packet::error_indication(7, [192, 0, 2, 1].into());
    indication
        .extension_headers
        .push(ExtensionHeader::UdpPort(40000));
    vec![
        Packet::g_pdu(1, payload.to_vec()),
        Packet::uplink(1, 9, payload.to_vec()),
        Packet::downlink(1, 9, payload.to_vec()),
        Packet::g_pdu(1, payload.to_vec())
            .with_pdu_session_container(PduSessionContainer::Downlink(downlink)),
        Packet::g_pdu(1, payload.to_vec())
            .with_pdu_session_container(PduSessionContainer::Uplink(uplink)),
        indication,
    ]
}

#[test]
fn a_message_with_at_most_one_extension_header_decodes_without_allocating() {
    for message in usual_messages(&[0x45; 64]) {
        let datagram = message.encode().unwrap();
        let (decoded, count) = allocations(|| Packet::decode_borrowed(&datagram));
        assert_eq!(count, 0, "{message:?}");
        assert_eq!(decoded.unwrap().into_owned(), message);
        // An owned message has the copy of its payload, and nothing else.
        let (decoded, count) = allocations(|| Packet::decode(&datagram));
        assert_eq!(count, 1, "{message:?}");
        assert_eq!(decoded.unwrap(), message);
    }
}

#[test]
fn a_g_pdu_is_made_and_encoded_into_a_used_buffer_without_allocating() {
    let payload = [0x45; 64];
    let mut buffer = Vec::with_capacity(128);
    type Make = fn(&[u8]) -> Packet<&[u8]>;
    let makers: [Make; 3] = [
        |payload| Packet::g_pdu(1, payload),
        |payload| Packet::uplink(1, 9, payload),
        |payload| Packet::downlink(1, 9, payload),
    ];
    for make in makers {
        buffer.clear();
        let (encoded, count) = allocations(|| make(&payload[..]).encode_into(&mut buffer));
        assert_eq!((encoded, count), (Ok(()), 0));
        assert_eq!(
            Packet::decode_borrowed(&buffer).unwrap(),
            make(&payload[..])
        );
    }
}

#[test]
fn a_chain_of_extension_headers_allocates_its_list_and_the_octets_it_keeps() {
    let mut message = Packet::uplink(1, 9, vec![0x45; 64]);
    message
        .extension_headers
        .push(ExtensionHeader::UdpPort(2152));
    message.extension_headers.push(ExtensionHeader::Other {
        kind: ExtensionHeader::SERVICE_CLASS_INDICATOR,
        content: vec![7, 0],
    });
    let datagram = message.encode().unwrap();
    let (decoded, count) = allocations(|| Packet::decode_borrowed(&datagram));
    // The list, and the octets of the header that is kept as received.
    assert_eq!(count, 2);
    assert_eq!(decoded.unwrap().into_owned(), message);

    // New IEs of a later release, in a container that is alone: their
    // flags, their octets, and where the two are kept.
    let mut uplink = UplinkPduSessionInformation::new(9);
    uplink.unknown_new_ies = Some(Box::new(UnknownNewIes {
        flags: vec![0x88, 0x01],
        content: vec![0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00],
    }));
    let message = Packet::g_pdu(1, vec![0x45; 64])
        .with_pdu_session_container(PduSessionContainer::Uplink(uplink));
    let datagram = message.encode().unwrap();
    let (decoded, count) = allocations(|| Packet::decode_borrowed(&datagram));
    assert_eq!(count, 3);
    assert_eq!(decoded.unwrap().into_owned(), message);
}

/// A datagram holds 16 382 extension headers at most, of four octets each:
/// the decoder makes a list of that many, which grows as a `Vec` does, and
/// a chain that ends badly gives the list back.
#[test]
fn the_longest_chain_of_a_datagram_is_a_bounded_list() {
    const HEADERS: usize = (65535 - 4) / 4;
    let mut message = Packet::g_pdu(1, vec![]);
    for port in 0..HEADERS {
        message
            .extension_headers
            .push(ExtensionHeader::UdpPort(port as u16));
    }
    let datagram = message.encode().unwrap();
    assert_eq!(datagram.len(), 8 + 4 + 4 * HEADERS);
    let (decoded, count) = allocations(|| Packet::decode_borrowed(&datagram));
    let decoded = decoded.unwrap();
    assert_eq!(decoded.extension_headers.len(), HEADERS);
    assert!(count <= 16, "{count} allocations");
    assert_eq!(decoded.into_owned(), message);

    // One more header does not fit the length of a message.
    message.extension_headers.push(ExtensionHeader::UdpPort(0));
    assert_eq!(message.encode(), Err(Error::OutOfRange("GTP-U length")));

    // The last header of the chain says that it has no octets, or more than
    // the datagram has, or that another follows.
    let last = datagram.len() - 4;
    for (index, octet, error) in [
        (last, 0, Error::InvalidLength("extension header")),
        (last, 2, Error::Truncated("extension header")),
        (last + 3, 0x40, Error::Truncated("extension header")),
    ] {
        let mut cut = datagram.clone();
        cut[index] = octet;
        let (decoded, count) = allocations(|| Packet::decode_borrowed(&cut).map(|_| ()));
        assert_eq!(decoded, Err(error));
        assert!(count <= 16, "{count} allocations");
    }
}
