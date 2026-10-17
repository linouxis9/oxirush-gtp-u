//! The side of this crate in the comparison with go-gtp, which
//! `benches/compare.sh` runs and tabulates: a fixed number of operations of
//! one case, and per operation the time, the allocations and their octets.
//! `compare.sh` reads the cycles and the instructions with `perf stat`.
//!
//! ```bash
//! cargo run --release --bin compare -- decode-container 10000000
//! ```
//!
//! The cases, each on a G-PDU with 1400 octets of payload:
//!
//! - `encode-plain`, `encode-container`: a G-PDU without extension header,
//!   as on S1-U, and an uplink one with its PDU Session Container (QFI 9),
//!   as on N3, written into a buffer that is used again;
//! - `decode-plain`, `decode-container`: the same octets read, the payload
//!   left in the datagram;
//! - `round-trip`: a G-PDU from one endpoint to another over the loopback
//!   interface, which sends it back, without PDU Session Container as go-gtp
//!   has none.
//!
//! It prints `case iterations ns/op allocations/op octets/op max-rss-KiB`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use oxirush_gtp_u::{Endpoint, Packet, RemoteTunnel};

/// The system allocator, counting what it is asked for.
struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static OCTETS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every call is passed on to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        OCTETS.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: as the caller of this function promises.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as the caller of this function promises.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        OCTETS.fetch_add(new_size as u64, Ordering::Relaxed);
        // SAFETY: as the caller of this function promises.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const TEID: u32 = 0x1234_5678;
const QFI: u8 = 9;
const OCTETS_OF_PAYLOAD: usize = 1400;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(case), Some(iterations)) = (args.next(), args.next()) else {
        eprintln!("usage: compare <case> <iterations>");
        std::process::exit(2);
    };
    let iterations: u64 = iterations.parse().expect("a number of iterations");
    let payload = vec![0x45_u8; OCTETS_OF_PAYLOAD];
    let plain = Packet::g_pdu(TEID, payload.as_slice());
    let container = Packet::uplink(TEID, QFI, payload.as_slice());
    let (plain_octets, container_octets) = (plain.encode().unwrap(), container.encode().unwrap());
    let mut buffer = Vec::with_capacity(2048);
    let mut sum = 0_usize;

    let mut encode = |packet: &Packet<&[u8]>| {
        let meter = Meter::start();
        for _ in 0..iterations {
            buffer.clear();
            black_box(packet).encode_into(&mut buffer).unwrap();
            sum += black_box(&buffer).len();
        }
        meter.stop()
    };
    let measured = match case.as_str() {
        "encode-plain" => encode(&plain),
        "encode-container" => encode(&container),
        "decode-plain" | "decode-container" => {
            let octets = match case.as_str() {
                "decode-plain" => &plain_octets,
                _ => &container_octets,
            };
            let meter = Meter::start();
            for _ in 0..iterations {
                let packet = Packet::decode_borrowed(black_box(octets)).unwrap();
                sum += black_box(&packet).payload.len();
            }
            meter.stop()
        }
        "round-trip" => round_trip(iterations, &payload),
        _ => panic!("no case {case}"),
    };
    let per = |total: u64| total as f64 / iterations as f64;
    println!(
        "{case} {iterations} {:.1} {:.2} {:.1} {}",
        measured.elapsed.as_nanos() as f64 / iterations as f64,
        per(measured.allocations),
        per(measured.octets),
        max_rss(),
    );
    black_box(sum);
}

/// The time, the allocations and their octets from its start.
struct Meter {
    start: Instant,
    allocations: u64,
    octets: u64,
}

struct Measured {
    elapsed: std::time::Duration,
    allocations: u64,
    octets: u64,
}

impl Meter {
    fn start() -> Self {
        Self {
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
            octets: OCTETS.load(Ordering::Relaxed),
            start: Instant::now(),
        }
    }

    fn stop(self) -> Measured {
        Measured {
            elapsed: self.start.elapsed(),
            allocations: ALLOCATIONS.load(Ordering::Relaxed) - self.allocations,
            octets: OCTETS.load(Ordering::Relaxed) - self.octets,
        }
    }
}

/// `iterations` G-PDUs from an endpoint to another, which sends each back
/// on its tunnel, on one thread.
fn round_trip(iterations: u64, payload: &[u8]) -> Measured {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    runtime.block_on(async {
        let address = "127.0.0.1:0".parse().unwrap();
        let (gnb, mut received) = Endpoint::bind(address).await.unwrap();
        let (upf, mut uplinks) = Endpoint::bind(address).await.unwrap();
        let (gnb_address, upf_address) = (gnb.local_addr().unwrap(), upf.local_addr().unwrap());
        let upf_teid = upf.install_s1u(1, 5, RemoteTunnel::new(gnb_address, 0));
        let gnb_teid = gnb.install_s1u(1, 5, RemoteTunnel::new(upf_address, upf_teid));
        upf.install_s1u(1, 5, RemoteTunnel::new(gnb_address, gnb_teid));
        let reflector = tokio::spawn(async move {
            while let Some(uplink) = uplinks.recv().await {
                upf.send(uplink.ran_id, uplink.session_id, uplink.packet.payload)
                    .await
                    .unwrap();
            }
        });
        let mut sum = 0;
        let meter = Meter::start();
        for _ in 0..iterations {
            gnb.send(1, 5, payload).await.unwrap();
            sum += received.recv().await.unwrap().packet.payload.len();
        }
        let measured = meter.stop();
        reflector.abort();
        black_box(sum);
        measured
    })
}

/// The most memory the process had, in KiB (`VmHWM`).
fn max_rss() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().trim_end_matches(" kB").parse().ok())
        .unwrap_or(0)
}
