//! The time of a G-PDU through the codec and through an endpoint, and
//! their CPU profile.
//!
//! ```bash
//! cargo bench --bench packets                    # every case
//! cargo bench --bench packets -- decode          # those whose name has it
//! cargo bench --bench packets -- --profile-time 10 endpoint/round-trip/1400
//! go tool pprof -top target/criterion/endpoint/round-trip/1400/profile/profile.pb
//! ```
//!
//! A benchmark is `group/case/octets`, the octets being those of the inner
//! packet: a small one (64) and one that fills an Ethernet frame (1400). The
//! case of a decoding is the chain of extension headers of the message, as
//! in `decode-borrowed/container/64`.
//! With `--profile-time`, criterion runs the benchmark for that many
//! seconds under pprof, which samples the program a thousand times a second
//! and writes `profile.pb`, a profile that `go tool pprof` reads. With
//! `PROFILE=flamegraph` in the environment it writes `flamegraph.svg`
//! instead.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oxirush_gtp_u::upf_sim::{Session, UpfSimulator};
use oxirush_gtp_u::{
    Endpoint, ExtensionHeader, ExtensionHeaderType, Packet, RemoteTunnel, ipv4_udp,
};
use oxirush_gtp_u_benches::payload;
use pprof::criterion::{Output, PProfProfiler};
use std::hint::black_box;
use std::time::Duration;

const SIZES: [usize; 2] = [64, 1400];
const TEID: u32 = 0x1234_5678;
const QFI: u8 = 9;

/// An uplink G-PDU with its PDU Session Container, as a gNB sends it on N3.
fn encode(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("encode");
    for octets in SIZES {
        let inner = payload(octets);
        group.throughput(Throughput::Bytes(octets as u64));
        // A new buffer for each message
        group.bench_function(BenchmarkId::new("new-buffer", octets), |bencher| {
            bencher.iter(|| Packet::uplink(TEID, QFI, black_box(inner.as_slice())).encode())
        });
        // One buffer for all of them
        let mut buffer = Vec::with_capacity(octets + 64);
        group.bench_function(BenchmarkId::new("same-buffer", octets), |bencher| {
            bencher.iter(|| {
                buffer.clear();
                Packet::uplink(TEID, QFI, black_box(inner.as_slice())).encode_into(&mut buffer)
            })
        });
    }
    group.finish();
}

/// The datagrams of a G-PDU with the chains of extension headers that a
/// receiver meets: none, as on S1-U; the PDU Session Container alone, as on
/// N3; and three, of which one is of a type that the crate keeps as octets.
fn chains(octets: usize) -> [(&'static str, Vec<u8>); 3] {
    let mut three = Packet::uplink(TEID, QFI, payload(octets));
    three.extension_headers.push(ExtensionHeader::UdpPort(2152));
    three.extension_headers.push(ExtensionHeader::Other {
        kind: ExtensionHeaderType(0x21),
        content: vec![7, 0],
    });
    [
        ("no-header", Packet::g_pdu(TEID, payload(octets))),
        ("container", Packet::uplink(TEID, QFI, payload(octets))),
        ("three-headers", three),
    ]
    .map(|(chain, packet)| (chain, packet.encode().expect("the message encodes")))
}

/// A G-PDU from its octets, the payload left in the datagram.
fn decode_borrowed(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decode-borrowed");
    for octets in SIZES {
        group.throughput(Throughput::Bytes(octets as u64));
        for (chain, datagram) in chains(octets) {
            group.bench_function(BenchmarkId::new(chain, octets), |bencher| {
                bencher.iter(|| Packet::decode_borrowed(black_box(&datagram)))
            });
        }
    }
    group.finish();
}

/// The same, the payload copied into the message.
fn decode_owned(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decode-owned");
    for octets in SIZES {
        group.throughput(Throughput::Bytes(octets as u64));
        for (chain, datagram) in chains(octets) {
            group.bench_function(BenchmarkId::new(chain, octets), |bencher| {
                bencher.iter(|| Packet::decode(black_box(&datagram)))
            });
        }
    }
    group.finish();
}

/// An inner packet from a gNB endpoint to the test UPF and its echo back,
/// over the loopback interface: two G-PDUs, four system calls and the
/// tasks of both sides.
fn endpoint(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("a runtime");
    let (gnb, mut received, _upf, _observed) = runtime.block_on(async {
        let (upf, observed) = UpfSimulator::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("the test UPF binds");
        let (gnb, received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("the endpoint binds");
        let remote = RemoteTunnel::new(upf.local_addr().unwrap(), 0x1001);
        let teid = gnb.install(1, 5, remote, QFI).expect("the tunnel");
        upf.set_session(Session::new(0x1001, teid, gnb.local_addr().unwrap(), QFI))
            .unwrap();
        (gnb, received, upf, observed)
    });

    let mut group = criterion.benchmark_group("endpoint");
    let (ue, server) = (
        "10.45.0.2:4000".parse().unwrap(),
        "192.0.2.1:7".parse().unwrap(),
    );
    for octets in SIZES {
        // The inner packet is IPv4 and UDP around the octets
        let inner = ipv4_udp(ue, server, &payload(octets - 28)).expect("an inner packet");
        group.throughput(Throughput::Bytes(octets as u64));
        group.bench_function(BenchmarkId::new("round-trip", octets), |bencher| {
            bencher.iter(|| {
                runtime.block_on(async {
                    gnb.send(1, 5, black_box(inner.as_slice()))
                        .await
                        .expect("sent");
                    // The observer of the test UPF is not read: it drops
                    // what its queue does not take
                    received.recv().await.expect("the echo")
                })
            })
        });
    }
    group.finish();
}

/// What an endpoint with many tunnels does for a datagram that anyone can
/// send it, and for a UE that leaves. The number in the name is that of its
/// tunnels: the time must not grow with it.
///
/// - `unmatched-error-indication`: an Error Indication that names no tunnel
///   of the endpoint, then an Echo Request, until the Echo Response.
/// - `install-remove-ran`: the tunnel of one more UE, and its removal.
fn tunnels(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("a runtime");
    let mut group = criterion.benchmark_group("tunnels");
    for tunnels in [1_000u32, 100_000] {
        let (gnb, peer) = runtime.block_on(async {
            let (gnb, _received) = Endpoint::bind("127.0.0.1:0".parse().unwrap())
                .await
                .expect("the endpoint binds");
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("the peer binds");
            (gnb, peer)
        });
        let upf = "127.0.0.2:2152".parse().unwrap();
        for ran_id in 0..tunnels {
            let remote = RemoteTunnel::new(upf, 0x1000_0000 + ran_id);
            gnb.install(ran_id, 5, remote, QFI).expect("the tunnel");
        }
        let to = gnb.local_addr().unwrap();
        let indication = Packet::error_indication(0x0bad_f00d, upf.ip())
            .encode()
            .expect("the message encodes");
        let request = Packet::echo_request(1).encode().expect("it encodes");
        group.bench_function(
            BenchmarkId::new("unmatched-error-indication", tunnels),
            |bencher| {
                let mut response = [0; 64];
                bencher.iter(|| {
                    runtime.block_on(async {
                        peer.send_to(&indication, to).await.expect("sent");
                        peer.send_to(&request, to).await.expect("sent");
                        peer.recv(&mut response).await.expect("the response")
                    })
                })
            },
        );
        group.bench_function(BenchmarkId::new("install-remove-ran", tunnels), |bencher| {
            let remote = RemoteTunnel::new(upf, 1);
            bencher.iter(|| {
                gnb.install(u32::MAX, 5, remote, QFI).expect("the tunnel");
                gnb.remove_ran(black_box(u32::MAX))
            })
        });
    }
    group.finish();
}

fn configuration() -> Criterion {
    let output = match std::env::var("PROFILE").as_deref() {
        Ok("flamegraph") => Output::Flamegraph(None),
        _ => Output::Protobuf,
    };
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .with_profiler(PProfProfiler::new(1000, output))
}

criterion_group! {
    name = benches;
    config = configuration();
    targets = encode, decode_borrowed, decode_owned, endpoint, tunnels
}
criterion_main!(benches);
