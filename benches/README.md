# Benchmarks of oxirush-gtp-u

A package of its own, which the published crate does not have. It times a
G-PDU through the codec and through an endpoint with
[criterion](https://crates.io/crates/criterion), and profiles them with
[pprof](https://crates.io/crates/pprof).

```sh
cargo bench --bench packets                 # every benchmark
cargo bench --bench packets -- decode       # those whose name has it

# Ten seconds of one benchmark under the profiler, then where the time went
cargo bench --bench packets -- --profile-time 10 endpoint/round-trip/1400
go tool pprof -top target/criterion/endpoint/round-trip/1400/profile/profile.pb
```

The profile is one that Go's `pprof` reads. With `PROFILE=flamegraph` in
the environment it is `flamegraph.svg`, in the same directory.

`compare.sh` prints the table that compares the crate with go-gtp:
`src/bin/compare.rs` and `compare/main.go` run the same operations on the
same G-PDUs, and `go build` fetches the version of go-gtp that
`compare/go.mod` pins.

```sh
PERF="sudo -n perf" benches/compare.sh 3    # on core 3
```

## Figures

On core 2 of an Intel Xeon E5-2680 v4 (Broadwell, 2.4 GHz; a KVM guest bound
to NUMA node 0; Linux 7.0), with Rust 1.100.0 and glibc 2.43, at 04de366 on
2026-11-15, the median of ten runs, each the median of criterion's samples.
The ten runs of a row were within 11 % of each other, but for the round trip
(up to 33 %) and for the copied decodes and the encodes of 1,400 octets (15
to 28 %). The G-PDU that is encoded is an uplink one with its
PDU Session Container, built in the timed call; those that are decoded have
no extension header, as on S1-U, that container, as on N3, or three
extension headers, of which one is kept as octets:

| | 64 octets of payload | 1,400 octets |
|---|---|---|
| Build and encode into a buffer that is used again | 82 ns | 101 ns |
| Build and encode into a new buffer | 111 ns | 211 ns |
| Decode, the payload left in the datagram: no extension header | 14 ns | 14 ns |
| The same, with the PDU Session Container | 61 ns | 61 ns |
| The same, with three extension headers | 119 ns | 118 ns |
| Decode, the payload copied: no extension header | 26 ns | 90 ns |
| The same, with the PDU Session Container | 73 ns | 136 ns |
| The same, with three extension headers | 130 ns | 219 ns |
| From an endpoint to the test peer and its echo back, over the loopback interface | 18.5 µs | 19.8 µs |

Four fifths of the round trip are its four system calls, and the codec is
under 2% of it. A message whose payload stays in the datagram allocates the list of its
extension headers when it has any, and the octets of a header that is kept
as received.

An endpoint finds the tunnel that an Error Indication names, and the tunnels
of a UE that `remove_ran` removes, by walking through its tunnels: the
benchmarks `tunnels/unmatched-error-indication` and
`tunnels/install-remove-ran` time them with 1,000 and 100,000 tunnels.

## Against go-gtp

[go-gtp](https://github.com/wmnsk/go-gtp) v0.8.12 on the same G-PDUs of
1,400 octets, built before they are timed, each program on core 3 of the
machine above (Go 1.27.4), at 04de366. Each side ran once a round, in turns,
ten rounds (ten runs of `compare.sh` with `ROUNDS=1`): a time is the median
of the ten, beside the lowest and the highest. Cycles and instructions are
per operation, the median of those of `perf stat`, user and kernel. Peak
memory is that of the whole program. The last column says how much slower
or faster go-gtp is than this crate: "about the same" when the medians are
within 10 %, which two builds of the same code can differ by, or the ten
times overlap; they overlap for none here.

| Operation | | ns | Lowest and highest | Cycles | Instructions | Allocations | Octets allocated | Peak memory | go-gtp against this crate |
|---|---|---|---|---|---|---|---|---|---|
| Encode, no extension header | oxirush-gtp-u | 47.3 | 46.4 to 50.6 | 136 | 297 | 0 | 0 | 2.7 MiB | |
| | go-gtp | 35.8 | 35.7 to 35.9 | 103 | 338 | 0 | 0 | 5.6 MiB | 1.3× faster |
| Encode, PDU Session Container | oxirush-gtp-u | 69.1 | 68.6 to 70.1 | 204 | 688 | 0 | 0 | 2.7 MiB | |
| | go-gtp | 58.3 | 57.9 to 58.5 | 168 | 526 | 0 | 0 | 5.6 MiB | 1.2× faster |
| Decode, no extension header | oxirush-gtp-u | 18.1 | 17.7 to 19.0 | 50 | 106 | 0 | 0 | 2.7 MiB | |
| | go-gtp | 8.2 | 8.2 to 8.5 | 23 | 88 | 0 | 0 | 5.5 MiB | 2.2× faster |
| Decode, PDU Session Container | oxirush-gtp-u | 76.2 | 75.6 to 89.1 | 218 | 535 | 1 | 416 | 2.7 MiB | |
| | go-gtp | 103.5 | 100.1 to 106.4 | 299 | 846 | 2 | 56 | 10.1 MiB | 1.4× slower |
| Endpoint to endpoint and back, no extension header, loopback | oxirush-gtp-u | 18,038 | 16,990 to 22,994 | 50,858 | 46,690 | 4 | 5,623 | 2.9 MiB | |
| | go-gtp | 38,141 | 37,478 to 48,417 | 110,172 | 91,379 | 82 | 8,736 | 10.2 MiB | 2.1× slower |

`benches/compare.sh 3` runs every row on core 3, and fetches go-gtp at the
version that it pins; perf may need `PERF="sudo -n perf"`.
