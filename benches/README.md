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

`compare.sh` prints the table of the README that compares the crate with
go-gtp: `src/bin/compare.rs` and `compare/main.go` run the same operations
on the same G-PDUs, and `go build` fetches the version of go-gtp that
`compare/go.mod` pins.

```sh
PERF="sudo -n perf" benches/compare.sh 3    # on core 3
```

## Figures

On one core of an AMD Ryzen 7 5700G (16 threads, Linux 7.0), with Rust 1.98.1
and glibc 2.43, at 0d25889, measured on a quiet machine on 2026-10-18, the
lowest of five runs. The G-PDU that is encoded is an uplink one with its
PDU Session Container, built in the timed call; those that are decoded have
no extension header, as on S1-U, that container, as on N3, or three
extension headers, of which one is kept as octets:

| | 64 octets of payload | 1,400 octets |
|---|---|---|
| Build and encode into a buffer that is used again | 34 ns | 45 ns |
| Build and encode into a new buffer | 45 ns | 76 ns |
| Decode, the payload left in the datagram: no extension header | 9 ns | 9 ns |
| The same, with the PDU Session Container | 22 ns | 22 ns |
| The same, with three extension headers | 61 ns | 61 ns |
| Decode, the payload copied: no extension header | 15 ns | 36 ns |
| The same, with the PDU Session Container | 27 ns | 57 ns |
| The same, with three extension headers | 76 ns | 108 ns |
| From an endpoint to the test UPF and its echo back, over the loopback interface | 12.3 µs | 12.9 µs |

Four fifths of the round trip are its four system calls, and the codec is
under 2% of it. A message whose payload stays in the datagram is decoded
without an allocation when it has one extension header at most; with
three, it allocates its list and the octets of the header that is kept as
received.

An endpoint with many tunnels, on the same core and at the same commit, the
lowest of five runs.
The first row is an Error Indication that names none of its tunnels, then a
G-PDU of one of them, until the endpoint delivers it; the second is the
tunnel of one more UE and its removal with `remove_ran`:

| | 1,000 tunnels | 100,000 tunnels |
|---|---|---|
| `tunnels/unmatched-error-indication` | 10.2 µs | 10.2 µs |
| `tunnels/install-remove-ran` | 0.29 µs | 0.34 µs |

Neither walks through the tunnels: an endpoint finds the tunnel that an
Error Indication names, and those of a UE, in an index.

## Against go-gtp

[go-gtp](https://github.com/wmnsk/go-gtp) v0.8.12 on the same G-PDUs of
1,400 octets, built before they are timed, each program on core 2 of the
machine above (Go 1.27), at 0d25889. Times are the lowest of three runs,
and each figure the median of three runs of the script. Cycles and
instructions are per operation, from `perf stat`, user and kernel. Peak
memory is that of the whole program. The last column is the time of go-gtp
over this crate's, "about the same" within 10 %, which two builds of the
same code can differ by. The three runs of an operation differed by 3 % at
most.

| Operation | | ns | Cycles | Instructions | Allocations | Octets allocated | Peak memory | go-gtp / this crate |
|---|---|---|---|---|---|---|---|---|
| Encode, no extension header | oxirush-gtp-u | 17.8 | 82 | 305 | 0 | 0 | 2.6 MiB | |
| | go-gtp | 17.7 | 80 | 338 | 0 | 0 | 5.5 MiB | about the same |
| Encode, PDU Session Container | oxirush-gtp-u | 25.8 | 116 | 472 | 0 | 0 | 2.6 MiB | |
| | go-gtp | 26.1 | 117 | 525 | 0 | 0 | 5.5 MiB | about the same |
| Decode, no extension header | oxirush-gtp-u | 10.8 | 48 | 127 | 0 | 0 | 2.7 MiB | |
| | go-gtp | 4.1 | 18 | 88 | 0 | 0 | 5.4 MiB | 0.38x |
| Decode, PDU Session Container | oxirush-gtp-u | 24.0 | 110 | 251 | 0 | 0 | 2.7 MiB | |
| | go-gtp | 43.9 | 204 | 864 | 2 | 56 | 10.2 MiB | 1.8x |
| Endpoint to endpoint and back, no extension header, loopback | oxirush-gtp-u | 12,078 | 56,106 | 39,975 | 2 | 2,807 | 3.0 MiB | |
| | go-gtp | 23,900 | 109,192 | 85,322 | 82 | 8,736 | 10.3 MiB | 2.0x |

`decode_borrowed` returns a `Packet` of 136 octets, with room for one
extension header whether the message has one or not.
`benches/compare.sh 3` runs every row on core 3, and fetches go-gtp at the
version that it pins; perf may need `PERF="sudo -n perf"`.
