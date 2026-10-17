# Benchmarks of oxirush-gtp-u

A package of its own, which the published crate does not have. It times a
G-PDU through the codec and through an endpoint with
[criterion](https://crates.io/crates/criterion), and profiles them with
[pprof](https://crates.io/crates/pprof).

```bash
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

```bash
PERF="sudo -n perf" benches/compare.sh 3    # on core 3
```

## Figures

On one core of an AMD Ryzen 7 5700G, with Rust 1.98.1 and glibc 2.43, the
lowest of four runs. The G-PDU that is encoded is an uplink one with its
PDU Session Container; those that are decoded have no extension header, as
on S1-U, that container, as on N3, or three extension headers, of which
one is kept as octets:

| | 64 octets of payload | 1400 octets |
|---|---|---|
| Encode into a buffer that is used again | 41 ns | 56 ns |
| Encode into a new buffer | 53 ns | 84 ns |
| Decode, the payload left in the datagram: no extension header | 9 ns | 9 ns |
| The same, with the PDU Session Container | 23 ns | 23 ns |
| The same, with three extension headers | 65 ns | 66 ns |
| Decode, the payload copied: no extension header | 16 ns | 38 ns |
| The same, with the PDU Session Container | 30 ns | 55 ns |
| The same, with three extension headers | 74 ns | 116 ns |
| From an endpoint to the test UPF and its echo back, over the loopback interface | 12.5 µs | 13.3 µs |

Four fifths of the round trip are its four system calls, and the codec is
under 2% of it. A message whose payload stays in the datagram is decoded
without an allocation when it has one extension header at most; with
three, it allocates its list and the octets of the header that is kept as
received.

An endpoint with many tunnels, on the same core, the machine busy with
other work (a load of 6 to 8). The first row is an Error Indication that
names none of its tunnels, then a G-PDU of one of them, until the endpoint
delivers it; the second is the tunnel of one more UE and its removal with
`remove_ran`:

| | 1 000 tunnels | 100 000 tunnels |
|---|---|---|
| `tunnels/unmatched-error-indication` | 15.9 µs | 16.4 µs |
| `tunnels/install-remove-ran` | 0.31 µs | 0.45 µs |

Neither walks through the tunnels: an endpoint finds the tunnel that an
Error Indication names, and those of a UE, in an index.
