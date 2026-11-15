# Contributing to oxirush-gtp-u

## Tests

```sh
cargo test --all-features
```

The TUN and the fast path need a network namespace or root. Each test runs
in a network namespace of its own: in a user namespace without root, or with
sudo as the runner.

```sh
# The TUN, without root
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="unshare --user --map-root-user --net --" \
  cargo test --features tun --test tun_linux --test tun_cleanup -- --ignored
# The fast path, as root (Linux 6.6)
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=sudo \
  cargo test --features ebpf --test ebpf_linux -- --ignored
# The encoder against Wireshark's dissector, with tshark 4.4 or later
cargo test --test wireshark -- --ignored
```

Where users may not create user namespaces, as on Ubuntu, use `sudo unshare
--net` instead of `unshare --user --map-root-user --net`.

## The eBPF programs

The object of the eBPF programs, `src/ebpf/gtpu.o`, is committed. After a
change of the programs, rebuild it with `ebpf/build.sh` and commit both; CI
rebuilds the object and compares.

## Fuzzing

```sh
cargo +nightly fuzz run decode -- -max_total_time=60
```

`fuzz/` has two [cargo-fuzz](https://crates.io/crates/cargo-fuzz) targets:
`decode` and `answers`, what a node answers. CI runs each for a minute at a
push, an hour each day but Friday and Sunday, and four hours on Friday.

## Benchmarks

[`benches/README.md`](benches/README.md) has the figures and the commands.

## Pull requests

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.
