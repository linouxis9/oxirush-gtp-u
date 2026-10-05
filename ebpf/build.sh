#!/bin/sh
# Rebuild the eBPF object embedded in oxirush-gtp-u (src/ebpf/gtpu.o).
# Needs a nightly toolchain with rust-src and bpf-linker in the PATH.
set -eu
cd "$(dirname "$0")"
cargo build --release --locked
cp "${CARGO_TARGET_DIR:-target}/bpfel-unknown-none/release/gtpu" ../src/ebpf/gtpu.o
