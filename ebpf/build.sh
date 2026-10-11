#!/bin/sh
# Rebuild the eBPF object embedded in oxirush-gtp-u (src/ebpf/gtpu.o) from
# src/ebpf/programs.rs.
#
# Needs rustup, bpf-linker in the PATH, and the nightly toolchain that
# rust-toolchain.toml pins, with rust-src: `rustup toolchain install` in this
# directory installs it.
#
# The build runs in build/, where programs.toml is the Cargo.toml and
# config.toml the .cargo/config.toml of a crate of its own.
set -eu
cd "$(dirname "$0")"
mkdir -p build/.cargo
cp programs.toml build/Cargo.toml
cp programs.lock build/Cargo.lock
cp config.toml build/.cargo/config.toml
cp rust-toolchain.toml build/rust-toolchain.toml
(cd build && cargo build --release --locked)
cp "${CARGO_TARGET_DIR:-build/target}/bpfel-unknown-none/release/gtpu" ../src/ebpf/gtpu.o
