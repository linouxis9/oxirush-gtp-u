//! `cfg(fast_path)`: the `ebpf` feature on Linux, on a little-endian
//! architecture whose eBPF loader, aya, builds there. Elsewhere the feature
//! builds and adds nothing, as off Linux. The list is that of the dependency
//! on aya in `Cargo.toml`, which is the list of aya-obj 0.3. The programs'
//! object is for little-endian eBPF (`bpfel`): a big-endian kernel refuses
//! it.

/// The architectures that aya-obj 0.3 has the kernel's definitions for.
const ARCHITECTURES: [&str; 9] = [
    "aarch64",
    "arm",
    "loongarch64",
    "mips",
    "mips64",
    "powerpc64",
    "riscv64",
    "s390x",
    "x86_64",
];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(fast_path)");
    let variable = |name| std::env::var(name).unwrap_or_default();
    if std::env::var_os("CARGO_FEATURE_EBPF").is_some()
        && variable("CARGO_CFG_TARGET_OS") == "linux"
        && variable("CARGO_CFG_TARGET_ENDIAN") == "little"
        && ARCHITECTURES.contains(&variable("CARGO_CFG_TARGET_ARCH").as_str())
    {
        println!("cargo::rustc-cfg=fast_path");
    }
}
