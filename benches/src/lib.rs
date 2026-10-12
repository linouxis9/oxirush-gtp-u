//! What the benchmarks of `benches/` share.

/// An inner packet of `octets` octets that looks random, the same at every
/// run.
pub fn payload(octets: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..octets)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}
