//! The README shows the programs of `examples/`, which are built with the
//! crate and can be run.

const EXAMPLES: [&str; 4] = [
    include_str!("../examples/codec.rs"),
    include_str!("../examples/endpoint.rs"),
    include_str!("../examples/tun.rs"),
    include_str!("../examples/fast_path.rs"),
];

#[test]
fn the_rust_blocks_of_the_readme_are_parts_of_the_examples() {
    // A checkout may have changed the line endings.
    let readme = include_str!("../README.md").replace('\r', "");
    let examples = EXAMPLES.map(|example| example.replace('\r', ""));
    let blocks: Vec<&str> = readme
        .split("\n```")
        .filter_map(|block| block.strip_prefix("rust"))
        .filter_map(|block| block.split_once('\n'))
        .map(|(_, code)| code)
        .collect();
    assert_eq!(blocks.len(), 6);
    for code in blocks {
        assert!(
            examples.iter().any(|example| example.contains(code)),
            "in no example:\n{code}"
        );
    }
}
