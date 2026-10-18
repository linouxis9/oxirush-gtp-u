//! The README and the documentation show what their code prints, and the
//! README shows the programs of `examples/`.
//!
//! `readme/blocks.rs` has each Rust block of the pages below as a function
//! that prints into a string. The first test here keeps that file equal to
//! the pages, and the second compares what each function prints with the
//! output that its page shows under its block. The third finds each Rust
//! block of the README in a program of `examples/`, which is built with the
//! crate and can be run.
//!
//! A page is the README, or the documentation of the crate: the `//!` lines
//! of `src/lib.rs`. A block that is run opens with ` ```rust `, and a block
//! that defines `main` is run through it. One that opens with
//! ` ```rust,no_run ` needs privileges: it is compared with its example and not
//! run. One that opens with ` ```rust,ignore ` uses other crates of the
//! family: the package of `family/` runs it, and these tests skip it. The
//! output of a block is the `text` blocks that follow it with nothing but
//! blank lines between them. A block that shows no output prints none.
//!
//! After a change of the code of a Rust block of a page, write the file
//! again and run the tests once more:
//!
//! ```bash
//! README_BLOCKS=write cargo test --test readme
//! cargo test --test readme
//! ```
// The blocks use the endpoint, which the default features have.
#![cfg(feature = "endpoint")]

use std::fmt::Write;

#[rustfmt::skip]
#[path = "readme/blocks.rs"]
mod blocks;

/// The pages: the README, and the file whose documentation is the front page
/// of the crate's.
const PAGES: &[(&str, &str)] = &[
    ("README.md", include_str!("../README.md")),
    ("src/lib.rs", include_str!("../src/lib.rs")),
];
/// The programs of `examples/`.
const EXAMPLES: [&str; 7] = [
    include_str!("../examples/codec.rs"),
    include_str!("../examples/endpoint.rs"),
    include_str!("../examples/path.rs"),
    include_str!("../examples/extension_headers.rs"),
    include_str!("../examples/handover.rs"),
    include_str!("../examples/tun.rs"),
    include_str!("../examples/fast_path.rs"),
];
/// The rest of the fence of a block that uses other crates of the family:
/// this test skips it, as the documentation tests do, and `family/` runs it.
const FAMILY: &str = ",ignore";
const BLOCKS: &str = include_str!("readme/blocks.rs");
const BLOCKS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/readme/blocks.rs");

/// A Rust block of a page: its page, the line of its opening fence, its
/// code, and the output that the page shows under it.
struct Example {
    page: &'static str,
    line: usize,
    code: String,
    output: String,
}

/// The Rust blocks of the pages, each with its output.
fn examples() -> Vec<Example> {
    let mut examples: Vec<Example> = Vec::new();
    for (page, text) in PAGES {
        let documentation = page.ends_with(".rs");
        // The language of the block that is open, and whether the blocks
        // since the last Rust block are still its output.
        let mut open: Option<&str> = None;
        let mut output = false;

        for (index, line) in text.lines().enumerate() {
            // The page of a file is the lines of its module documentation.
            let line = match (documentation, line.strip_prefix("//!")) {
                (false, _) => line,
                (true, Some(line)) => line.strip_prefix(' ').unwrap_or(line),
                (true, None) => continue,
            };
            match (open, line.strip_prefix("```")) {
                (None, Some("rust")) => {
                    open = Some("rust");
                    output = true;
                    examples.push(Example {
                        page,
                        line: index + 1,
                        code: String::new(),
                        output: String::new(),
                    });
                }
                (None, Some(language)) => {
                    open = Some(language);
                    output &= language == "text";
                }
                (Some(_), Some("")) => open = None,
                (Some("rust"), _) => {
                    // A line that the documentation hides is code all the same.
                    let code = match documentation {
                        true => line.strip_prefix("# ").unwrap_or(line),
                        false => line,
                    };
                    let example = examples.last_mut().unwrap();
                    writeln!(example.code, "{code}").unwrap();
                }
                (Some(_), _) if output => {
                    let example = examples.last_mut().unwrap();
                    writeln!(example.output, "{line}").unwrap();
                }
                (Some(_), _) => {}
                // Text between two blocks ends the output of the first.
                (None, None) => output &= line.trim().is_empty(),
            }
        }
    }
    examples
}

/// The text of `readme/blocks.rs` for the Rust blocks of the pages.
fn generated(examples: &[Example]) -> String {
    let mut file = String::from(HEAD);

    // The blocks go by their rank, and not by their line: a change of the
    // text of a page leaves this file as it is.
    writeln!(file, "pub const BLOCKS: &[fn()] = &[").unwrap();
    for rank in 1..=examples.len() {
        writeln!(file, "    block_{rank},").unwrap();
    }
    writeln!(file, "];").unwrap();

    let mut last = "";
    let mut of_page = 0;
    for (example, rank) in examples.iter().zip(1..) {
        let page = example.page;
        of_page = if page == last { of_page + 1 } else { 1 };
        last = page;
        writeln!(file, "\n/// The Rust block {of_page} of {page}.").unwrap();
        writeln!(file, "fn block_{rank}() {{").unwrap();
        for code in example.code.lines() {
            match code.is_empty() {
                true => writeln!(file).unwrap(),
                false => writeln!(file, "    {code}").unwrap(),
            }
        }
        // A block that is a program is run through its `main`.
        if example.code.contains("fn main() -> ") {
            writeln!(file, "    main().unwrap();").unwrap();
        } else if example.code.contains("fn main()") {
            writeln!(file, "    main();").unwrap();
        }
        writeln!(file, "}}").unwrap();
    }
    file
}

const HEAD: &str = r#"// The Rust blocks of the README and of the documentation, each as a function.
// `tests/readme.rs` writes this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what its page shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    // The line is made first, where the block is: its arguments may have a
    // `?` or an `await`.
    ($($argument:tt)*) => {{
        let line = format!($($argument)*);
        PRINTED.with(|printed| {
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    }};
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

"#;

#[test]
fn the_blocks_are_those_of_the_pages() {
    let generated = generated(&examples());
    // A checkout may have changed the line endings.
    if generated == BLOCKS.replace('\r', "") {
        return;
    }
    if std::env::var("README_BLOCKS").as_deref() == Ok("write") {
        std::fs::write(BLOCKS_PATH, generated).unwrap();
        panic!("tests/readme/blocks.rs is written from the pages: run the tests again");
    }
    panic!(
        "tests/readme/blocks.rs is not the Rust blocks of the pages: write it with \
         `README_BLOCKS=write cargo test --test readme`, then run the tests again"
    );
}

#[test]
fn each_block_prints_what_its_page_shows() {
    let examples = examples();
    assert_eq!(examples.len(), blocks::BLOCKS.len());

    let mut differences = String::new();
    for (example, block) in examples.iter().zip(blocks::BLOCKS) {
        // macOS has no loopback address but 127.0.0.1, and a program that
        // binds port 2152 binds another one.
        if cfg!(target_os = "macos") && example.code.contains(":2152") {
            continue;
        }
        let printed = blocks::printed(*block);
        if printed != example.output {
            let (page, line, shown) = (example.page, example.line, &example.output);
            writeln!(differences, "{page}, the block of line {line} prints:").unwrap();
            writeln!(differences, "{printed}and the page shows:\n{shown}").unwrap();
        }
    }
    assert!(differences.is_empty(), "{differences}");
}

#[test]
fn the_rust_blocks_of_the_readme_are_parts_of_the_examples() {
    // A checkout may have changed the line endings.
    let readme = include_str!("../README.md").replace('\r', "");
    let examples = EXAMPLES.map(|example| example.replace('\r', ""));
    let blocks: Vec<&str> = readme
        .split("\n```")
        .filter_map(|block| block.strip_prefix("rust"))
        .filter_map(|block| block.split_once('\n'))
        // A block of `family/` uses other crates, and is in no example
        .filter(|(fence, _)| *fence != FAMILY)
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
