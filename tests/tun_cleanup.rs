//! What a TUN leaves behind when it goes, whatever ends it. These tests
//! need `CAP_NET_ADMIN`, as those of `tun_linux.rs`, and move their thread
//! to a network namespace of its own.

#![cfg(all(target_os = "linux", feature = "tun"))]

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use oxirush_gtp_u::tun::{Routing, TunConfig, TunPort};

fn isolate() {
    // SAFETY: only the calling test thread enters a fresh network namespace.
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWNET) },
        0,
        "{}",
        io::Error::last_os_error()
    );
}

fn namespace() -> File {
    // SAFETY: gettid has no arguments and only returns this thread's ID.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    File::open(format!("/proc/self/task/{tid}/ns/net")).unwrap()
}

fn enter(namespace: &File) {
    // SAFETY: the live descriptor names a network namespace; only this thread moves.
    assert_eq!(
        unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) },
        0,
        "{}",
        io::Error::last_os_error()
    );
}

fn exists(name: &str) -> bool {
    let name = CString::new(name).unwrap();
    // SAFETY: the NUL-terminated name remains live during the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

fn ip(args: &[&str]) -> String {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn close_uses_the_creation_namespace_and_preserves_other_links() {
    isolate();
    let owner = namespace();
    let port = TunPort::create(TunConfig::new(
        "scope_tun",
        Routing::UePolicy {
            address: Ipv4Addr::new(198, 19, 0, 20),
            table: 1000,
            priority: 1000,
        },
    ))
    .unwrap();
    isolate();
    let other = namespace();
    // Both fresh namespaces allocate index 2; equal names must not permit
    // cleanup to remove this unrelated interface in the caller's namespace.
    ip(&["link", "add", "scope_tun", "type", "dummy"]);
    port.close().unwrap();
    assert!(
        exists("scope_tun"),
        "cleanup removed an unrelated interface"
    );
    enter(&owner);
    assert!(!exists("scope_tun"), "the original TUN was not removed");
    assert!(
        !ip(&["-4", "rule", "show"]).contains("198.19.0.20"),
        "the policy rule was not removed"
    );
    enter(&other);
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn close_accepts_externally_removed_resources() {
    isolate();
    let port = TunPort::create(TunConfig::new(
        "gone_tun",
        Routing::UePolicy {
            address: Ipv4Addr::new(198, 19, 0, 22),
            table: 1002,
            priority: 1002,
        },
    ))
    .unwrap();
    ip(&["link", "delete", "gone_tun"]);
    ip(&[
        "-4",
        "rule",
        "delete",
        "from",
        "198.19.0.22",
        "table",
        "1002",
        "priority",
        "1002",
    ]);
    ip(&["link", "add", "gone_tun", "type", "dummy"]);
    port.close().unwrap();
    port.close().unwrap();
    assert!(
        exists("gone_tun"),
        "cleanup removed the replacement interface"
    );
}
