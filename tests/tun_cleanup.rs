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
#[ignore = "needs root and network namespaces"]
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
    port.close();
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
#[ignore = "needs root and network namespaces"]
async fn try_close_accepts_externally_removed_resources() {
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
    port.try_close().unwrap();
    port.try_close().unwrap();
    assert!(
        exists("gone_tun"),
        "cleanup removed the replacement interface"
    );
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

struct Capabilities([CapabilityData; 2]);

impl Capabilities {
    fn without_net_admin() -> Self {
        let header = CapabilityHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut saved = [CapabilityData::default(); 2];
        // SAFETY: these C-layout buffers have the two entries required by version 3.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capget, &header, saved.as_mut_ptr()) },
            0
        );
        let mut changed = saved;
        // CAP_NET_ADMIN is bit 12 in Linux's capability bitmap.
        changed[0].effective &= !(1 << 12);
        // SAFETY: capset with pid 0 changes only the calling thread's capabilities.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capset, &header, changed.as_ptr()) },
            0
        );
        Self(saved)
    }
}

impl Drop for Capabilities {
    fn drop(&mut self) {
        let header = CapabilityHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        // SAFETY: restore this thread's saved effective capabilities, whose permitted
        // and inheritable sets were never changed.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capset, &header, self.0.as_ptr()) },
            0
        );
    }
}

#[tokio::test]
#[ignore = "needs root and network namespaces"]
async fn close_retries_resources_after_a_permission_failure() {
    isolate();
    let port = TunPort::create(TunConfig::new(
        "retry_tun",
        Routing::UePolicy {
            address: Ipv4Addr::new(198, 19, 0, 21),
            table: 1001,
            priority: 1001,
        },
    ))
    .unwrap();
    let capabilities = Capabilities::without_net_admin();
    let error = port.try_close().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let source = error.get_ref().unwrap().source().unwrap();
    assert_eq!(
        source.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(libc::EPERM)
    );
    port.close();
    assert!(
        exists("retry_tun"),
        "cleanup unexpectedly succeeded without CAP_NET_ADMIN"
    );
    drop(capabilities);
    port.close();
    assert!(
        !exists("retry_tun"),
        "cleanup did not retry the failed link removal"
    );
    assert!(
        !ip(&["-4", "rule", "show"]).contains("198.19.0.21"),
        "cleanup did not retry the failed policy rule removal"
    );
    port.try_close().unwrap();
}
