//! Descriptor ownership and asynchronous packet I/O for a TUN.

use super::error::context;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use tokio::io::{Interest, unix::AsyncFd};

pub(super) struct TunDevice {
    io: AsyncFd<File>,
}

impl TunDevice {
    pub(super) fn create(name: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        // SAFETY: ifreq is plain data, for which all zeros is valid.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        // The name is at most 15 bytes, so the last byte stays NUL.
        for (target, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *target = byte as libc::c_char;
        }
        // IFF_TUN_EXCL: fail instead of attaching to an existing device.
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
        // SAFETY: TUNSETIFF reads and writes the ifreq, which outlives the
        // call, on a valid /dev/net/tun descriptor.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::EBUSY) => io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("network interface {} already exists", name),
                ),
                _ => context(error, format_args!("create TUN {}", name)),
            });
        }
        set_nonblocking(&file)?;
        Ok(Self {
            io: AsyncFd::new(file)?,
        })
    }

    /// Read a raw IPv4 or IPv6 packet that Linux routed to the TUN.
    pub(super) async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            // Error readiness wakes a reader when `close` removes the TUN.
            let mut ready = self.io.ready(Interest::READABLE | Interest::ERROR).await?;
            match ready.try_io(|inner| inner.get_ref().read(buffer)) {
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Hand a raw IPv4 or IPv6 packet to Linux, as if the TUN received it.
    pub(super) async fn send(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.io.ready(Interest::WRITABLE | Interest::ERROR).await?;
            match ready.try_io(|inner| inner.get_ref().write(packet)) {
                Ok(Ok(written)) if written == packet.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL only act on this valid descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
