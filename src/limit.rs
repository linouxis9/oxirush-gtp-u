//! What a peer can make an endpoint or the test UPF do without having a
//! tunnel: the replies it sends and the lines it logs, each under a limit.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Error Indications and Supported Extension Headers Notifications that a
/// socket sends to one address in a second, after a burst of as many.
pub(crate) const REPLIES_PER_ADDRESS: u64 = 100;
/// Those that it sends to all addresses together.
pub(crate) const REPLIES_PER_SOCKET: u64 = 1000;
/// Echo Responses that a socket sends to one address in a second, after a
/// burst of as many: a peer sends an Echo Request on a path every 60 s at
/// most, and again each T3-RESPONSE until it is answered (TS 29.281
/// §7.2.1, §11).
pub(crate) const ECHO_RESPONSES_PER_ADDRESS: u64 = 10;

/// The cells of a limit for each address, a power of two: the addresses
/// whose keyed hash falls into one cell share it.
const CELLS: usize = 1024;

const SECOND: u64 = 1_000_000_000;

/// A rate with a burst, as the generic cell rate algorithm keeps it: one
/// time per cell, that at which its next event is due if none came before.
struct Gcra {
    /// Between two events at the rate.
    interval: u64,
    /// How far ahead of the clock a cell's time may be: a burst of `n`
    /// events is `n - 1` intervals.
    tolerance: u64,
}

impl Gcra {
    const fn new(per_second: u64, burst: u64) -> Self {
        let interval = SECOND / per_second;
        Self {
            interval,
            tolerance: interval * (burst - 1),
        }
    }

    /// Whether an event at `now` is within the rate of cell `due`, whose
    /// time, in nanoseconds after the clock's start, it then uses.
    fn allow(&self, due: &AtomicU64, now: u64) -> bool {
        let mut at = due.load(Ordering::Relaxed);
        loop {
            let start = at.max(now);
            if start - now > self.tolerance {
                return false;
            }
            match due.compare_exchange_weak(
                at,
                start + self.interval,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => at = current,
            }
        }
    }
}

/// A rate with a burst for all events together.
pub(crate) struct Rate {
    due: AtomicU64,
    gcra: Gcra,
}

impl Rate {
    pub(crate) const fn new(per_second: u64, burst: u64) -> Self {
        Self {
            due: AtomicU64::new(0),
            gcra: Gcra::new(per_second, burst),
        }
    }

    /// Whether an event at `now` is within the rate, which it then uses.
    pub(crate) fn allow(&self, now: u64) -> bool {
        self.gcra.allow(&self.due, now)
    }
}

/// A rate with a burst for the events of each address: a cell of a small
/// table, chosen by a hash of the address under a key of the socket's own,
/// so that whoever floods from addresses of their choice cannot aim at the
/// cell of another.
pub(crate) struct PerAddress {
    key: RandomState,
    cells: Box<[AtomicU64]>,
    gcra: Gcra,
}

impl PerAddress {
    pub(crate) fn new(per_second: u64, burst: u64) -> Self {
        Self {
            key: RandomState::new(),
            cells: (0..CELLS).map(|_| AtomicU64::new(0)).collect(),
            gcra: Gcra::new(per_second, burst),
        }
    }

    /// Whether an event for `address` at `now` is within the rate of its
    /// cell, which it then uses.
    pub(crate) fn allow(&self, address: IpAddr, now: u64) -> bool {
        let cell = self.key.hash_one(address.to_canonical()) as usize & (CELLS - 1);
        self.gcra.allow(&self.cells[cell], now)
    }
}

/// One line a second at most, which says how many were not logged since
/// the one before.
pub(crate) struct Lines {
    next: AtomicU64,
    suppressed: AtomicU64,
}

impl Lines {
    pub(crate) const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Whether a line at `now` is logged, with the number of those that
    /// were not since the last one; otherwise it is counted.
    pub(crate) fn allow(&self, now: u64) -> Option<Suppressed> {
        let next = self.next.load(Ordering::Relaxed);
        if now >= next
            && self
                .next
                .compare_exchange(next, now + SECOND, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(Suppressed(self.suppressed.swap(0, Ordering::Relaxed)));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// The end of a line that a limit let through: how many lines of its kind
/// were not logged before it.
pub(crate) struct Suppressed(u64);

impl fmt::Display for Suppressed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => Ok(()),
            more => write!(f, " (and {more} more since the line before, not logged)"),
        }
    }
}

/// The limits of the replies that a peer can cause, and the lines that it
/// can cause by kind: a flood of one kind leaves the others to be logged.
pub(crate) struct Notices {
    start: Instant,
    /// Error Indications and Supported Extension Headers Notifications,
    /// for each address and for the socket.
    replies_to: PerAddress,
    replies: Rate,
    echo_responses_to: PerAddress,
    pub(crate) malformed: Lines,
    pub(crate) discarded: Lines,
    pub(crate) unknown_teid: Lines,
    pub(crate) error_indication: Lines,
    pub(crate) ignored: Lines,
    #[cfg(all(target_os = "linux", feature = "tun"))]
    pub(crate) tun: Lines,
    pub(crate) echo: Lines,
}

impl Notices {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            replies_to: PerAddress::new(REPLIES_PER_ADDRESS, REPLIES_PER_ADDRESS),
            replies: Rate::new(REPLIES_PER_SOCKET, REPLIES_PER_SOCKET),
            echo_responses_to: PerAddress::new(
                ECHO_RESPONSES_PER_ADDRESS,
                ECHO_RESPONSES_PER_ADDRESS,
            ),
            malformed: Lines::new(),
            discarded: Lines::new(),
            unknown_teid: Lines::new(),
            error_indication: Lines::new(),
            ignored: Lines::new(),
            #[cfg(all(target_os = "linux", feature = "tun"))]
            tun: Lines::new(),
            echo: Lines::new(),
        }
    }

    /// Nanoseconds since the socket was bound.
    pub(crate) fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Whether an Error Indication or a Supported Extension Headers
    /// Notification to `to` is within the limits, which it then uses. The
    /// limit of its address is asked first, so that a reply that it
    /// refuses uses nothing of the socket's.
    pub(crate) fn reply(&self, to: IpAddr) -> bool {
        self.reply_at(to, self.now())
    }

    fn reply_at(&self, to: IpAddr, now: u64) -> bool {
        self.replies_to.allow(to, now) && self.replies.allow(now)
    }

    /// Whether an Echo Response to `to` is within the limit of its
    /// address, which it then uses.
    pub(crate) fn echo_response(&self, to: IpAddr) -> bool {
        self.echo_responses_to.allow(to, self.now())
    }
}

/// Log a line that a peer can cause through `$lines`, a [`Lines`] of the
/// socket's [`Notices`], when its level is enabled.
macro_rules! limited {
    ($level:ident, $notices:expr, $lines:ident, $($arg:tt)+) => {
        if tracing::enabled!(tracing::Level::$level) {
            let notices: &$crate::limit::Notices = $notices;
            if let Some(suppressed) = notices.$lines.allow(notices.now()) {
                tracing::event!(
                    tracing::Level::$level,
                    "{}{suppressed}",
                    format_args!($($arg)+)
                );
            }
        }
    };
}
pub(crate) use limited;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rate_lets_a_burst_through_then_one_event_an_interval() {
        let rate = Rate::new(100, 5);
        let ms = 1_000_000;
        // A burst at the start, and nothing more until an interval passed.
        assert_eq!((0..8).filter(|_| rate.allow(0)).count(), 5);
        assert!(!rate.allow(9 * ms));
        assert!(rate.allow(10 * ms));
        assert!(!rate.allow(10 * ms));
        // A second of nothing gives the burst back, and no more.
        assert_eq!((0..8).filter(|_| rate.allow(2000 * ms)).count(), 5);
        // At the rate, every event goes through.
        assert!((0..1000).all(|i| rate.allow(3000 * ms + i * 10 * ms)));
        // Above it, one in two.
        let at_twice = (0..1000).filter(|i| rate.allow(20_000 * ms + i * 5 * ms));
        assert!((499..=505).contains(&at_twice.count()));
    }

    #[test]
    fn each_address_has_its_rate() {
        let limit = PerAddress::new(10, 2);
        let (a, b): (IpAddr, IpAddr) =
            ("192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap());
        let ms = 1_000_000;
        assert_eq!((0..5).filter(|_| limit.allow(a, 0)).count(), 2);
        // Another address has its own cell, unless its hash falls into the
        // same one, one time in 1024.
        let same = limit.key.hash_one(a) as usize & (CELLS - 1)
            == limit.key.hash_one(b) as usize & (CELLS - 1);
        assert_eq!(limit.allow(b, 0), !same);
        // An IPv4-mapped address is the IPv4 address.
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(!limit.allow(mapped, 0));
        assert!(limit.allow(mapped, 100 * ms));
    }

    /// A reply that the limit of its address refuses uses nothing of the
    /// socket's: one address alone cannot use it up past its own rate.
    #[test]
    fn a_reply_refused_for_its_address_leaves_the_rate_of_the_socket() {
        let notices = Notices::new();
        let flooder: IpAddr = "192.0.2.1".parse().unwrap();
        let sent = (0..5000).filter(|_| notices.reply_at(flooder, 0)).count();
        assert_eq!(sent, REPLIES_PER_ADDRESS as usize);
        let others = (0..2000u32)
            .map(|host| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + host)))
            .filter(|address| notices.reply_at(*address, 0))
            .count();
        // The socket's burst, but what the flooder had of it. The few that
        // share the flooder's cell are refused there.
        assert_eq!(others, (REPLIES_PER_SOCKET - REPLIES_PER_ADDRESS) as usize);
    }

    #[test]
    fn lines_are_one_a_second_and_count_those_not_logged() {
        let lines = Lines::new();
        let ms = 1_000_000;
        assert_eq!(lines.allow(0).map(|s| s.0), Some(0));
        assert!(lines.allow(1).is_none());
        assert!(lines.allow(999 * ms).is_none());
        assert_eq!(lines.allow(1000 * ms).map(|s| s.0), Some(2));
        assert_eq!(lines.allow(5000 * ms).map(|s| s.0), Some(0));
        assert_eq!(Suppressed(0).to_string(), "");
        assert_eq!(
            Suppressed(7).to_string(),
            " (and 7 more since the line before, not logged)"
        );
    }
}
