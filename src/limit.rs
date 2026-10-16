//! What a peer can make an endpoint or the test UPF do without having a
//! tunnel: the replies it sends and the lines it logs, each under a limit.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Error Indications and Supported Extension Headers Notifications that a
/// socket sends in a second, after a burst of as many.
pub(crate) const REPLIES_PER_SECOND: u64 = 100;

const SECOND: u64 = 1_000_000_000;

/// A rate with a burst, as the generic cell rate algorithm keeps it: one
/// time, that at which the next event is due if none came before.
pub(crate) struct Rate {
    /// Nanoseconds after the clock's start.
    due: AtomicU64,
    /// Between two events at the rate.
    interval: u64,
    /// How far ahead of the clock `due` may be: a burst of `n` events is
    /// `n - 1` intervals.
    tolerance: u64,
}

impl Rate {
    pub(crate) const fn new(per_second: u64, burst: u64) -> Self {
        let interval = SECOND / per_second;
        Self {
            due: AtomicU64::new(0),
            interval,
            tolerance: interval * (burst - 1),
        }
    }

    /// Whether an event at `now` is within the rate, which it then uses.
    pub(crate) fn allow(&self, now: u64) -> bool {
        let mut due = self.due.load(Ordering::Relaxed);
        loop {
            let start = due.max(now);
            if start - now > self.tolerance {
                return false;
            }
            match self.due.compare_exchange_weak(
                due,
                start + self.interval,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => due = current,
            }
        }
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

/// The lines that a peer can cause, by kind: a flood of one kind leaves
/// the others to be logged.
pub(crate) struct Notices {
    start: Instant,
    pub(crate) replies: Rate,
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
            replies: Rate::new(REPLIES_PER_SECOND, REPLIES_PER_SECOND),
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
