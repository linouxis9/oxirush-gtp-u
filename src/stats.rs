use std::sync::atomic::{AtomicU64, Ordering};

/// Individually sampled receive counters shared by all clones of an endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiveStats {
    /// UDP datagrams received, including malformed or ignored messages.
    pub received_datagrams: u64,
    /// Datagrams rejected by the GTP-U decoder.
    pub malformed_datagrams: u64,
    /// Messages consumed by automatic path management, including protocol drops.
    pub path_messages: u64,
    /// Messages dropped because the application's receive queue was full.
    pub queue_full_drops: u64,
    /// Messages discarded because the application's receiver was closed.
    pub receiver_closed_drops: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) received_datagrams: AtomicU64,
    pub(crate) malformed_datagrams: AtomicU64,
    pub(crate) path_messages: AtomicU64,
    pub(crate) queue_full_drops: AtomicU64,
    pub(crate) receiver_closed_drops: AtomicU64,
}

impl Counters {
    pub(crate) fn snapshot(&self) -> ReceiveStats {
        ReceiveStats {
            received_datagrams: self.received_datagrams.load(Ordering::Relaxed),
            malformed_datagrams: self.malformed_datagrams.load(Ordering::Relaxed),
            path_messages: self.path_messages.load(Ordering::Relaxed),
            queue_full_drops: self.queue_full_drops.load(Ordering::Relaxed),
            receiver_closed_drops: self.receiver_closed_drops.load(Ordering::Relaxed),
        }
    }
}
