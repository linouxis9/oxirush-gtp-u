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
    /// G-PDUs on a TEID that has no tunnel or session, each answered with
    /// an Error Indication within the limit of replies, but for TEID 0.
    pub unknown_teid_g_pdus: u64,
    /// Error Indications that name no tunnel of an endpoint.
    pub unmatched_error_indications: u64,
    /// Messages that the endpoint or the test UPF does not take: End
    /// Markers on a TEID without a tunnel, the test UPF's Error Indications
    /// and End Markers, and messages of other types.
    pub ignored_messages: u64,
    /// Error Indications and Supported Extension Headers Notifications not
    /// sent: past 100 a second to an address after a burst of 100, or past
    /// 1,000 a second from the socket after a burst of 1,000.
    pub suppressed_replies: u64,
    /// Echo Responses not sent: past 10 a second to an address, after a
    /// burst of 10.
    pub suppressed_echo_responses: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) received_datagrams: AtomicU64,
    pub(crate) malformed_datagrams: AtomicU64,
    pub(crate) path_messages: AtomicU64,
    pub(crate) queue_full_drops: AtomicU64,
    pub(crate) receiver_closed_drops: AtomicU64,
    pub(crate) unknown_teid_g_pdus: AtomicU64,
    pub(crate) unmatched_error_indications: AtomicU64,
    pub(crate) ignored_messages: AtomicU64,
    pub(crate) suppressed_replies: AtomicU64,
    pub(crate) suppressed_echo_responses: AtomicU64,
}

impl Counters {
    pub(crate) fn snapshot(&self) -> ReceiveStats {
        ReceiveStats {
            received_datagrams: self.received_datagrams.load(Ordering::Relaxed),
            malformed_datagrams: self.malformed_datagrams.load(Ordering::Relaxed),
            path_messages: self.path_messages.load(Ordering::Relaxed),
            queue_full_drops: self.queue_full_drops.load(Ordering::Relaxed),
            receiver_closed_drops: self.receiver_closed_drops.load(Ordering::Relaxed),
            unknown_teid_g_pdus: self.unknown_teid_g_pdus.load(Ordering::Relaxed),
            unmatched_error_indications: self.unmatched_error_indications.load(Ordering::Relaxed),
            ignored_messages: self.ignored_messages.load(Ordering::Relaxed),
            suppressed_replies: self.suppressed_replies.load(Ordering::Relaxed),
            suppressed_echo_responses: self.suppressed_echo_responses.load(Ordering::Relaxed),
        }
    }
}
