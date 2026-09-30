//! UDP mechanics shared by the RAN endpoint and the simulator.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Sender, error::TrySendError};
use tracing::debug;

use crate::path;
use crate::stats::Counters;
use crate::{Packet, ReceiveStats};

/// The socket and protocol processing, without a role's registry or task owner.
/// Receive tasks may retain this value without retaining their own join handle.
pub(crate) struct DatagramSocket {
    socket: UdpSocket,
    ipv6: bool,
    counters: Counters,
}

impl DatagramSocket {
    pub(crate) async fn bind(address: SocketAddr) -> io::Result<Self> {
        if address.ip().to_canonical().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GTP-U requires a specific bind address",
            ));
        }
        let socket = UdpSocket::bind(address).await?;
        let ipv6 = socket.local_addr()?.is_ipv6();
        Ok(Self {
            socket,
            ipv6,
            counters: Counters::default(),
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) fn stats(&self) -> ReceiveStats {
        self.counters.snapshot()
    }

    /// Receive one datagram. Malformed and path-management messages are handled
    /// here and return `None`; the role handles the remaining message types.
    /// The payload borrows the caller's buffer until it is forwarded or observed.
    pub(crate) async fn receive<'a>(
        &self,
        buffer: &'a mut [u8],
    ) -> io::Result<Option<(Packet<&'a [u8]>, SocketAddr)>> {
        let (size, from) = loop {
            match self.socket.recv_from(buffer).await {
                Ok(received) => break received,
                Err(error) if path::transient(&error) => continue,
                Err(error) => return Err(error),
            }
        };
        self.counters
            .received_datagrams
            .fetch_add(1, Ordering::Relaxed);
        let packet = match Packet::decode_borrowed(&buffer[..size]) {
            Ok(packet) => packet,
            Err(error) => {
                self.counters
                    .malformed_datagrams
                    .fetch_add(1, Ordering::Relaxed);
                debug!("GTP-U dropped a malformed message from {from}: {error}");
                path::answer_length_error(&self.socket, &buffer[..size], from).await;
                return Ok(None);
            }
        };
        if path::answer(&self.socket, &packet, from).await {
            self.counters.path_messages.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        Ok(Some((packet, path::canonical(from))))
    }

    pub(crate) async fn send<P: AsRef<[u8]>>(
        &self,
        packet: &Packet<P>,
        to: SocketAddr,
    ) -> io::Result<()> {
        let bytes = packet
            .encode()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.socket.send_to(&bytes, self.destination(to)).await?;
        Ok(())
    }

    pub(crate) fn destination(&self, address: SocketAddr) -> SocketAddr {
        path::destination(self.ipv6, address)
    }

    pub(crate) async fn writable(&self) -> io::Result<()> {
        self.socket.writable().await
    }

    /// The registry owns the synchronization around this nonblocking syscall.
    pub(crate) fn try_send_to(&self, bytes: &[u8], to: SocketAddr) -> io::Result<usize> {
        self.socket.try_send_to(bytes, to)
    }

    pub(crate) async fn error_indication(&self, teid: u32, from: SocketAddr) {
        path::error_indication(&self.socket, teid, self.destination(from)).await;
    }

    /// Reserve first so a dropped observation does not copy its borrowed payload.
    pub(crate) fn observe<T>(&self, tx: &Sender<T>, build: impl FnOnce() -> T) {
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(build());
            }
            Err(TrySendError::Full(_)) => {
                self.counters
                    .queue_full_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Closed(_)) => {
                self.counters
                    .receiver_closed_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn receive_borrows_the_datagram_payload() {
        let socket = DatagramSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bytes = Packet::g_pdu(42, b"payload").encode().unwrap();
        peer.send_to(&bytes, socket.local_addr().unwrap())
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let payload_start = buffer.as_ptr().wrapping_add(8);
        let (packet, from) = socket.receive(&mut buffer).await.unwrap().unwrap();
        assert_eq!(packet.payload, b"payload");
        assert_eq!(packet.payload.as_ptr(), payload_start);
        assert_eq!(from, peer.local_addr().unwrap());
    }

    #[tokio::test]
    async fn dropped_observations_do_not_construct_owned_packets() {
        let socket = DatagramSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(1);
        socket.observe(&tx, || 1);
        let mut built = false;
        socket.observe(&tx, || {
            built = true;
            2
        });
        assert!(!built);
        drop(rx);
        socket.observe(&tx, || {
            built = true;
            3
        });
        assert!(!built);
        let stats = socket.stats();
        assert_eq!(stats.queue_full_drops, 1);
        assert_eq!(stats.receiver_closed_drops, 1);
    }
}
