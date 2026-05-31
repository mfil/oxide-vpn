//! This module lets the control channel receive incoming packets in the correct order, send acks
//! for received packets, and periodically resend outgoing packets until an ack is received.

use std::cmp::min;
use std::io;
use std::iter::Iterator;
use std::time::{Duration, Instant};

use crate::packets::{ControlChannelPacketBuffer, Opcode};

/// Tracks packet IDs that we saw from the peer.
#[derive(Debug)]
pub struct PacketIdBuffer {
    /// The (up to) eight most recent packet IDs we have seen. We can ack them multiple times
    /// to avoid unnecessary resends in case the packet with the original ack got lost. This is
    /// recommended in the OpenVPN WIP RFC.
    ///
    /// The first [`unacked_ids_count`] elements of the buffer have not yet been acked.
    recent_packet_ids: [u32; 8],
    /// How many elements of `recent_packet_id`s are actually in use.
    recent_packet_ids_len: usize,
    /// How many elements have not yet been acked.
    unacked_ids_count: usize,
}

impl PacketIdBuffer {
    const SIZE: usize = 8;

    pub fn new() -> Self {
        Self {
            recent_packet_ids: [0; Self::SIZE],
            recent_packet_ids_len: 0,
            unacked_ids_count: 0,
        }
    }

    /// Returns true if there are any unacked IDs.
    pub fn has_unacked_ids(&self) -> bool {
        self.unacked_ids_count > 0
    }

    /// Returns true if adding a new ID would bump out another ID that has not yet been acked.
    pub fn filled_with_unacked_ids(&self) -> bool {
        self.unacked_ids_count == Self::SIZE
    }

    /// Insert a new packet ID that needs to be acked. If this ID already is in the buffer, move it
    /// to the front.
    pub fn insert(&mut self, id: u32) {
        // First, check if id already appears in the array.
        if let Some(index) = self.recent_packet_ids[..self.recent_packet_ids_len]
            .iter()
            .position(|value| *value == id)
        {
            // Move the element to the front.
            self.recent_packet_ids.copy_within(0..index, 1);
            self.recent_packet_ids[0] = id;

            // We count the id as unacked. If we acked it but it was resent anyway, then most likely
            // our previous ack got lost.
            if index >= self.unacked_ids_count {
                self.unacked_ids_count += 1;
            }
        } else {
            self.recent_packet_ids.copy_within(0..Self::SIZE - 1, 1);
            self.recent_packet_ids[0] = id;
            self.recent_packet_ids_len = min(Self::SIZE, self.recent_packet_ids_len + 1);
            self.unacked_ids_count = min(Self::SIZE, self.unacked_ids_count + 1);
        }
    }

    /// Returns up to `n` packet IDs to ack. The oldest IDs that have not been previously acked are
    /// prioritized. All returned packet IDs are now considered acked by the [`PacketIdBuffer`].
    pub fn ack(&mut self, n: usize) -> &[u32] {
        let return_amount = min(n, self.recent_packet_ids_len);
        if return_amount >= self.unacked_ids_count {
            self.unacked_ids_count = 0;
            &self.recent_packet_ids[0..return_amount]
        } else {
            // We can't ack all unacked packets, so we prioritize the ones that have waited the longest.
            let unacked_before = self.unacked_ids_count;
            self.unacked_ids_count -= return_amount;
            &self.recent_packet_ids[self.unacked_ids_count..unacked_before]
        }
    }
}

/// The parts of the packet that are relevant for the other parts of the control channel:
/// Opcode, key ID and payload.
type PacketContent = (Opcode, u8, Vec<u8>);

/// Stores the content of incoming packets and returns them in the correct order without duplicates.
#[derive(Debug)]
pub struct IncomingQueue {
    /// The next packet ID that we expect from the peer.
    expected_next_id: u32,
    /// The incoming packets, as pairs of the packet ID and the content.
    /// They are sorted by packet ID from low to high.
    packets: Vec<(u32, PacketContent)>,
}

impl IncomingQueue {
    pub fn new() -> Self {
        IncomingQueue {
            expected_next_id: 0,
            packets: Vec::new(),
        }
    }

    pub fn insert(&mut self, id: u32, content: PacketContent) {
        if id < self.expected_next_id {
            return;
        }

        if let Err(index) = self.packets.binary_search_by_key(&id, |(id, _)| *id) {
            self.packets.insert(index, (id, content));
            for (id, _) in &self.packets[index..] {
                if *id == self.expected_next_id {
                    self.expected_next_id += 1;
                } else {
                    break;
                }
            }
        }
    }

    /// Returns an iterator that yields the [`PacketContent`] items in the correct order.
    /// All items that are returned via a `next` call are removed from the queue.
    pub fn iter(&mut self) -> impl Iterator<Item = PacketContent> {
        self.packets
            .extract_if(.., |(id, _)| self.expected_next_id > *id)
            .map(|(_, content)| content)
    }
}

#[derive(Debug)]
struct ResendPacket {
    /// Packet ID.
    id: u32,
    /// Last time that we sent this packet.
    last_sent: Instant,
    /// Raw packet data, as it should be sent through the socket.
    data: ControlChannelPacketBuffer,
}

/// Holds packets that are pending acknowledgement by the peer.
#[derive(Debug)]
pub struct ResendQueue {
    /// Vector with the packets that should be periodically resent until an ack is reveived. The
    /// first part of the tuple is the packet ID.
    packets: Vec<ResendPacket>,
    /// How long to wait until packets are resent. This duration doubles every time that a packet
    /// is sent until it reaches [`MAX_TIMEOUT`] and is reset to [`BASE_TIMEOUT`]
    /// when acks are received. (Exponential backoff.)
    timeout: Duration,
}

impl ResendQueue {
    /// Initial interval.
    const BASE_TIMEOUT: Duration = Duration::from_secs(2);
    /// Maximal interval.
    const MAX_TIMEOUT: Duration = Duration::from_secs(16);

    /// Create a new empty `RetransmitBuffer`.
    pub fn new() -> Self {
        ResendQueue {
            packets: Vec::new(),
            timeout: Self::BASE_TIMEOUT,
        }
    }

    /// Add a packet to be sent
    pub fn add_packet(
        &mut self,
        time: Instant,
        packet_id: u32,
        packet: ControlChannelPacketBuffer,
    ) {
        self.packets.push(ResendPacket {
            id: packet_id,
            last_sent: time,
            data: packet,
        })
    }

    /// Remove packets whose ID appears in `acks`. Resets `timeout`.
    pub fn remove_acked_packets(&mut self, acks: &[u32]) {
        self.packets.retain(|p| !acks.contains(&p.id));
        self.timeout = Self::BASE_TIMEOUT;
    }

    /// Resend all packets that have not been sent within [`timeout`] from `time` by calling
    /// `send_function` on them. If that function returns an error, processing further packets is
    /// stopped and the error is returned. If no error occurs and at least one packet was sent,
    /// `timeout` is doubled.
    pub fn resend<T, F: FnMut(&[u8]) -> io::Result<T>>(
        &mut self,
        time: Instant,
        send_function: &mut F,
    ) -> io::Result<()> {
        let resend_cutoff = time - self.timeout;
        let mut did_resend = false;
        for packet in self.packets.iter_mut() {
            if packet.last_sent <= resend_cutoff {
                send_function(packet.data.as_slice())?;
                packet.last_sent = time;
                did_resend = true;
            }
        }
        if did_resend {
            self.timeout = min(self.timeout * 2, Self::MAX_TIMEOUT);
        }
        Ok(())
    }
}

#[cfg(test)]
mod packet_id_buffer_tests {
    use super::PacketIdBuffer;
    use std::ops::Range;

    fn packet_id_buffer_from_range(r: Range<u32>) -> PacketIdBuffer {
        let mut buffer = PacketIdBuffer::new();
        for id in r {
            buffer.insert(id);
        }
        buffer
    }

    #[test]
    fn returns_received_ids() {
        let mut id_buffer = PacketIdBuffer::new();
        id_buffer.insert(0);
        id_buffer.insert(1);
        id_buffer.insert(2);

        assert_eq!(id_buffer.ack(4), [2, 1, 0]);

        id_buffer.insert(3);
        id_buffer.insert(4);
        id_buffer.insert(5);

        assert_eq!(id_buffer.ack(4), [5, 4, 3, 2]);
        assert_eq!(id_buffer.ack(8), [5, 4, 3, 2, 1, 0]);

        id_buffer.insert(6);
        id_buffer.insert(7);

        assert_eq!(id_buffer.ack(8), [7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn tells_if_ack_packet_is_needed() {
        let mut buffer = packet_id_buffer_from_range(0..7);
        assert_eq!(buffer.filled_with_unacked_ids(), false);
        buffer.insert(7);
        assert_eq!(buffer.filled_with_unacked_ids(), true);
        buffer.ack(3);
        assert_eq!(buffer.filled_with_unacked_ids(), false);
    }

    #[test]
    fn prioritizes_oldest_unacked_ids() {
        let mut buffer = packet_id_buffer_from_range(0..6);
        assert_eq!(buffer.ack(4), [3, 2, 1, 0]);
        assert_eq!(buffer.unacked_ids_count, 2);
        buffer.insert(6);
        assert_eq!(buffer.unacked_ids_count, 3);
        assert_eq!(buffer.ack(4), [6, 5, 4, 3]);
        assert_eq!(buffer.unacked_ids_count, 0);
    }

    #[test]
    fn moves_repeated_ids_to_front() {
        let mut buffer = packet_id_buffer_from_range(0..8);
        _ = buffer.ack(8);
        buffer.insert(2);
        assert_eq!(buffer.unacked_ids_count, 1);
        assert_eq!(buffer.ack(4), [2, 7, 6, 5]);
        assert_eq!(buffer.unacked_ids_count, 0);
        assert_eq!(buffer.ack(8), [2, 7, 6, 5, 4, 3, 1, 0]);
    }
}

#[cfg(test)]
mod incoming_queue_tests {
    use super::{IncomingQueue, PacketContent};

    use crate::packets::Opcode;

    fn make_packet_content(payload: &[u8]) -> PacketContent {
        (Opcode::ControlV1, 0, payload.to_vec())
    }

    fn example_items() -> [PacketContent; 4] {
        [
            make_packet_content(b"Message 0"),
            make_packet_content(b"Message 1"),
            make_packet_content(b"Message 2"),
            make_packet_content(b"Message 3"),
        ]
    }

    #[test]
    fn handles_items_that_arrive_in_sequence() {
        let mut queue = IncomingQueue::new();
        let items = example_items();
        for (id, item) in items.iter().enumerate() {
            queue.insert(id as u32, item.clone())
        }
        assert_eq!(Vec::from_iter(queue.iter()), items);
        assert_eq!(Vec::from_iter(queue.iter()), []);
    }

    #[test]
    fn removes_only_accessed_items() {
        let mut queue = IncomingQueue::new();
        let items = example_items();
        for (id, item) in items.iter().enumerate() {
            queue.insert(id as u32, item.clone())
        }
        assert_eq!(Vec::from_iter(queue.iter().take(2)), &items[..2]);
        assert_eq!(Vec::from_iter(queue.iter()), &items[2..]);
    }

    #[test]
    fn fixes_packet_order() {
        let mut queue = IncomingQueue::new();
        let items = example_items();

        // Packets arrive in reverse.
        for (id, item) in items.iter().enumerate().rev() {
            queue.insert(id as u32, item.clone())
        }
        assert_eq!(Vec::from_iter(queue.iter().take(2)), &items[..2]);
        assert_eq!(Vec::from_iter(queue.iter()), &items[2..]);
    }

    #[test]
    fn waits_for_missing_packets() {
        let mut queue = IncomingQueue::new();
        let items = example_items();

        // Insert only the last item. The queue should not yield anything.
        queue.insert(3, items[3].clone());
        assert_eq!(Vec::from_iter(queue.iter()), []);

        // Insert the first item. This should be yielded.
        queue.insert(0, items[0].clone());
        assert_eq!(Vec::from_iter(queue.iter()), &items[..1]);

        // Insert the remaining two items. This should yield the rest.
        queue.insert(1, items[1].clone());
        queue.insert(2, items[2].clone());
        assert_eq!(Vec::from_iter(queue.iter()), &items[1..]);
    }

    #[test]
    fn ignores_duplicate_packets() {
        let mut queue = IncomingQueue::new();
        let items = [
            make_packet_content(b"Message 0"),
            make_packet_content(b"Message 1"),
            make_packet_content(b"Message 2"),
            make_packet_content(b"Message 3"),
            make_packet_content(b"Message 4"),
            make_packet_content(b"Message 5"),
            make_packet_content(b"Message 6"),
            make_packet_content(b"Message 7"),
        ];

        for (id, item) in items.iter().enumerate().take(4) {
            queue.insert(id as u32, item.clone())
        }

        // Duplicate of an item that is currently ready to be yielded.
        queue.insert(1, items[1].clone());
        assert_eq!(Vec::from_iter(queue.iter()), &items[..4]);

        // Duplicate of an item that was already yielded.
        queue.insert(2, items[2].clone());
        queue.insert(4, items[4].clone());
        assert_eq!(Vec::from_iter(queue.iter()), &items[4..5]);

        // Duplicate of an item that arrived out-of-order.
        queue.insert(6, items[6].clone());
        queue.insert(7, items[7].clone());
        queue.insert(6, items[6].clone());
        queue.insert(5, items[5].clone());
        assert_eq!(Vec::from_iter(queue.iter()), &items[5..]);
    }
}

#[cfg(test)]
mod resend_queue_tests {
    use crate::control_channel::test_helpers::ChannelWriteBuffer;
    use crate::packets::ControlChannelPacketBuffer;

    use super::ResendQueue;

    use std::time::{Duration, Instant};

    fn make_test_packet(payload: &[u8]) -> ControlChannelPacketBuffer {
        let mut out = ControlChannelPacketBuffer::with_payload_capacity(payload.len());
        out.extend_payload_from_slice(payload);
        out
    }

    #[test]
    fn can_add_and_resend_packets() {
        let mut resend = ResendQueue::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        resend.add_packet(t0, 0, make_test_packet(b"Packet0"));
        resend.add_packet(t0, 1, make_test_packet(b"Packet1"));
        let mut receive_buffer = ChannelWriteBuffer::new();
        resend
            .resend(t1, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 2);
        assert_eq!(receive_buffer[0], b"Packet0");
        assert_eq!(receive_buffer[1], b"Packet1");
    }

    #[test]
    fn removes_acked_packets() {
        let mut resend = ResendQueue::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        resend.add_packet(t0, 0, make_test_packet(b"Packet0"));
        resend.add_packet(t0, 1, make_test_packet(b"Packet1"));
        resend.add_packet(t0, 2, make_test_packet(b"Packet2"));
        resend.remove_acked_packets(&[0, 2]);
        let mut receive_buffer = ChannelWriteBuffer::new();
        resend
            .resend(t1, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 1);
        assert_eq!(receive_buffer[0], b"Packet1");
    }

    #[test]
    fn resends_unacked_packets() {
        let mut resend = ResendQueue::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        let t2 = t1 + Duration::from_secs(2);
        resend.add_packet(t0, 0, make_test_packet(b"Packet0"));
        resend.add_packet(t0, 1, make_test_packet(b"Packet1"));
        resend.add_packet(t0, 2, make_test_packet(b"Packet2"));

        // Resend packets at t1.
        let mut receive_buffer = ChannelWriteBuffer::new();
        resend
            .resend(t1, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 3);
        assert_eq!(receive_buffer[0], b"Packet0");
        assert_eq!(receive_buffer[1], b"Packet1");
        assert_eq!(receive_buffer[2], b"Packet2");

        // Ack one packet.
        resend.remove_acked_packets(&[1]);

        // Try to send again at t2.
        receive_buffer.clear();
        resend
            .resend(t2, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 2);
        assert_eq!(receive_buffer[0], b"Packet0");
        assert_eq!(receive_buffer[1], b"Packet2");
    }

    #[test]
    fn implements_exponential_backoff() {
        let mut resend = ResendQueue::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2); // First resend interval passed.
        let t2 = t1 + Duration::from_secs(2);
        let t3 = t2 + Duration::from_secs(2); // Second resend interval passed.
        let t4 = t3 + Duration::from_secs(2);
        let t5 = t4 + Duration::from_secs(2);
        let t6 = t5 + Duration::from_secs(2);
        let t7 = t6 + Duration::from_secs(2); // Third resend interval passed.
        resend.add_packet(t0, 0, make_test_packet(b"Packet0"));
        resend.add_packet(t0, 1, make_test_packet(b"Packet1"));
        resend.add_packet(t0, 2, make_test_packet(b"Packet2"));

        // Packets should be resent at t1.
        let mut receive_buffer = ChannelWriteBuffer::new();
        resend
            .resend(t1, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 3);

        // Packets should not be resent at t2.
        receive_buffer.clear();
        resend
            .resend(t2, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 0);

        // Packets should be resent at t3.
        receive_buffer.clear();
        resend
            .resend(t3, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 3);

        // Packets should not be resent at t4.
        receive_buffer.clear();
        resend
            .resend(t4, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 0);

        // Packets should not be resent at t5.
        receive_buffer.clear();
        resend
            .resend(t5, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 0);

        // Packets should not be resent at t6.
        receive_buffer.clear();
        resend
            .resend(t6, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 0);

        // Packets should be resent at t7.
        receive_buffer.clear();
        resend
            .resend(t7, &mut receive_buffer.get_send_function())
            .unwrap();
        assert_eq!(receive_buffer.len(), 3);
    }
}
