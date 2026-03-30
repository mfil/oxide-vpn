use std::time::{Duration, Instant};

struct RetransmitPacket {
    /// Last time that we resent this packet.
    last_sent: Instant,
    /// Id of the packet.
    id: u32,
    /// Raw packet data, as it should be sent through the socket.
    content: Vec<u8>,
}

/// Holds packets that are pending acknowledgement by the peer.
pub struct RetransmitBuffer {
    packets: Vec<RetransmitPacket>,
}

impl RetransmitBuffer {
    /// How long to wait before resending a packet that has not been acked.
    const RETRANSMIT_INTERVAL: Duration = Duration::from_secs(10);

    /// Create a new empty `RetransmitBuffer`.
    pub fn new() -> Self {
        RetransmitBuffer {
            packets: Vec::new(),
        }
    }

    /// Add a packet to the buffer.
    pub fn add_packet(&mut self, time: Instant, packet_id: u32, packet: Vec<u8>) {
        self.packets.push(RetransmitPacket {
            last_sent: time,
            id: packet_id,
            content: packet,
        })
    }

    /// Remove packets whose `packet_id` appears in `acks`.
    ///
    /// This function assumes that `packet_id`s are unique and therefore removes only the first
    /// occurrence that it encounters.
    pub fn remove_acked_packets(&mut self, acks: &[u32]) {
        for ack in acks {
            let mut enumerated_packets = self.packets.iter().enumerate();
            if let Some((index, _)) = enumerated_packets.find(|(_, packet)| packet.id == *ack) {
                self.packets.swap_remove(index);
            }
        }
    }

    /// Get a vector with all packets that should be resent.
    ///
    /// The packets may appear in a different order than they were added.
    pub fn get_packets_to_resend(&mut self, time: Instant) -> Vec<&[u8]> {
        Vec::new()
    }
}

#[cfg(test)]
mod test {
    use super::RetransmitBuffer;

    use std::time::{Duration, Instant};

    #[test]
    fn can_add_packet() {
        let mut retransmit = RetransmitBuffer::new();
        let time1 = Instant::now();
        retransmit.add_packet(time1, 0, Vec::from(b"Packet1"));

        let time2 = time1 + Duration::from_secs(23);
        retransmit.add_packet(time2, 1, Vec::from(b"Packet2"));

        assert_eq!(retransmit.packets[0].last_sent, time1);
        assert_eq!(retransmit.packets[0].id, 0);
        assert_eq!(retransmit.packets[0].content, b"Packet1");

        assert_eq!(retransmit.packets[1].last_sent, time2);
        assert_eq!(retransmit.packets[1].id, 1);
        assert_eq!(retransmit.packets[1].content, b"Packet2");
    }

    #[test]
    fn can_remove_acked_packets() {
        let mut retransmit = RetransmitBuffer::new();
        let time1 = Instant::now();
        retransmit.add_packet(time1, 0, Vec::from(b"Packet1"));

        let time2 = time1 + Duration::from_secs(23);
        retransmit.add_packet(time2, 1, Vec::from(b"Packet2"));

        let time3 = time2 + Duration::from_secs(5);
        retransmit.add_packet(time3, 2, Vec::from(b"Packet3"));

        retransmit.remove_acked_packets(&[1, 3]);
        for packet in retransmit.packets {
            assert_ne!(packet.id, 1);
            assert_ne!(packet.id, 3);
        }
    }

    #[test]
    fn only_remove_acked_packets() {
        let mut retransmit = RetransmitBuffer::new();
        let time1 = Instant::now();
        retransmit.add_packet(time1, 0, Vec::from(b"Packet1"));

        let time2 = time1 + Duration::from_secs(23);
        retransmit.add_packet(time2, 1, Vec::from(b"Packet2"));

        let time3 = time2 + Duration::from_secs(5);
        retransmit.add_packet(time3, 2, Vec::from(b"Packet3"));

        let time4 = time3 + Duration::from_secs(3);
        retransmit.add_packet(time4, 3, Vec::from(b"Packet4"));

        retransmit.remove_acked_packets(&[0, 2]);
        assert!(retransmit.packets.iter().any(|packet| packet.id == 1));
        assert!(retransmit.packets.iter().any(|packet| packet.id == 3));
    }

    /*
    #[test]
    fn get_resend_packets() {
        let mut retransmit = RetransmitBuffer::new();
        let time1 = Instant::now();
        retransmit.add_packet(time1, 0, Vec::from(b"Packet1"));

        assert_eq!(
            retransmit.get_packets_to_resend(time1),
            vec![] as Vec<&[u8]>
        );

        let time2 = time1 + Duration::from_secs(23);
        retransmit.add_packet(time2, 1, Vec::from(b"Packet2"));

        let time3 = time2 + Duration::from_secs(5);
        retransmit.add_packet(time3, 2, Vec::from(b"Packet3"));

        // Should resend the first two packets now.
        let packets = retransmit.get_packets_to_resend(time3);
        assert_eq!(packets.len(), 2);
        assert!(packets.contains(&b"Packet1".as_slice()));
        assert!(packets.contains(&b"Packet2".as_slice()));

        let time4 = time3 + Duration::from_secs(6);
        retransmit.add_packet(time4, 3, Vec::from(b"Packet4"));

        // Should resend the third packet now, but not the first two because they already were
        // resent recently.
        let packets = retransmit.get_packets_to_resend(time4);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"Packet3");
    }
    */
}
