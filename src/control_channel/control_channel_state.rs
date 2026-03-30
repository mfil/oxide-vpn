use std::cmp::min;

use crate::packets::{ControlChannelPacket, Opcode, Packet};

/// Tracks packet IDs that we saw from the peer.
#[derive(Debug)]
struct PacketIdBuffer {
    /// Packet IDs that have not yet been acked.
    pub unacked_ids: Vec<u32>,
    /// The (up to) eight most recent packet IDs for which we have sent acks. We can ack them again
    /// to avoid unnecessary resends in case the packet with the original ack got lost. This is
    /// recommended in the OpenVPN WIP RFC.
    recent_packet_ids: [u32; 8],
    /// How many elements of `recent_packet_id`s are actually in use.
    recent_packet_ids_len: usize,
}

impl PacketIdBuffer {
    pub fn new() -> Self {
        Self {
            unacked_ids: Vec::with_capacity(8),
            recent_packet_ids: [0; 8],
            recent_packet_ids_len: 0,
        }
    }

    /// Returns up to `n` packet IDs to ack. IDs that have not been previously acked are
    /// prioritized. The number is filled out with other recently seen packet IDs, if available.
    /// All returned packet IDs are now considered acked by the [`PacketIdBuffer`].
    pub fn ack(&mut self, n: usize) -> &[u32] {
        let max_output_amount = min(n, 8);
        let newly_acked_amount = min(self.unacked_ids.len(), max_output_amount);
        let newly_acked_ids = &self.unacked_ids[..newly_acked_amount];

        // Free up slots in recent_packet_ids for the newly acked IDs and copy them.
        self.recent_packet_ids.copy_within(newly_acked_amount.., 0);
        self.recent_packet_ids[8 - newly_acked_amount..].copy_from_slice(newly_acked_ids);
        self.recent_packet_ids_len = min(8, self.recent_packet_ids_len + newly_acked_amount);

        self.unacked_ids.copy_within(newly_acked_amount.., 0);
        let remaining_unacked_amount = self.unacked_ids.len() - newly_acked_amount;
        self.unacked_ids.truncate(remaining_unacked_amount);

        let slice_start = 8 - min(self.recent_packet_ids_len, max_output_amount);
        &self.recent_packet_ids[slice_start..]
    }
}

/// Stores information about the control channel of the session, such as what should be our next
/// packet ID, what packet IDs do we need to ack, etc.
///
/// Given a opcode and payload, this object fills in the remaining fields to make a control channel
/// packet.
#[derive(Debug)]
pub struct ControlChannelState {
    next_packet_id: u32,
    session_id: u64,
    key_id: u8,
    peer_session_id: Option<u64>,
    peer_packet_ids: PacketIdBuffer,
}

impl ControlChannelState {
    pub fn new(session_id: u64) -> Self {
        Self {
            next_packet_id: 0,
            session_id,
            key_id: 0,
            peer_session_id: None,
            peer_packet_ids: PacketIdBuffer::new(),
        }
    }

    pub fn unacked_packets(&self) -> usize {
        self.peer_packet_ids.unacked_ids.len()
    }

    /// Make a control channel packet with the given opcode and payload.
    ///
    /// This increments the `next_packet_id` and marks some of the peer packet IDs as acked.
    pub fn make_packet(&mut self, opcode: Opcode, payload: Vec<u8>) -> ControlChannelPacket {
        if opcode == Opcode::ControlAckV1 {
            self.make_ack_packet();
        }

        let packet_id = Some(self.next_packet_id);
        self.next_packet_id += 1;

        let acks = self.peer_packet_ids.ack(4).to_vec();
        let peer_session_id = if acks.len() > 0 {
            self.peer_session_id
        } else {
            None
        };

        ControlChannelPacket {
            opcode,
            key_id: self.key_id,
            session_id: self.session_id,
            acks,
            peer_session_id,
            packet_id,
            payload,
        }
    }

    /// Make an ACK packet.
    ///
    /// These are special control channel packets that only serve to ack received packets. They can
    /// be sent if we are not sending enough regular packets to ack all the packets we get from our
    /// peer. They don't have a payload or message ID.
    pub fn make_ack_packet(&mut self) -> ControlChannelPacket {
        let acks = self.peer_packet_ids.ack(8).to_vec();
        let peer_session_id = if acks.len() > 0 {
            self.peer_session_id
        } else {
            None
        };

        ControlChannelPacket {
            opcode: Opcode::ControlAckV1,
            key_id: self.key_id,
            session_id: self.session_id,
            acks,
            peer_session_id,
            packet_id: None,
            payload: Vec::new(),
        }
    }

    /// Update the state based on a packet from our peer.
    pub fn process_packet<'b>(&mut self, packet: &ControlChannelPacket) {
        self.peer_session_id = Some(packet.session_id);
        if let Some(packet_id) = packet.packet_id {
            self.peer_packet_ids.unacked_ids.push(packet_id);
        }
    }
}

#[cfg(test)]
mod test {
    use super::ControlChannelState;
    use crate::packets::{ControlChannelPacket, Opcode, Packet};

    fn make_packet_with_id(id: u32) -> ControlChannelPacket {
        ControlChannelPacket {
            opcode: Opcode::ControlV1,
            key_id: 0,
            session_id: 0xf1f2f3f4f5f6f7f8,
            acks: Vec::new(),
            peer_session_id: Some(0x0102030405060708),
            packet_id: Some(id),
            payload: Vec::new(),
        }
    }

    #[test]
    fn packet_channel_increments_packet_id() {
        let mut packet_channel = ControlChannelState::new(0x0102030405060708);
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(packet.packet_id, Some(0));
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(packet.packet_id, Some(1));
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(packet.packet_id, Some(2));

        packet_channel.next_packet_id = 23;
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(packet.packet_id, Some(23));
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(packet.packet_id, Some(24));
    }

    #[test]
    fn packet_channel_acks_packets() {
        let mut packet_channel = ControlChannelState::new(0x0102030405060708);
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(&packet.acks, &[]);

        packet_channel.process_packet(&make_packet_with_id(0));
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(&packet.acks, &[0]);

        packet_channel.process_packet(&make_packet_with_id(1));
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(&packet.acks, &[0, 1]);

        packet_channel.process_packet(&make_packet_with_id(2));
        packet_channel.process_packet(&make_packet_with_id(3));
        packet_channel.process_packet(&make_packet_with_id(4));
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(&packet.acks, &[1, 2, 3, 4]);

        packet_channel.process_packet(&make_packet_with_id(5));
        packet_channel.process_packet(&make_packet_with_id(6));
        let packet = packet_channel.make_ack_packet();
        assert_eq!(&packet.acks, &[0, 1, 2, 3, 4, 5, 6]);

        packet_channel.process_packet(&make_packet_with_id(7));
        packet_channel.process_packet(&make_packet_with_id(8));
        let packet = packet_channel.make_ack_packet();
        assert_eq!(&packet.acks, &[1, 2, 3, 4, 5, 6, 7, 8]);

        packet_channel.process_packet(&make_packet_with_id(9));
        packet_channel.process_packet(&make_packet_with_id(10));
        let packet = packet_channel.make_packet(Opcode::ControlV1, Vec::new());
        assert_eq!(&packet.acks, &[7, 8, 9, 10]);
    }
}
