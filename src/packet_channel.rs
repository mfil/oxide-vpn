use std::cmp::min;

use crate::packets::{ControlChannelPacket, Opcode, OpcodeType, Packet};

struct PacketIdBuffer {
    /// Packet IDs that have not yet been acked.
    unacked_ids: Vec<u32>,
    /// The (up to) eight most recent packet IDs for which we have sent acks. We can ack them again
    /// to avoid unnecessary resends in case our packets got lost.
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

    pub fn insert_id(&mut self, id: u32) {
        self.unacked_ids.push(id);
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

struct PacketChannel {
    next_packet_id: u32,
    session_id: u64,
    key_id: u8,
    peer_session_id: Option<u64>,
    peer_packet_ids: PacketIdBuffer,
}

impl PacketChannel {
    pub fn new(session_id: u64) -> Self {
        Self {
            next_packet_id: 0,
            session_id,
            key_id: 0,
            peer_session_id: None,
            peer_packet_ids: PacketIdBuffer::new(),
        }
    }

    pub fn make_packet<'b>(&mut self, opcode: Opcode, payload: &'b [u8]) -> Packet<'b> {
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

        if opcode.get_type() == OpcodeType::Control {
            Packet::Control(ControlChannelPacket {
                opcode,
                key_id: self.key_id,
                session_id: self.session_id,
                acks,
                peer_session_id,
                packet_id,
                payload,
            })
        } else {
            panic!("at the disco");
        }
    }

    pub fn make_ack_packet(&mut self) -> Packet<'static> {
        let acks = self.peer_packet_ids.ack(8).to_vec();
        let peer_session_id = if acks.len() > 0 {
            self.peer_session_id
        } else {
            None
        };

        Packet::Control(ControlChannelPacket {
            opcode: Opcode::ControlAckV1,
            key_id: self.key_id,
            session_id: self.session_id,
            acks,
            peer_session_id,
            packet_id: None,
            payload: &[],
        })
    }

    pub fn process_packet<'b>(&mut self, packet: &Packet<'b>) -> Option<(Opcode, Vec<u8>)> {
        self.peer_session_id = Some(packet.get_session_id());
        let opcode = packet.get_opcode();

        if let Some(packet_id) = packet.get_packet_id() {
            self.peer_packet_ids.insert_id(packet_id);
        }

        if opcode != Opcode::ControlAckV1 {
            Some((opcode, packet.get_payload().to_vec()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::PacketChannel;
    use crate::packets::{ControlChannelPacket, Opcode, Packet};

    fn make_packet_with_id(id: u32) -> Packet<'static> {
        Packet::Control(ControlChannelPacket {
            opcode: Opcode::ControlV1,
            key_id: 0,
            session_id: 0xf1f2f3f4f5f6f7f8,
            acks: Vec::new(),
            peer_session_id: Some(0x0102030405060708),
            packet_id: Some(id),
            payload: &[],
        })
    }

    #[test]
    fn packet_channel_increments_packet_id() {
        let mut packet_channel = PacketChannel::new(0x0102030405060708);
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_packet_id(), Some(0));
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_packet_id(), Some(1));
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_packet_id(), Some(2));

        packet_channel.next_packet_id = 23;
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_packet_id(), Some(23));
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_packet_id(), Some(24));
    }

    #[test]
    fn packet_channel_sends_and_receives_payloads_and_opcodes() {
        let mut packet_channel = PacketChannel::new(0x0102030405060708);
        let mut packet_channel2 = PacketChannel::new(0xf1f2f3f4f5f6f7f8);

        let packet = packet_channel.make_packet(Opcode::ControlHardResetClientV2, &[]);
        let (opcode, payload) = packet_channel2.process_packet(&packet).unwrap();
        assert_eq!(opcode, Opcode::ControlHardResetClientV2);
        assert_eq!(payload, &[]);

        let packet = packet_channel2.make_packet(Opcode::ControlHardResetServerV2, &[]);
        let (opcode, payload) = packet_channel.process_packet(&packet).unwrap();
        assert_eq!(opcode, Opcode::ControlHardResetServerV2);
        assert_eq!(payload, &[]);

        let packet = packet_channel.make_packet(Opcode::ControlV1, b"Hello World");
        let (_, payload) = packet_channel2.process_packet(&packet).unwrap();
        assert_eq!(payload, b"Hello World");
    }

    #[test]
    fn packet_channel_acks_packets() {
        let mut packet_channel = PacketChannel::new(0x0102030405060708);
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_acks(), &[]);

        packet_channel.process_packet(&make_packet_with_id(0));
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_acks(), &[0]);

        packet_channel.process_packet(&make_packet_with_id(1));
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_acks(), &[0, 1]);

        packet_channel.process_packet(&make_packet_with_id(2));
        packet_channel.process_packet(&make_packet_with_id(3));
        packet_channel.process_packet(&make_packet_with_id(4));
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_acks(), &[1, 2, 3, 4]);

        packet_channel.process_packet(&make_packet_with_id(5));
        packet_channel.process_packet(&make_packet_with_id(6));
        let packet = packet_channel.make_ack_packet();
        assert_eq!(packet.get_acks(), &[0, 1, 2, 3, 4, 5, 6]);

        packet_channel.process_packet(&make_packet_with_id(7));
        packet_channel.process_packet(&make_packet_with_id(8));
        let packet = packet_channel.make_ack_packet();
        assert_eq!(packet.get_acks(), &[1, 2, 3, 4, 5, 6, 7, 8]);

        packet_channel.process_packet(&make_packet_with_id(9));
        packet_channel.process_packet(&make_packet_with_id(10));
        let packet = packet_channel.make_packet(Opcode::ControlV1, &[]);
        assert_eq!(packet.get_acks(), &[7, 8, 9, 10]);
    }
}
