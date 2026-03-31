//! This module defines the different packet types used in OpenVPN and contains functions for parsing them.

use std::convert::From;
use std::error::Error;
use std::fmt;
use std::iter::zip;

#[derive(Debug)]
pub struct PacketError {
    message: &'static str,
}

impl fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Parse error: {}", self.message)
    }
}

impl Error for PacketError {}

impl PacketError {
    fn with_message(message: &'static str) -> Self {
        PacketError { message }
    }
}

impl From<&'static str> for PacketError {
    fn from(message: &'static str) -> Self {
        PacketError::with_message(message)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpcodeType {
    Control,
    Data,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Opcode {
    /// Control channel packet with TLS protocol data.
    ControlV1 = 4,
    /// All control channel packets in OpenVPN can send along ACKs for up to four received packets.
    /// This is a dedicated ACK packet that sends ACKs for up to eight.
    ControlAckV1 = 5,
    /// Initial key from client, forget previous state
    ControlHardResetClientV2 = 7,
    /// Initial key from server, forget previous state
    ControlHardResetServerV2 = 8,
}

impl TryFrom<u8> for Opcode {
    type Error = PacketError;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            4 => Ok(Opcode::ControlV1),
            5 => Ok(Opcode::ControlAckV1),
            7 => Ok(Opcode::ControlHardResetClientV2),
            8 => Ok(Opcode::ControlHardResetServerV2),
            _ => Err(PacketError::with_message("Invalid opcode")),
        }
    }
}

impl Opcode {
    pub fn get_type(&self) -> OpcodeType {
        match *self {
            Opcode::ControlV1 => OpcodeType::Control,
            Opcode::ControlAckV1 => OpcodeType::Control,
            Opcode::ControlHardResetClientV2 => OpcodeType::Control,
            Opcode::ControlHardResetServerV2 => OpcodeType::Control,
        }
    }

    fn is_ack(&self) -> bool {
        *self == Opcode::ControlAckV1
    }
}

#[derive(Debug)]
pub struct ControlChannelPacket<'a> {
    pub opcode: Opcode,
    pub key_id: u8,
    pub session_id: u64,
    pub acks: Vec<u32>,
    pub peer_session_id: Option<u64>,
    pub packet_id: Option<u32>,
    pub payload: &'a [u8],
}

impl<'a> ControlChannelPacket<'a> {
    /// Calculate the required buffer size to write this packet in the wire format.
    fn size(&self) -> usize {
        let mut packet_size: usize = 1 + size_of::<u64>() + 1 + self.acks.len() * size_of::<u32>();
        if self.peer_session_id.is_some() {
            packet_size += size_of::<u64>();
        }
        if self.packet_id.is_some() {
            packet_size += size_of::<u32>();
        }
        packet_size += self.payload.len();
        packet_size
    }

    /// Write the packet in wire format to a buffer.
    pub fn to_buffer(&self, buffer: &mut [u8]) -> Result<usize, PacketError> {
        // Check that the packet is valid.
        if self.opcode.get_type() != OpcodeType::Control {
            return Err(PacketError::with_message("Bad opcode"));
        }
        if self.key_id > 7 {
            return Err(PacketError::with_message("Key ID too large"));
        }
        if self.opcode.is_ack() {
            if self.packet_id.is_some() {
                return Err(PacketError::with_message(
                    "Ack packets don't have packet IDs.",
                ));
            }
            if self.acks.len() > 8 {
                return Err(PacketError::with_message(
                    "ControlAckV1 packets can have at most 8 acks.",
                ));
            }
        } else {
            if self.packet_id.is_none() {
                return Err(PacketError::with_message(
                    "Control channel packets must have packet IDs.",
                ));
            }
            if self.acks.len() > 4 {
                return Err(PacketError::with_message(
                    "Control channel packets can have at most 4 acks.",
                ));
            }
        }
        if self.acks.len() > 0 && self.peer_session_id.is_none() {
            return Err(PacketError::with_message(
                "Control channel packets must have a peer session ID if they have acks.",
            ));
        }

        let size = self.size();
        if buffer.len() < size {
            return Err(PacketError::with_message("Buffer too small"));
        }
        buffer[0] = ((self.opcode as u8) << 3) | self.key_id;
        let (session_id_buffer, rest) = buffer[1..].split_first_chunk_mut::<8>().unwrap();
        *session_id_buffer = self.session_id.to_be_bytes();
        let num_acks = self.acks.len() as u8;
        rest[0] = num_acks;

        let (acks_buffer, rest) = rest[1..].split_at_mut((num_acks as usize) * size_of::<u32>());
        let (acks_buffer_chunked, _) = acks_buffer.as_chunks_mut::<4>();
        for (ack_buffer, ack) in zip(acks_buffer_chunked, &self.acks) {
            *ack_buffer = ack.to_be_bytes();
        }

        let rest = if let Some(peer_session_id) = self.peer_session_id {
            let (peer_session_id_buffer, rest) = rest.split_first_chunk_mut::<8>().unwrap();
            *peer_session_id_buffer = peer_session_id.to_be_bytes();
            rest
        } else {
            rest
        };

        let rest = if let Some(packet_id) = self.packet_id {
            let (packet_id_buffer, rest) = rest.split_first_chunk_mut::<4>().unwrap();
            *packet_id_buffer = packet_id.to_be_bytes();
            rest
        } else {
            rest
        };
        rest[..self.payload.len()].copy_from_slice(self.payload);

        Ok(size)
    }
}

pub struct DataChannelPacket<'a> {
    opcode: Opcode,
    session_id: u64,
    payload: &'a [u8],
}

/// OpenVPN UDP packet.
pub enum Packet<'a> {
    Control(ControlChannelPacket<'a>),
    Data(DataChannelPacket<'a>),
}

impl<'a> Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Packet<'a>, PacketError> {
        let first_byte = data
            .get(0)
            .ok_or(PacketError::with_message("Empty packet"))?;
        let opcode = Opcode::try_from(first_byte >> 3)?;
        let key_id = first_byte & 0x07;
        match opcode.get_type() {
            OpcodeType::Control => Self::parse_control_packet(opcode, key_id, data),
            OpcodeType::Data => panic!("Not implemented"),
        }
    }

    fn parse_control_packet(
        opcode: Opcode,
        key_id: u8,
        data: &'a [u8],
    ) -> Result<Packet, PacketError> {
        let (session_id_bytes, rest) = data[1..]
            .split_first_chunk::<8>()
            .ok_or("Control channel packet too short.")?;
        let session_id = u64::from_be_bytes(*session_id_bytes);
        let (num_acks_byte, rest) = rest
            .split_first()
            .ok_or("Control channel packet too short.")?;
        let num_acks = *num_acks_byte as usize;
        let (acks_portion, rest) = rest
            .split_at_checked(num_acks * size_of::<u32>())
            .ok_or("Control channel packet too short.")?;
        let (ack_chunks, _) = acks_portion.as_chunks::<4>();

        let mut acks = Vec::<u32>::with_capacity(num_acks);
        for ack_id in ack_chunks {
            acks.push(u32::from_be_bytes(*ack_id));
        }

        // We have a peer session ID if and only if we have any acks.
        let (peer_session_id, rest) = if num_acks > 0 {
            let (peer_session_id_bytes, rest) = rest
                .split_first_chunk::<8>()
                .ok_or("Control channel packet too short.")?;
            let peer_session_id = u64::from_be_bytes(*peer_session_id_bytes);
            (Some(peer_session_id), rest)
        } else {
            (None, rest)
        };

        // We have a packet ID unless it is an ack packet.
        let (packet_id, payload) = if !opcode.is_ack() {
            let (packet_id_bytes, rest) = rest
                .split_first_chunk::<4>()
                .ok_or("Control channel packet too short.")?;
            let packet_id = u32::from_be_bytes(*packet_id_bytes);
            (Some(packet_id), rest)
        } else {
            (None, rest)
        };

        let control_packet = ControlChannelPacket {
            opcode,
            key_id,
            session_id,
            acks,
            peer_session_id,
            packet_id,
            payload,
        };
        Ok(Self::Control(control_packet))
    }

    /// Write the packet in the wire format to a buffer.
    pub fn to_buffer(&self, buffer: &mut [u8]) -> Result<usize, PacketError> {
        match self {
            Self::Control(control_packet) => control_packet.to_buffer(buffer),
            Self::Data(_) => panic!("Not implemented"),
        }
    }

    pub fn get_opcode(&self) -> Opcode {
        match self {
            Self::Control(p) => p.opcode,
            Self::Data(p) => p.opcode,
        }
    }

    pub fn get_session_id(&self) -> u64 {
        match self {
            Self::Control(p) => p.session_id,
            Self::Data(p) => p.session_id,
        }
    }

    pub fn get_acks(&self) -> &[u32] {
        match self {
            Self::Control(p) => &p.acks,
            Self::Data(_) => &[],
        }
    }

    pub fn get_packet_id(&self) -> Option<u32> {
        match self {
            Self::Control(p) => p.packet_id,
            Self::Data(p) => None,
        }
    }

    pub fn get_payload(&self) -> &'a [u8] {
        match self {
            Self::Control(p) => p.payload,
            Self::Data(p) => p.payload,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Opcode, Packet};

    const VALID_PACKET_NO_ACKS: &'static [u8] = &[
        7 << 3, // Opcode ControlHardResetClientV2
        1,      // Session ID
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        0, // No acks (and therefore no peer session ID)
        0, // Packet ID
        0,
        0,
        0,
    ];

    const VALID_PACKET_WITH_ACK: &'static [u8] = &[
        8 << 3, // Opcode ControlHardResetServerV2
        0xf1,   // Session ID
        0xf2,
        0xf3,
        0xf4,
        0xf5,
        0xf6,
        0xf7,
        0xf8,
        1, // One ack.
        0, // Acked packet
        0,
        0,
        0,
        1, // Peer session ID
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        0, // Packet ID
        0,
        0,
        0,
    ];

    const VALID_PACKET_WITH_ACKS_AND_PAYLOAD: &'static [u8] = &[
        4 << 3 | 2, // Opcode ControlV1 plus key_id 2
        0xf1,       // Session ID
        0xf2,
        0xf3,
        0xf4,
        0xf5,
        0xf6,
        0xf7,
        0xf8,
        2, // Two acks.
        0, // Acked packet
        0,
        0,
        2,
        0, // Acked packet
        0,
        0,
        3,
        1, // Peer session ID
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        0, // Packet ID
        0,
        0,
        3,
        b'h', // Payload
        b'e',
        b'l',
        b'l',
        b'o',
    ];

    const BAD_OPCODE: &'static [u8] = &[
        23 << 3, // Funny opcode
        1,       // Session ID
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        0, // No acks (and therefore no peer session ID)
        0, // Packet ID
        0,
        0,
        0,
    ];

    #[test]
    fn can_parse_valid_control_packets() {
        let packet = Packet::parse(VALID_PACKET_NO_ACKS).unwrap();
        if let Packet::Control(control_packet) = packet {
            assert_eq!(control_packet.opcode, Opcode::ControlHardResetClientV2);
            assert_eq!(control_packet.key_id, 0);
            assert_eq!(control_packet.session_id, 0x0102030405060708);
            assert_eq!(control_packet.acks.len(), 0);
            assert_eq!(control_packet.packet_id, Some(0));
            assert!(control_packet.peer_session_id.is_none());
            assert_eq!(control_packet.payload.len(), 0);
        } else {
            assert!(false);
        }

        let packet = Packet::parse(VALID_PACKET_WITH_ACK).unwrap();
        if let Packet::Control(control_packet) = packet {
            assert_eq!(control_packet.opcode, Opcode::ControlHardResetServerV2);
            assert_eq!(control_packet.key_id, 0);
            assert_eq!(control_packet.session_id, 0xf1f2f3f4f5f6f7f8);
            assert_eq!(control_packet.acks.len(), 1);
            assert_eq!(control_packet.acks[0], 0x0);
            assert_eq!(control_packet.peer_session_id, Some(0x0102030405060708));
            assert_eq!(control_packet.packet_id, Some(0));
        } else {
            assert!(false);
        }

        let packet = Packet::parse(VALID_PACKET_WITH_ACKS_AND_PAYLOAD).unwrap();
        if let Packet::Control(control_packet) = packet {
            assert_eq!(control_packet.opcode, Opcode::ControlV1);
            assert_eq!(control_packet.key_id, 2);
            assert_eq!(control_packet.session_id, 0xf1f2f3f4f5f6f7f8);
            assert_eq!(control_packet.acks, [2, 3]);
            assert_eq!(control_packet.peer_session_id, Some(0x0102030405060708));
            assert_eq!(control_packet.packet_id, Some(3));
            assert_eq!(control_packet.payload, b"hello");
        } else {
            assert!(false);
        }
    }

    #[test]
    fn rejects_too_short_packets() {
        let too_short: &[u8] = &[1, 2, 3];
        assert!(Packet::parse(too_short).is_err());
    }

    #[test]
    fn rejects_bad_opcodes() {
        assert!(Packet::parse(BAD_OPCODE).is_err());
    }

    #[test]
    fn can_write_packets() {
        let mut buffer: [u8; 1024] = [0; 1024];
        for raw_packet in [
            VALID_PACKET_NO_ACKS,
            VALID_PACKET_WITH_ACK,
            VALID_PACKET_WITH_ACKS_AND_PAYLOAD,
        ] {
            let packet = Packet::parse(raw_packet).unwrap();
            let bytes_written = packet.to_buffer(buffer.as_mut_slice()).unwrap();
            assert_eq!(raw_packet, &buffer[..bytes_written]);
        }
    }
}
