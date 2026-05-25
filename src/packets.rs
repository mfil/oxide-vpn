//! This module defines the different packet types used in OpenVPN and contains functions for parsing them.
use crate::error::Error;
use std::io::Read;
use std::net::UdpSocket;

const CONTROL_CHANNEL_MAX_HEADER_SIZE: usize = 50;
const DATA_CHANNEL_HEADER_SIZE: usize = 12;
const DATA_CHANNEL_TAG_SIZE: usize = 16;

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
    /// Data channel packet with user id.
    DataV2 = 9,
}

impl TryFrom<u8> for Opcode {
    type Error = Error;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            4 => Ok(Opcode::ControlV1),
            5 => Ok(Opcode::ControlAckV1),
            7 => Ok(Opcode::ControlHardResetClientV2),
            8 => Ok(Opcode::ControlHardResetServerV2),
            9 => Ok(Opcode::DataV2),
            _ => Err(Error::packet_error("Invalid opcode")),
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
            Opcode::DataV2 => OpcodeType::Data,
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
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let (first_byte, rest) = data
            .split_first()
            .ok_or_else(|| Error::packet_error("Control channel packet too short."))?;
        let opcode = Opcode::try_from(first_byte >> 3)?;
        let key_id = first_byte & 0x07;

        let (session_id_bytes, rest) = rest
            .split_first_chunk::<8>()
            .ok_or_else(|| Error::packet_error("Control channel packet too short."))?;
        let session_id = u64::from_be_bytes(*session_id_bytes);
        let (num_acks_byte, rest) = rest
            .split_first()
            .ok_or_else(|| Error::packet_error("Control channel packet too short."))?;
        let num_acks = *num_acks_byte as usize;
        let (acks_portion, rest) = rest
            .split_at_checked(num_acks * size_of::<u32>())
            .ok_or_else(|| Error::packet_error("Control channel packet too short."))?;
        let (ack_chunks, _) = acks_portion.as_chunks::<4>();

        let mut acks = Vec::<u32>::with_capacity(num_acks);
        for ack_id in ack_chunks {
            acks.push(u32::from_be_bytes(*ack_id));
        }

        // We have a peer session ID if and only if we have any acks.
        let (peer_session_id, rest) = if num_acks > 0 {
            let (peer_session_id_bytes, rest) = rest
                .split_first_chunk::<8>()
                .ok_or_else(|| Error::packet_error("Control channel packet too short."))?;
            let peer_session_id = u64::from_be_bytes(*peer_session_id_bytes);
            (Some(peer_session_id), rest)
        } else {
            (None, rest)
        };

        // We have a packet ID unless it is an ack packet.
        let (packet_id, payload) = if !opcode.is_ack() {
            let (packet_id_bytes, rest) = rest
                .split_first_chunk::<4>()
                .ok_or_else(|| Error::packet_error("Control channel packet too short."))?;
            let packet_id = u32::from_be_bytes(*packet_id_bytes);
            (Some(packet_id), rest)
        } else {
            (None, rest)
        };

        Ok(Self {
            opcode,
            key_id,
            session_id,
            acks,
            peer_session_id,
            packet_id,
            payload,
        })
    }
}

fn write_byte_and_advance(buf: &mut [u8], byte: u8) -> &mut [u8] {
    let (first, rest) = buf.split_first_mut().unwrap();
    *first = byte;
    rest
}

fn write_u32_and_advance(buf: &mut [u8], n: u32) -> &mut [u8] {
    let (first_chunk, rest) = buf.split_first_chunk_mut::<4>().unwrap();
    *first_chunk = n.to_be_bytes();
    rest
}

fn write_u64_and_advance(buf: &mut [u8], n: u64) -> &mut [u8] {
    let (first_chunk, rest) = buf.split_first_chunk_mut::<8>().unwrap();
    *first_chunk = n.to_be_bytes();
    rest
}

/// Buffer for writing a control channel packet. The packet may be incomplete.
///
/// When writing payload data to the buffer, enough headroom is left to prepend the payload data
/// with a control channel packet header.
#[derive(Debug)]
pub struct ControlChannelPacketBuffer {
    header_start: usize,
    buffer: Vec<u8>,
}

impl ControlChannelPacketBuffer {
    /// Allocates memory for a control channel packet with a payload of length `capacity`.
    /// Pre-fills the headroom with 0.
    pub fn with_payload_capacity(capacity: usize) -> Self {
        let mut buffer = Vec::with_capacity(CONTROL_CHANNEL_MAX_HEADER_SIZE + capacity);
        buffer.extend_from_slice(&[0; CONTROL_CHANNEL_MAX_HEADER_SIZE]);
        ControlChannelPacketBuffer {
            header_start: CONTROL_CHANNEL_MAX_HEADER_SIZE,
            buffer,
        }
    }

    pub fn extend_payload_from_slice(&mut self, slice: &[u8]) {
        self.buffer.extend_from_slice(slice);
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.buffer[CONTROL_CHANNEL_MAX_HEADER_SIZE..]
    }

    pub fn payload_len(&self) -> usize {
        self.buffer.len() - CONTROL_CHANNEL_MAX_HEADER_SIZE
    }

    /// Write a control channel packet header before the payload.
    ///
    /// The underlying buffer has enough headroom so that this can be done for all valid headers.
    /// This function may panic if there are too many acks. In regular control channel packets,
    /// four acks are allowed and in dedicated ACK packets eight.
    pub fn write_header(
        &mut self,
        opcode: Opcode,
        key_id: u8,
        session_id: u64,
        acks: &[u32],
        peer_session_id: Option<u64>,
        packet_id: Option<u32>,
    ) {
        let mut header_size = 1 + 8 + 1 + acks.len() * 4;
        if peer_session_id.is_some() {
            header_size += 8;
        }
        if packet_id.is_some() {
            header_size += 4;
        }
        self.header_start = CONTROL_CHANNEL_MAX_HEADER_SIZE - header_size;
        let mut header = &mut self.buffer[self.header_start..CONTROL_CHANNEL_MAX_HEADER_SIZE];
        let first_byte = ((opcode as u8) << 3) | key_id;
        header = write_byte_and_advance(header, first_byte);
        header = write_u64_and_advance(header, session_id);
        header = write_byte_and_advance(header, acks.len() as u8);
        for ack in acks {
            header = write_u32_and_advance(header, *ack);
        }
        if let Some(id) = peer_session_id {
            header = write_u64_and_advance(header, id);
        }
        if let Some(id) = packet_id {
            write_u32_and_advance(header, id);
        }
    }

    /// Returns a slice with all header and payload data that has been written.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[self.header_start..]
    }
}

#[derive(Debug)]
pub struct DataChannelPacket<'a> {
    packet_data: &'a mut [u8],
}

impl<'a> DataChannelPacket<'a> {
    const PEER_ID_OFFSET: usize = 1;

    pub fn get_opcode(&self) -> Result<Opcode, Error> {
        Opcode::try_from(self.packet_data[0] >> 3)
    }

    pub fn get_key_id(&self) -> u8 {
        self.packet_data[0] & 0x07
    }

    pub fn get_peer_id(&self) -> &[u8; 3] {
        self.packet_data[Self::PEER_ID_OFFSET..]
            .first_chunk::<3>()
            .unwrap()
    }

    const PACKET_ID_OFFSET: usize = Self::PEER_ID_OFFSET + 3;
    pub fn get_epoch(&self) -> u16 {
        u16::from_be_bytes([
            self.packet_data[Self::PACKET_ID_OFFSET],
            self.packet_data[Self::PACKET_ID_OFFSET + 1],
        ])
    }

    pub fn get_packet_id(&self) -> &[u8; 8] {
        self.packet_data[Self::PACKET_ID_OFFSET..]
            .first_chunk::<8>()
            .unwrap()
    }

    const PAYLOAD_OFFSET: usize = Self::PACKET_ID_OFFSET + 8;
    pub fn get_payload(&self) -> &[u8] {
        &self.packet_data[Self::PAYLOAD_OFFSET..(self.packet_data.len() - DATA_CHANNEL_TAG_SIZE)]
    }

    pub fn get_payload_mut(&mut self) -> &mut [u8] {
        let payload_end = self.packet_data.len() - DATA_CHANNEL_TAG_SIZE;
        &mut self.packet_data[Self::PAYLOAD_OFFSET..payload_end]
    }

    /// Consumes the packet and returns a buffer with only the payload.
    pub fn take_payload(self) -> &'a mut [u8] {
        let payload_end = self.packet_data.len() - DATA_CHANNEL_TAG_SIZE;
        &mut self.packet_data[DATA_CHANNEL_HEADER_SIZE..payload_end]
    }

    pub fn get_auth_tag(&self) -> &[u8; 16] {
        self.packet_data.last_chunk::<16>().unwrap()
    }

    /// Get the unencrypted but authenticated portion of the packet. That is, the "AD" in "AEAD".
    pub fn get_additional_authenticated_data(&self) -> &[u8; 12] {
        &self.packet_data.first_chunk::<12>().unwrap()
    }

    #[cfg(test)]
    pub fn to_vec(&self) -> Vec<u8> {
        self.packet_data.to_vec()
    }

    #[cfg(test)]
    pub fn from_raw_bytes(packet_data: &'a mut [u8]) -> Self {
        Self { packet_data }
    }
}

/// OpenVPN UDP packet.
#[derive(Debug)]
pub enum Packet<'a> {
    Control(ControlChannelPacket<'a>),
    Data(DataChannelPacket<'a>),
}

impl<'a> Packet<'a> {
    pub fn parse(data: &'a mut [u8]) -> Result<Packet<'a>, Error> {
        let first_byte = data.get(0).ok_or(Error::packet_error("Empty packet"))?;
        let opcode = Opcode::try_from(first_byte >> 3)?;
        match opcode.get_type() {
            OpcodeType::Control => Ok(Self::Control(ControlChannelPacket::parse(data)?)),
            OpcodeType::Data => Self::parse_data_packet(data),
        }
    }

    fn parse_data_packet(data: &'a mut [u8]) -> Result<Packet<'a>, Error> {
        if data.len() < 28 {
            return Err(Error::packet_error("Packet too short."));
        }
        Ok(Packet::Data(DataChannelPacket { packet_data: data }))
    }

    pub fn get_opcode(&self) -> Opcode {
        match self {
            Self::Control(p) => p.opcode,
            Self::Data(_) => Opcode::DataV2,
        }
    }
}

/// Buffer for reading/writing OpenVPN packets.
pub struct PacketBuffer {
    /// Underlying storage.
    buffer: Vec<u8>,
}

impl PacketBuffer {
    pub fn new(size: usize) -> Self {
        PacketBuffer {
            buffer: vec![0; size],
        }
    }

    pub fn recv_packet<'a>(&'a mut self, socket: &UdpSocket) -> Result<Packet<'a>, Error> {
        let length = socket.recv(&mut self.buffer)?;
        Packet::parse(&mut self.buffer[..length])
    }

    /// Read a plaintext data channel payload from `reader` and place it in the buffer so that there
    /// is enough room before it to write a header and enough after to write the tag.
    pub fn read_data_channel_plaintext<'a, R: Read>(
        &'a mut self,
        reader: &mut R,
    ) -> Result<DataChannelPacketBuffer<'a>, Error> {
        let start = DATA_CHANNEL_HEADER_SIZE;
        let end = self.buffer.len() - DATA_CHANNEL_TAG_SIZE;
        let length = reader.read(&mut self.buffer[start..end])?;

        Ok(DataChannelPacketBuffer {
            buffer: &mut self.buffer[0..start + length + DATA_CHANNEL_TAG_SIZE],
        })
    }
}

/// Buffer for writing a data channel packet. May or may not contain a valid data channel packet.
pub struct DataChannelPacketBuffer<'a> {
    buffer: &'a mut [u8],
}

impl<'a> DataChannelPacketBuffer<'a> {
    #[cfg(test)]
    pub fn from_payload(buffer: &'a mut [u8], payload: &'static [u8]) -> Self {
        buffer[DATA_CHANNEL_HEADER_SIZE..DATA_CHANNEL_HEADER_SIZE + payload.len()]
            .copy_from_slice(payload);
        Self {
            buffer: &mut buffer[..DATA_CHANNEL_HEADER_SIZE + payload.len() + DATA_CHANNEL_TAG_SIZE],
        }
    }

    pub fn get_header(&self) -> &[u8] {
        &self.buffer[..DATA_CHANNEL_HEADER_SIZE]
    }

    pub fn get_payload_mut(&mut self) -> &mut [u8] {
        let start = DATA_CHANNEL_HEADER_SIZE;
        let end = self.buffer.len() - DATA_CHANNEL_TAG_SIZE;
        &mut self.buffer[start..end]
    }

    pub fn get_tag_mut(&mut self) -> &mut [u8] {
        let start = self.buffer.len() - DATA_CHANNEL_TAG_SIZE;
        &mut self.buffer[start..]
    }

    pub fn write_header(&mut self, key_id: u8, peer_id: [u8; 3], packet_id: [u8; 8]) {
        let first_byte = (Opcode::DataV2 as u8) << 3 | key_id;
        self.buffer[0] = first_byte;
        let (peer_id_bytes, rest) = self.buffer[1..].split_first_chunk_mut::<3>().unwrap();
        *peer_id_bytes = peer_id;
        let (packet_counter_bytes, _) = rest.split_first_chunk_mut::<8>().unwrap();
        *packet_counter_bytes = packet_id;
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

#[cfg(test)]
mod test {
    use crate::packets::PacketBuffer;
    use std::io::Read;

    use super::{Opcode, Packet};

    fn valid_packet_no_acks() -> Vec<u8> {
        vec![
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
        ]
    }

    fn valid_packet_with_ack() -> Vec<u8> {
        vec![
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
        ]
    }

    fn valid_packet_with_acks_and_payload() -> Vec<u8> {
        vec![
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
        ]
    }

    fn bad_opcode() -> Vec<u8> {
        vec![
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
        ]
    }

    #[test]
    fn can_parse_valid_control_packets() {
        let mut packet_data = valid_packet_no_acks();
        let packet = Packet::parse(&mut packet_data).unwrap();
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

        let mut packet_data = valid_packet_with_ack();
        let packet = Packet::parse(&mut packet_data).unwrap();
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

        let mut packet_data = valid_packet_with_acks_and_payload();
        let packet = Packet::parse(&mut packet_data).unwrap();
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
        let too_short: &mut [u8] = &mut [1, 2, 3];
        assert!(Packet::parse(too_short).is_err());
    }

    #[test]
    fn rejects_bad_opcodes() {
        assert!(Packet::parse(&mut bad_opcode()).is_err());
    }

    struct TestReader {
        data: [u8; 1000],
    }

    impl Read for TestReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let length = std::cmp::min(buffer.len(), self.data.len());
            buffer[..length].copy_from_slice(&self.data[..length]);
            Ok(length)
        }
    }

    #[test]
    fn packet_buffer_reads_data_channel_plaintext() {
        let mut long_message_reader = TestReader { data: [23u8; 1000] };
        let mut packet_buffer = PacketBuffer::new(3000);
        let mut data_channel_buffer = packet_buffer
            .read_data_channel_plaintext(&mut long_message_reader)
            .unwrap();
        assert_eq!(data_channel_buffer.get_payload_mut(), &[23u8; 1000]);
    }
}
