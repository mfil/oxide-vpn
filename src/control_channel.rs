use rand::CryptoRng;
use std::cmp::min;
use std::convert::From;
use std::error::Error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::net::UdpSocket;

use crate::packets::{ControlChannelPacket, Opcode, Packet, PacketError};

#[derive(Debug)]
pub enum ControlChannelError {
    Io(io::Error),
    MalformedPacket(PacketError),
    Other(&'static str),
}

impl fmt::Display for ControlChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(formatter, "Control channel IO Error: {}", e)?,
            Self::MalformedPacket(e) => {
                write!(formatter, "Malformed packet in control channel: {}", e)?
            }
            Self::Other(message) => write!(formatter, "Control channel error: {}", message)?,
        }
        Result::Ok(())
    }
}

impl From<io::Error> for ControlChannelError {
    fn from(e: io::Error) -> Self {
        ControlChannelError::Io(e)
    }
}

impl From<PacketError> for ControlChannelError {
    fn from(e: PacketError) -> Self {
        ControlChannelError::MalformedPacket(e)
    }
}

impl Error for ControlChannelError {}

impl ControlChannelError {
    pub fn with_message(message: &'static str) -> Self {
        ControlChannelError::Other(message)
    }

    pub fn would_block(&self) -> bool {
        if let Self::Io(e) = self {
            e.kind() == io::ErrorKind::WouldBlock
        } else {
            false
        }
    }
}

/// Message content for external use.
pub struct Message<'a> {
    pub opcode: Opcode,
    pub payload: &'a [u8],
}

#[derive(PartialEq, Eq, Debug)]
enum State {
    Uninitalized = 0,
    PendingReset = 1,
    Initialized = 2,
}

/// OpenVPN Control Channel.
#[derive(Debug)]
pub struct ControlChannel {
    state: State,
    next_packet_id: u32,
    session_id: u64,
    key_id: u8,
    peer_session_id: Option<u64>,

    /// The most recent eight packet IDs that we have seen from the peer, from least to most recent.
    /// To avoid unnecessary resending, the WIP RFC of OpenVPN recommends to make maximal use of the
    /// acks field in control channel packets and continue re-acking some older packets if there is
    /// room.
    last_seen_packet_ids: [u32; 8],
    /// The number of packet IDs in the buffer.
    num_last_seen_packet_ids: usize,
    /// The number of packet IDs in `last_seen_packet_ids` that have not been acked at least once.
    /// The `ControlChannel` will ensure that this number will never be larger than 4.
    num_unacked_packet_ids: usize,
    pending_ack_packets: Vec<ControlChannelPacket<'static>>,
    socket: UdpSocket,
}

impl ControlChannel {
    /// Create new control channel.
    pub fn new<T: CryptoRng>(rng: &mut T, socket: UdpSocket) -> Self {
        ControlChannel {
            state: State::Uninitalized,
            next_packet_id: 0,
            session_id: rng.next_u64(),
            key_id: 0,
            peer_session_id: None,
            last_seen_packet_ids: [0; 8],
            num_last_seen_packet_ids: 0,
            num_unacked_packet_ids: 0,
            pending_ack_packets: Vec::new(),
            socket,
        }
    }

    fn add_unacked_id(&mut self, peer_packet_id: u32) {
        self.num_unacked_packet_ids += 1;
        if self.num_last_seen_packet_ids < 8 {
            self.last_seen_packet_ids[self.num_last_seen_packet_ids] = peer_packet_id;
            self.num_last_seen_packet_ids += 1;
        } else {
            // Shift the existing packet IDs in the buffer one to the left.
            let temp = self.last_seen_packet_ids.clone();
            self.last_seen_packet_ids[..7].copy_from_slice(&temp[1..]);
            // Add the new one on the right.
            self.last_seen_packet_ids[7] = peer_packet_id;
        }

        // If we have four unacked packets, queue up an ack packet.
        if self.num_unacked_packet_ids >= 4 {
            let ack_packet = self.make_packet(Opcode::ControlAckV1, &[]);
            self.pending_ack_packets.push(ack_packet);
            self.num_unacked_packet_ids = 0;
        }
    }

    fn make_packet<'a>(&mut self, opcode: Opcode, payload: &'a [u8]) -> ControlChannelPacket<'a> {
        let num_acks: usize;
        let mut packet_id = None;
        if opcode == Opcode::ControlAckV1 {
            num_acks = self.num_last_seen_packet_ids;
        } else {
            num_acks = min(4, self.num_last_seen_packet_ids);
            packet_id = Some(self.next_packet_id);
            self.next_packet_id += 1;
        }

        let acks = if self.peer_session_id.is_none() {
            Vec::<u32>::new()
        } else {
            self.last_seen_packet_ids[8 - num_acks..].to_vec()
        };
        println!("{:?}", acks);

        let peer_session_id = if num_acks > 0 {
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

    pub fn send_packet(&mut self, opcode: Opcode, payload: &[u8]) -> io::Result<usize> {
        let packet = self.make_packet(opcode, payload);
        let mut send_buffer: [u8; 3000] = [0; 3000];
        let length = packet.to_buffer(&mut send_buffer).unwrap();
        self.socket.send(&send_buffer[..length])
    }

    pub fn client_reset(&mut self) -> io::Result<()> {
        self.state = State::PendingReset;
        self.send_packet(Opcode::ControlHardResetClientV2, &[])?;
        while self.state != State::Initialized {
            let mut buffer: [u8; 2000] = [0; 2000];
            match self.read(&mut buffer) {
                Ok(_) => {}
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    fn receive_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<Message<'a>, ControlChannelError> {
        let length = self.socket.recv(buffer)?;
        let packet = Packet::parse(&buffer[..length])?;
        if let Packet::Control(p) = packet {
            self.process_packet(&p)
        } else {
            panic!("at the disco");
        }
    }

    fn process_packet<'a>(
        &mut self,
        packet: &ControlChannelPacket<'a>,
    ) -> Result<Message<'a>, ControlChannelError> {
        if let Some(peer_session_id) = self.peer_session_id {
            if peer_session_id != packet.session_id {
                return Err(ControlChannelError::with_message("Wrong peer session ID"));
            }
        } else {
            self.peer_session_id = Some(packet.session_id);
        }

        if let Some(packet_id) = packet.packet_id {
            self.add_unacked_id(packet_id);
        }

        if self.state == State::PendingReset && packet.opcode == Opcode::ControlHardResetServerV2 {
            self.state = State::Initialized;
        }

        Ok(Message {
            opcode: packet.opcode,
            payload: packet.payload,
        })
    }
}

struct TlsRecord<'a> {
    length: usize,
    record_data: &'a [u8],
}

impl<'a> TlsRecord<'a> {
    const HEADER_SIZE: usize = 5;
}

pub struct TlsRecordStream<'a> {
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    packet_channel: &'a mut ControlChannel,
}

impl<'a> TlsRecordStream<'a> {
    pub fn new(packet_channel: &'a mut ControlChannel) -> Self {
        TlsRecordStream {
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            packet_channel,
        }
    }
}

impl<'a> Read for TlsRecordStream<'a> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if self.read_buffer.len() > 0 {
            let num_bytes = min(target.len(), self.read_buffer.len());
            target[..num_bytes].copy_from_slice(&self.read_buffer[..num_bytes]);

            // Remove the bytes that we just copied from the read buffer.
            self.read_buffer.copy_within(num_bytes.., 0);
            let remaining_bytes = self.read_buffer.len() - num_bytes;
            self.read_buffer.truncate(remaining_bytes);
            Ok(num_bytes)
        } else {
            let mut receive_buffer: [u8; 3000] = [0; 3000];
            let message = match self.packet_channel.receive_packet(&mut receive_buffer) {
                Ok(message) => message,
                Err(ControlChannelError::Io(e)) => {
                    if (e.kind() == io::ErrorKind::WouldBlock) {
                        return Ok(0);
                    }
                    return Err(e);
                }
                _ => panic!("at the disco"),
            };
            if message.opcode == Opcode::ControlV1 {
                let num_bytes = min(message.payload.len(), target.len());
                target[..num_bytes].copy_from_slice(&message.payload[..num_bytes]);
                self.read_buffer = message.payload[num_bytes..].to_vec();
                Ok(num_bytes)
            } else {
                Ok(0)
            }
        }
    }
}

impl<'a> Write for TlsRecordStream<'a> {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        println!("SSL wants to write {} bytes", source.len());
        self.write_buffer.extend(source);
        let mut remaining_write_buffer: &mut [u8] = self.write_buffer.as_mut_slice();
        let mut tls_record: &mut [u8];
        let mut payload_bytes_sent: usize = 0;
        while remaining_write_buffer.len() > TlsRecord::HEADER_SIZE {
            let record_length =
                u16::from_be_bytes([remaining_write_buffer[3], remaining_write_buffer[4]]) as usize;
            if remaining_write_buffer.len() >= TlsRecord::HEADER_SIZE + record_length as usize {
                (tls_record, remaining_write_buffer) =
                    remaining_write_buffer.split_at_mut(TlsRecord::HEADER_SIZE + record_length);
                self.packet_channel
                    .send_packet(Opcode::ControlV1, tls_record)?;
                payload_bytes_sent += tls_record.len();
            } else {
                break;
            }
        }
        self.write_buffer.copy_within(payload_bytes_sent.., 0);
        self.write_buffer
            .truncate(self.write_buffer.len() - payload_bytes_sent);
        Ok(source.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.packet_channel
            .send_packet(Opcode::ControlV1, &self.write_buffer)
            .map(|_| ())
    }
}

impl Read for ControlChannel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut receive_buffer: [u8; 2000] = [0; 2000];

        loop {
            let length = self.socket.recv(&mut receive_buffer)?;
            if length == 0 {
                return Ok(0);
            }

            let packet = Packet::parse(&receive_buffer[..length]).unwrap();
            if let Packet::Control(p) = packet {
                let message = self.process_packet(&p).unwrap();
                if message.opcode == Opcode::ControlV1 {
                    buffer[0..message.payload.len()].copy_from_slice(message.payload);
                    return Ok(message.payload.len());
                }
            } else {
                panic!("at the disco");
            }
        }
    }
}

impl Write for ControlChannel {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        /*
        if data.len() >= 5 {
            if data[0] == 0x16 {
                println!("Have TLS record");
                let length = u16::from_be_bytes([data[3], data[4]]);
                println!("Record length {}", length);
                return self.send_packet(Opcode::ControlV1, &data[0..(length as usize) + 5]);
            }
        }
        */
        self.send_packet(Opcode::ControlV1, data)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
