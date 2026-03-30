use std::cmp::min;
use std::error::Error;
use std::fmt;
use std::io;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};

use rand::CryptoRng;

use crate::packets::{ControlChannelPacket, Opcode, OpcodeType, Packet, PacketError};

#[derive(Debug)]
pub struct QueuePacket {
    opcode: Opcode,
    payload: Vec<u8>,
}

#[derive(PartialEq, Eq, Debug)]
enum State {
    Uninitalized = 0,
    PendingReset = 1,
    Initialized = 2,
}

#[derive(Debug)]
pub enum PacketChannelError {
    Io(io::Error),
    MalformedPacket(PacketError),
    Other(&'static str),
}

impl fmt::Display for PacketChannelError {
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

impl From<io::Error> for PacketChannelError {
    fn from(e: io::Error) -> Self {
        PacketChannelError::Io(e)
    }
}

impl From<PacketError> for PacketChannelError {
    fn from(e: PacketError) -> Self {
        PacketChannelError::MalformedPacket(e)
    }
}

impl Error for PacketChannelError {}

impl PacketChannelError {
    pub fn with_message(message: &'static str) -> Self {
        PacketChannelError::Other(message)
    }

    pub fn would_block(&self) -> bool {
        if let Self::Io(e) = self {
            e.kind() == io::ErrorKind::WouldBlock
        } else {
            false
        }
    }
}

/// Channel to send and receive packets from our peer.
#[derive(Debug)]
pub struct PacketChannel {
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
    socket: UdpSocket,
}

impl PacketChannel {
    /// Create new control channel.
    pub fn new<T: CryptoRng>(
        rng: &mut T,
        socket: UdpSocket,
        receive_queue: Arc<Mutex<Vec<QueuePacket>>>,
        send_queue: Arc<Mutex<Vec<QueuePacket>>>,
    ) -> Self {
        Self {
            state: State::Uninitalized,
            next_packet_id: 0,
            session_id: rng.next_u64(),
            key_id: 0,
            peer_session_id: None,
            last_seen_packet_ids: [0; 8],
            num_last_seen_packet_ids: 0,
            num_unacked_packet_ids: 0,
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
            self.num_unacked_packet_ids = 0;
        }
    }

    fn make_packet<'b>(&mut self, opcode: Opcode, payload: &'b [u8]) -> Packet<'b> {
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

        match opcode.get_type() {
            OpcodeType::Control => Packet::Control(ControlChannelPacket {
                opcode,
                key_id: self.key_id,
                session_id: self.session_id,
                acks,
                peer_session_id,
                packet_id,
                payload,
            }),
            OpcodeType::Data => panic!("At the disco"),
        }
    }

    fn process_packet<'b>(&mut self, packet: &Packet<'b>) -> Option<QueuePacket> {
        self.peer_session_id = Some(packet.get_session_id());
        let opcode = packet.get_opcode();

        if let Some(packet_id) = packet.get_packet_id() {
            self.add_unacked_id(packet_id);
        }

        if self.state == State::PendingReset && opcode == Opcode::ControlHardResetServerV2 {
            self.state = State::Initialized;
        }

        if opcode != Opcode::ControlAckV1 {
            Some(QueuePacket {
                opcode,
                payload: packet.get_payload().to_vec(),
            })
        } else {
            None
        }
    }

    fn receive_packet(&mut self) -> Result<Option<QueuePacket>, PacketChannelError> {
        let mut receive_buffer: [u8; 3000] = [0; 3000];
        let length = self.socket.recv(&mut receive_buffer)?;
        let packet = Packet::parse(&receive_buffer[..length])?;
        Ok(self.process_packet(&packet))
    }

    pub fn send_packet(
        &mut self,
        opcode: Opcode,
        payload: &[u8],
    ) -> Result<(), PacketChannelError> {
        let packet = self.make_packet(opcode, payload);
        let mut send_buffer: [u8; 3000] = [0; 3000];
        let length = packet.to_buffer(&mut send_buffer)?;
        self.socket.send(&send_buffer[..length])?;
        Ok(())
    }
}
