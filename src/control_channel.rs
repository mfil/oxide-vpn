use rand::CryptoRng;
use std::cmp::min;
use std::error::Error;
use std::fmt;
use std::io;
use std::io::Read;
use std::net::UdpSocket;

use crate::packets::{ControlChannelPacket, Opcode, Packet};

#[derive(Debug)]
pub struct ControlChannelError {
    message: &'static str,
    cause: Option<Box<dyn Error>>,
}

impl fmt::Display for ControlChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(cause) = &self.cause {
            write!(
                formatter,
                "Control channel error: {}; cause: {}",
                self.message, cause
            )?;
        } else {
            write!(formatter, "Control channel error: {}", self.message)?;
        }
        Result::Ok(())
    }
}

impl Error for ControlChannelError {}

impl ControlChannelError {
    pub fn source(&self) -> Option<&dyn Error> {
        self.cause.as_ref().map(|boxed_error| &**boxed_error)
    }

    pub fn with_message(message: &'static str) -> Self {
        ControlChannelError {
            message,
            cause: None,
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
        println!("{:?}", packet_id);

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
        println!("{:?}", self.session_id);

        if opcode == Opcode::ControlV1 {
            println!("acks: {:?}, peer session id: {:?}", acks, peer_session_id);
        }

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
        let mut send_buffer: [u8; 2000] = [0; 2000];
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
        println!(
            "last seen {:?}",
            &self.last_seen_packet_ids[..self.num_last_seen_packet_ids]
        );

        if self.state == State::PendingReset && packet.opcode == Opcode::ControlHardResetServerV2 {
            self.state = State::Initialized;
        }

        Ok(Message {
            opcode: packet.opcode,
            payload: packet.payload,
        })
    }
}

impl io::Read for ControlChannel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut receive_buffer: [u8; 2000] = [0; 2000];

        loop {
            let length = self.socket.recv(&mut receive_buffer)?;
            if length == 0 {
                return Ok(0);
            }
            println!("read length {}", length);

            let packet = Packet::parse(&receive_buffer[..length]).unwrap();
            if let Packet::Control(p) = packet {
                let message = self.receive_packet(&p).unwrap();
                println!("received opcode {:?}", message.opcode);
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

impl io::Write for ControlChannel {
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
