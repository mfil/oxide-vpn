use rand::CryptoRng;
use std::cmp::min;
use std::convert::From;
use std::error::Error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::mem::swap;
use std::net::UdpSocket;

use super::control_channel_state::ControlChannelState;

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

/// Reader + Writer for use by the [`SslConnector`].
///
/// Each control channel packet needs to contain a single whole TLS record, so we chunk the data
/// from the [`SslConnector`] into TLS records. We assume that the data written to this object is
/// a stream of TLS records. We do not validate the TLS record headers, but simply take the length
/// from what should be the length field.
#[derive(Debug)]
struct TlsRecordStream {
    /// The payloads of the received packets, in one continuous stream.
    payloads_to_read: Vec<u8>,
    /// Data to send to the peer.
    written_tls_records: Vec<Vec<u8>>,
    partial_record: Vec<u8>,
}

impl TlsRecordStream {
    pub fn new() -> Self {
        Self {
            payloads_to_read: Vec::new(),
            written_tls_records: Vec::new(),
            partial_record: Vec::new(),
        }
    }

    pub fn get_written_records(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        swap(&mut out, &mut self.written_tls_records);
        out
    }

    pub fn insert_payload(&mut self, payload: &[u8]) {
        self.payloads_to_read.extend_from_slice(payload);
    }
}

impl Read for TlsRecordStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let amount_to_read = min(buffer.len(), self.payloads_to_read.len());
        if buffer.len() > 0 && amount_to_read == 0 {
            // This error stops the SslConnector but lets us resume a handshake later.
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        buffer[..amount_to_read].copy_from_slice(&self.payloads_to_read[..amount_to_read]);
        self.payloads_to_read.copy_within(amount_to_read.., 0);
        self.payloads_to_read
            .truncate(self.payloads_to_read.len() - amount_to_read);
        Ok(amount_to_read)
    }
}

/// Assuming that record points at a TLS record header, calculate the length, including the header.
fn get_tls_record_length(record: &[u8]) -> usize {
    let (header, _) = record.split_first_chunk::<5>().unwrap();
    let (_, length_bytes) = header.split_last_chunk::<2>().unwrap();
    u16::from_be_bytes(*length_bytes) as usize + 5
}

impl Write for TlsRecordStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut record: &[u8];
        let mut rest = buffer;

        if !self.partial_record.is_empty() {
            let missing_bytes =
                get_tls_record_length(&self.partial_record) - self.partial_record.len();
            if buffer.len() < missing_bytes {
                self.partial_record.extend_from_slice(buffer);
                return Ok(buffer.len());
            }

            let record_tail: &[u8];
            (record_tail, rest) = rest.split_at(missing_bytes);
            let mut new_record = Vec::with_capacity(self.partial_record.len() + missing_bytes);
            new_record.extend_from_slice(&self.partial_record);
            new_record.extend_from_slice(record_tail);
            self.written_tls_records.push(new_record);
            self.partial_record.clear();
        }

        // We keep going until there are less than five bytes left. A TLS record header is five
        // bytes, so we can't do anything with less.
        while rest.len() >= 5 {
            let record_len = get_tls_record_length(rest);
            if record_len > rest.len() {
                self.partial_record.extend_from_slice(rest);
                return Ok(buffer.len());
            }

            (record, rest) = rest.split_at(record_len);
            self.written_tls_records.push(record.to_vec());
        }
        Ok(buffer.len() - rest.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// OpenVPN Control Channel.
#[derive(Debug)]
pub struct ControlChannel {
    state: ControlChannelState,
    record_stream: TlsRecordStream,
}

impl ControlChannel {
    /// Create new control channel.
    pub fn new<T: CryptoRng>(rng: &mut T) -> Self {
        ControlChannel {
            state: ControlChannelState::new(rng.next_u64()),
            record_stream: TlsRecordStream::new(),
        }
    }

    pub fn receive_packet(&mut self, packet: ControlChannelPacket) {
        self.state.process_packet(&packet);
        match packet.opcode {
            Opcode::ControlV1 => self.record_stream.insert_payload(&packet.payload),
            Opcode::ControlAckV1 => (), // Nothing to do.
            _ => panic!("foo"),
        }
    }
}

/*
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
*/

#[cfg(test)]
mod record_stream_test {
    use super::TlsRecordStream;
    use std::io::{ErrorKind, Read, Write};

    // Fake "TLS records"; we only care about the length field.
    const RECORD1: &[u8] = b"\x00\x00\x00\x00\x0dHello, World!";
    const RECORD2: &[u8] = b"\x00\x00\x00\x00\x29Tut das Not dass das hier so rumoxidiert?";
    const RECORD1_PART1: &[u8] = b"\x00\x00\x00\x00\x0dHe";
    const RECORD1_PART2: &[u8] = b"llo, ";
    const RECORD1_PART3: &[u8] = b"World!";

    fn checked_write(record_stream: &mut TlsRecordStream, record: &[u8]) {
        assert_eq!(record_stream.write(record).unwrap(), record.len());
    }

    fn check_written_records(record_stream: &mut TlsRecordStream, expected: &[&[u8]]) {
        let actual = record_stream.get_written_records();
        assert_eq!(actual.len(), expected.len());
        for (record, expected_record) in actual.iter().zip(expected.iter()) {
            assert_eq!(record, *expected_record);
        }
    }

    #[test]
    fn tls_record_stream_handles_individual_records() {
        let mut record_stream = TlsRecordStream::new();
        checked_write(&mut record_stream, RECORD1);
        checked_write(&mut record_stream, RECORD2);
        check_written_records(&mut record_stream, &[RECORD1, RECORD2]);
    }

    #[test]
    fn tls_record_stream_handles_combined_records() {
        let mut record_stream = TlsRecordStream::new();
        let mut combined_records = Vec::new();
        combined_records.extend_from_slice(RECORD1);
        combined_records.extend_from_slice(RECORD2);
        checked_write(&mut record_stream, &combined_records);
        check_written_records(&mut record_stream, &[RECORD1, RECORD2]);
    }

    #[test]
    fn tls_record_stream_handles_partial_records() {
        let mut record_stream = TlsRecordStream::new();
        checked_write(&mut record_stream, RECORD1_PART1);
        check_written_records(&mut record_stream, &[]);

        checked_write(&mut record_stream, RECORD1_PART2);
        check_written_records(&mut record_stream, &[]);

        checked_write(&mut record_stream, RECORD1_PART3);
        check_written_records(&mut record_stream, &[RECORD1]);
    }

    #[test]
    fn tls_record_stream_handles_mixed_partial_and_full_records() {
        let mut record_stream = TlsRecordStream::new();
        checked_write(&mut record_stream, RECORD1_PART1);

        let mut combined_records = Vec::new();
        combined_records.extend_from_slice(RECORD1_PART2);
        combined_records.extend_from_slice(RECORD1_PART3);
        combined_records.extend_from_slice(RECORD2);
        combined_records.extend_from_slice(RECORD1_PART1);

        checked_write(&mut record_stream, &combined_records);
        checked_write(&mut record_stream, RECORD1_PART2);
        checked_write(&mut record_stream, RECORD1_PART3);
        check_written_records(&mut record_stream, &[RECORD1, RECORD2, RECORD1]);
    }

    #[test]
    fn tls_record_stream_does_not_write_partial_header() {
        let mut record_stream = TlsRecordStream::new();
        let mut combined_records = Vec::new();
        combined_records.extend_from_slice(RECORD1);
        combined_records.extend_from_slice(b"\x00\x00\x00\x23");
        assert_eq!(
            record_stream.write(&combined_records).unwrap(),
            RECORD1.len()
        );
        check_written_records(&mut record_stream, &[RECORD1]);
    }

    #[test]
    fn tls_record_stream_can_read() {
        let mut record_stream = TlsRecordStream::new();
        let mut read_buffer = [0; 5];
        record_stream.insert_payload(RECORD1);
        assert_eq!(record_stream.read(&mut read_buffer).unwrap(), 5);
        assert_eq!(read_buffer, RECORD1[..5]);
        assert_eq!(record_stream.read(&mut read_buffer).unwrap(), 5);
        assert_eq!(read_buffer, RECORD1[5..10]);
        assert_eq!(record_stream.read(&mut read_buffer).unwrap(), 5);
        assert_eq!(read_buffer, RECORD1[10..15]);
        assert_eq!(record_stream.read(&mut read_buffer).unwrap(), 3);
        assert_eq!(read_buffer[..3], RECORD1[15..]);
    }

    #[test]
    fn tls_record_stream_says_would_block_if_empty() {
        let mut record_stream = TlsRecordStream::new();
        let mut read_buf = [0; 23];
        assert!(
            record_stream
                .read(&mut read_buf)
                .is_err_and(|e| e.kind() == ErrorKind::WouldBlock)
        )
    }
}
