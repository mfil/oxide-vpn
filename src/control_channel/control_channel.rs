use std::cmp::min;
use std::convert::From;
use std::error::Error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::mem::swap;
use std::sync::mpsc::{Receiver, Sender};

use rand::CryptoRng;

use openssl;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, SslAcceptor, SslAcceptorBuilder, SslConnector,
    SslMethod, SslStream, SslVerifyMode, SslVersion,
};
use openssl::x509::X509;

use super::control_channel_state::ControlChannelState;

use crate::packets::{ControlChannelPacket, Opcode, PacketError};

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

    pub fn insert_payload(&mut self, payload: Vec<u8>) {
        if self.payloads_to_read.is_empty() {
            self.payloads_to_read = payload;
        } else {
            self.payloads_to_read.extend_from_slice(&payload);
        }
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

#[derive(Debug)]
enum TlsSession {
    Uninitialized,
    Handshake(MidHandshakeSslStream<TlsRecordStream>),
    Connected(SslStream<TlsRecordStream>),
}

impl TlsSession {
    pub fn is_uninitialized(&self) -> bool {
        if let Self::Uninitialized = self {
            true
        } else {
            false
        }
    }

    pub fn is_handshake(&self) -> bool {
        if let Self::Handshake(_) = self {
            true
        } else {
            false
        }
    }

    pub fn is_connected(&self) -> bool {
        if let Self::Connected(_) = self {
            true
        } else {
            false
        }
    }

    pub fn get_tls_record_stream(&mut self) -> Option<&mut TlsRecordStream> {
        match self {
            Self::Uninitialized => None,
            Self::Handshake(stream) => Some(stream.get_mut()),
            Self::Connected(stream) => Some(stream.get_mut()),
        }
    }

    pub fn get_stream(&mut self) -> Option<&mut SslStream<TlsRecordStream>> {
        if let Self::Connected(ssl_stream) = self {
            Some(ssl_stream)
        } else {
            None
        }
    }

    fn take(&mut self) -> Self {
        let mut out = Self::Uninitialized;
        swap(&mut out, self);
        out
    }

    pub fn insert_payload(
        &mut self,
        payload: Vec<u8>,
    ) -> Result<(), HandshakeError<TlsRecordStream>> {
        let session = self.take();

        if let TlsSession::Handshake(mut stream) = session {
            stream.get_mut().insert_payload(payload);
            match stream.handshake() {
                Ok(stream) => {
                    *self = TlsSession::Connected(stream);
                    println!("Handshake done");
                }
                Err(HandshakeError::WouldBlock(stream)) => *self = TlsSession::Handshake(stream),
                Err(e) => return Err(e),
            };
        } else if let TlsSession::Connected(mut stream) = session {
            stream.get_mut().insert_payload(payload);
            *self = TlsSession::Connected(stream);
        }
        Ok(())
    }
}

/// OpenVPN Control Channel.
#[derive(Debug)]
pub struct ControlChannel {
    state: ControlChannelState,
    is_server: bool,
    tls_session: TlsSession,
    ca: X509,
    certificate: X509,
    private_key: PKey<Private>,
    receiver: Receiver<ControlChannelPacket>,
    sender: Sender<ControlChannelPacket>,
}

impl ControlChannel {
    /// Create new control channel.
    pub fn new<R: CryptoRng>(
        rng: &mut R,
        is_server: bool,
        ca: X509,
        certificate: X509,
        private_key: PKey<Private>,
        receiver: Receiver<ControlChannelPacket>,
        sender: Sender<ControlChannelPacket>,
    ) -> Self {
        ControlChannel {
            state: ControlChannelState::new(rng.next_u64()),
            is_server,
            tls_session: TlsSession::Uninitialized,
            ca,
            certificate,
            private_key,
            receiver,
            sender,
        }
    }

    fn is_connected(&self) -> bool {
        self.tls_session.is_connected()
    }

    fn begin_tls_handshake_client(&mut self) -> Result<(), HandshakeError<TlsRecordStream>> {
        // TODO: Do actual cert verification.
        let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
        connector_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        connector_builder.set_verify(SslVerifyMode::NONE);
        connector_builder.set_certificate(&self.certificate);
        connector_builder.set_private_key(&self.private_key);
        let connector = connector_builder.build();
        let record_stream = TlsRecordStream::new();

        match connector.connect("Control Channel", record_stream) {
            Ok(stream) => self.tls_session = TlsSession::Connected(stream),
            Err(HandshakeError::WouldBlock(stream)) => {
                self.tls_session = TlsSession::Handshake(stream)
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    fn begin_tls_handshake_server(&mut self) -> Result<(), HandshakeError<TlsRecordStream>> {
        // TODO: Do actual cert verification.
        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        acceptor_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        acceptor_builder.set_verify(SslVerifyMode::NONE);
        acceptor_builder.set_certificate(&self.certificate);
        acceptor_builder.set_private_key(&self.private_key);
        let acceptor = acceptor_builder.build();
        let record_stream = TlsRecordStream::new();

        match acceptor.accept(record_stream) {
            Ok(stream) => self.tls_session = TlsSession::Connected(stream),
            Err(HandshakeError::WouldBlock(stream)) => {
                self.tls_session = TlsSession::Handshake(stream)
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// (Re-)initialize the control channel.
    pub fn reset(&mut self) {
        if !self.is_server {
            let packet = self
                .state
                .make_packet(Opcode::ControlHardResetClientV2, Vec::new());
            self.sender.send(packet).unwrap();
            self.tls_session = TlsSession::Uninitialized;
        }
    }

    pub fn receive_packets(&mut self) {
        while let Ok(packet) = self.receiver.try_recv() {
            // TODO: Need to handle out of order packets.
            self.state.process_packet(&packet);

            // Insert an ACK packet if the next regular packet can't hold all the acks that are pending.
            if self.state.unacked_packets() > 4 {
                let ack_packet = self.state.make_ack_packet();
                self.sender.send(ack_packet);
            }

            if self.is_server && packet.opcode == Opcode::ControlHardResetClientV2 {
                let packet = self
                    .state
                    .make_packet(Opcode::ControlHardResetServerV2, Vec::new());
                self.sender.send(packet).unwrap();
                // TODO: Normal OpenVPN waits for the client to send the first ControlV1 packet
                // before establishing the session, to make DOS attacks harder. In the unlikely case
                // that anyone runs this for real, this should be fixed here.
                self.begin_tls_handshake_server().unwrap();
            } else if !self.is_server && packet.opcode == Opcode::ControlHardResetServerV2 {
                self.begin_tls_handshake_client().unwrap();
            } else if packet.opcode == Opcode::ControlV1 {
                self.tls_session.insert_payload(packet.payload).unwrap();
            }
        }
    }

    pub fn send_packets(&mut self) {
        if let Some(tls_record_stream) = self.tls_session.get_tls_record_stream() {
            for payload in tls_record_stream.get_written_records() {
                let packet = self.state.make_packet(Opcode::ControlV1, payload);
                self.sender.send(packet).unwrap();
            }
        }
    }
}

impl Read for ControlChannel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.send_packets();
        self.receive_packets();
        if let Some(stream) = self.tls_session.get_stream() {
            return stream.read(buffer);
        }

        // Only the client can initialize a session.
        if self.tls_session.is_uninitialized() {
            if self.is_server {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.reset();
        }

        if let Some(stream) = self.tls_session.get_stream() {
            stream.read(buffer)
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }
}

impl Write for ControlChannel {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.send_packets();
        self.receive_packets();
        if let Some(stream) = self.tls_session.get_stream() {
            let bytes_written = stream.write(buffer)?;
            self.send_packets();
            return Ok(bytes_written);
        }

        // Only the client can initialize a session.
        if self.tls_session.is_uninitialized() {
            if self.is_server {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.reset();
            self.send_packets();
        }

        if let Some(stream) = self.tls_session.get_stream() {
            stream.write(buffer)
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
        record_stream.insert_payload(RECORD1.to_vec());
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

#[cfg(test)]
mod control_channel_test {
    use super::{ControlChannel, TlsSession};
    use crate::packets::ControlChannelPacket;
    use crate::packets::Opcode;
    use openssl;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::X509;
    use rand::rng;
    use std::io::{Read, Write};
    use std::sync::mpsc::channel;

    const CA_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIC/jCCAoWgAwIBAgIJAOGrHm6V0krZMAoGCCqGSM49BAMCMHcxCzAJBgNVBAYT
Ak5MMQswCQYDVQQIEwJaSDEOMAwGA1UEBxMFRGVsZnQxEzARBgNVBAoTClBraVRl
c3RlcnMxEzARBgNVBAMTClBraVRlc3RlcnMxITAfBgkqhkiG9w0BCQEWEm9wZW52
cG5AZm94LWl0LmNvbTAeFw0xMzExMTMxNDM4MzRaFw0yMzExMTExNDM4MzRaMHcx
CzAJBgNVBAYTAk5MMQswCQYDVQQIEwJaSDEOMAwGA1UEBxMFRGVsZnQxEzARBgNV
BAoTClBraVRlc3RlcnMxEzARBgNVBAMTClBraVRlc3RlcnMxITAfBgkqhkiG9w0B
CQEWEm9wZW52cG5AZm94LWl0LmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABE9f
umyRTnsT5E+bQMmUMjaG40g5Ccxvy1rn6+jOiQGh0tUwpttojodM7M6WS3M2OrvZ
Rr1eXewnWcLzkNbeQX2cxPnfiE3wQl+3PgnZa+QP55bqxEkpauP7CPu87+saXaOB
3DCB2TAdBgNVHQ4EFgQUtCIuf0c+TM7ITEbDMC6lK7sbWukwgakGA1UdIwSBoTCB
noAUtCIuf0c+TM7ITEbDMC6lK7sbWumhe6R5MHcxCzAJBgNVBAYTAk5MMQswCQYD
VQQIEwJaSDEOMAwGA1UEBxMFRGVsZnQxEzARBgNVBAoTClBraVRlc3RlcnMxEzAR
BgNVBAMTClBraVRlc3RlcnMxITAfBgkqhkiG9w0BCQEWEm9wZW52cG5AZm94LWl0
LmNvbYIJAOGrHm6V0krZMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDZwAwZAIw
KBfaKAYWsEsIX3NsSgBJ7wXXI4eQy+mgQlqFHFQidr2uFwDY+NQe/Y5/x8dJfaWY
AjA2v5jaw5ZopX8i0nSVTUWUzduBDsIOec8tK1bCXpVIBt+FM7IHUWck4OyXq+uj
Rgg=
-----END CERTIFICATE-----";

    const SERVER_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIDYTCCAuigAwIBAgIBADAKBggqhkjOPQQDAjB3MQswCQYDVQQGEwJOTDELMAkG
A1UECBMCWkgxDjAMBgNVBAcTBURlbGZ0MRMwEQYDVQQKEwpQa2lUZXN0ZXJzMRMw
EQYDVQQDEwpQa2lUZXN0ZXJzMSEwHwYJKoZIhvcNAQkBFhJvcGVudnBuQGZveC1p
dC5jb20wHhcNMTMxMTEzMTQzOTE4WhcNMjMxMTExMTQzOTE4WjB4MQswCQYDVQQG
EwJOTDELMAkGA1UECBMCWkgxDjAMBgNVBAcTBURlbGZ0MRMwEQYDVQQKEwpQa2lU
ZXN0ZXJzMRQwEgYDVQQDFAtyb290X3NlcnZlcjEhMB8GCSqGSIb3DQEJARYSb3Bl
bnZwbkBmb3gtaXQuY29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEkRPda7TjtdQ4
YqPrVQgqua2EnkwLBUoMHtQ1vrkX4blPGfbLHHMpz2CqYDDitapGs9XA5pHT616q
drmaCdV9d/cYbUlJLXJy1WX1r2+8bf1DYSqFkSGYY1vaLRFXhMeGo4IBRTCCAUEw
CQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwNAYJYIZIAYb4QgENBCcWJUVh
c3ktUlNBIEdlbmVyYXRlZCBTZXJ2ZXIgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFIZ9
0SO5BV/Jmy/S7oXDuB9CEE2qMIGpBgNVHSMEgaEwgZ6AFLQiLn9HPkzOyExGwzAu
pSu7G1rpoXukeTB3MQswCQYDVQQGEwJOTDELMAkGA1UECBMCWkgxDjAMBgNVBAcT
BURlbGZ0MRMwEQYDVQQKEwpQa2lUZXN0ZXJzMRMwEQYDVQQDEwpQa2lUZXN0ZXJz
MSEwHwYJKoZIhvcNAQkBFhJvcGVudnBuQGZveC1pdC5jb22CCQDhqx5uldJK2TAT
BgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAwCgYIKoZIzj0EAwIDZwAw
ZAIwOIuz2wrjE5RcroAH/WtJgAzy/qIyo5tJbW+fCzNB+wFniWwKVhJcF15de1Ha
cyN7AjBkmxmSDp6liLYwWpuX+FxqUi9iP4XdtdvbhXhN9X6bREfO5ET1nhoqqRTX
8KrRdVA=
-----END CERTIFICATE-----";

    const SERVER_KEY: &'static [u8] = b"-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDC0rD0sJ+XdRc0+bzZPgMZcngnJ7gXMy1jrUOohBlUm7zPmSnmUi+zf
NwxqjX+Uyw2gBwYFK4EEACKhZANiAASRE91rtOO11Dhio+tVCCq5rYSeTAsFSgwe
1DW+uRfhuU8Z9ssccynPYKpgMOK1qkaz1cDmkdPrXqp2uZoJ1X139xhtSUktcnLV
ZfWvb7xt/UNhKoWRIZhjW9otEVeEx4Y=
-----END EC PRIVATE KEY-----";

    const CLIENT_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIDSjCCAtCgAwIBAgIBATAKBggqhkjOPQQDAjB3MQswCQYDVQQGEwJOTDELMAkG
A1UECBMCWkgxDjAMBgNVBAcTBURlbGZ0MRMwEQYDVQQKEwpQa2lUZXN0ZXJzMRMw
EQYDVQQDEwpQa2lUZXN0ZXJzMSEwHwYJKoZIhvcNAQkBFhJvcGVudnBuQGZveC1p
dC5jb20wHhcNMTMxMTEzMTQ0MTExWhcNMjMxMTExMTQ0MTExWjB6MQswCQYDVQQG
EwJOTDELMAkGA1UECBMCWkgxDjAMBgNVBAcTBURlbGZ0MRMwEQYDVQQKEwpQa2lU
ZXN0ZXJzMRYwFAYDVQQDFA1yb290X2NsaWVudF8xMSEwHwYJKoZIhvcNAQkBFhJv
cGVudnBuQGZveC1pdC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARGsC3L2S4v
+r2CdXu5tSCY2zyr4FvnmnC6aJIeJdg4PTWJYLTu+uaGVoIVDM5FyUHRwp3m2RkQ
uz3mBkgubKn1wrSKXa/aWvbd3bCNz5uHW9/65ulUe3H5k+PLh6g0S56jggErMIIB
JzAJBgNVHRMEAjAAMC0GCWCGSAGG+EIBDQQgFh5FYXN5LVJTQSBHZW5lcmF0ZWQg
Q2VydGlmaWNhdGUwHQYDVR0OBBYEFLUws3mTDeMAEzdOeylzmnutSRvWMIGpBgNV
HSMEgaEwgZ6AFLQiLn9HPkzOyExGwzAupSu7G1rpoXukeTB3MQswCQYDVQQGEwJO
TDELMAkGA1UECBMCWkgxDjAMBgNVBAcTBURlbGZ0MRMwEQYDVQQKEwpQa2lUZXN0
ZXJzMRMwEQYDVQQDEwpQa2lUZXN0ZXJzMSEwHwYJKoZIhvcNAQkBFhJvcGVudnBu
QGZveC1pdC5jb22CCQDhqx5uldJK2TATBgNVHSUEDDAKBggrBgEFBQcDAjALBgNV
HQ8EBAMCB4AwCgYIKoZIzj0EAwIDaAAwZQIxAJhseGOzRQnOzCGGPppKjMPdQFLV
ztt/bX8ygEneYsOYG+X6IySnpxT2GKBd17XFnQIwRwQvLDkyL85YCV1LRp9cW3sa
ZRgB27ulkpmKvrg0H0PcaOQkPiIYMIidNA4M+RqQ
-----END CERTIFICATE-----";

    const CLIENT_KEY: &'static [u8] = b"-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDApsneFBw5ne/7Oj2YZfzq4upS8PWh1GbQwuhT3sOuVeio2hta/dg5Q
AyP9o/4NnsWgBwYFK4EEACKhZANiAARGsC3L2S4v+r2CdXu5tSCY2zyr4FvnmnC6
aJIeJdg4PTWJYLTu+uaGVoIVDM5FyUHRwp3m2RkQuz3mBkgubKn1wrSKXa/aWvbd
3bCNz5uHW9/65ulUe3H5k+PLh6g0S54=
-----END EC PRIVATE KEY-----";

    #[test]
    fn control_channel_sends_reset() {
        let (_, receiver_incoming) = channel();
        let (sender_outgoing, receiver_outgoing) = channel();
        let ca_cert = X509::from_pem(CA_CERT).unwrap();
        let client_cert = X509::from_pem(CLIENT_CERT).unwrap();
        let client_key = openssl::pkey::PKey::private_key_from_pem(CLIENT_KEY).unwrap();
        let mut control_channel = ControlChannel::new(
            &mut rng(),
            false,
            ca_cert,
            client_cert,
            client_key,
            receiver_incoming,
            sender_outgoing,
        );
        control_channel.reset();

        let packet = receiver_outgoing.try_recv().unwrap();
        assert_eq!(packet.opcode, Opcode::ControlHardResetClientV2);
        assert_eq!(packet.acks, &[]);
        assert_eq!(packet.payload, &[]);
    }

    #[test]
    fn control_channel_can_read_and_write() {
        let (sender_server, receiver_client) = channel();
        let (sender_client, receiver_server) = channel();
        let ca_cert = X509::from_pem(CA_CERT).unwrap();
        let server_cert = X509::from_pem(SERVER_CERT).unwrap();
        let server_key = openssl::pkey::PKey::private_key_from_pem(SERVER_KEY).unwrap();
        let client_cert = X509::from_pem(CLIENT_CERT).unwrap();
        let client_key = openssl::pkey::PKey::private_key_from_pem(CLIENT_KEY).unwrap();
        let mut client = ControlChannel::new(
            &mut rng(),
            false,
            ca_cert.clone(),
            client_cert,
            client_key,
            receiver_client,
            sender_client,
        );
        let mut server = ControlChannel::new(
            &mut rng(),
            true,
            ca_cert,
            server_cert,
            server_key,
            receiver_server,
            sender_server,
        );

        client.reset();
        while !client.is_connected() || !server.is_connected() {
            client.send_packets();
            server.receive_packets();
            server.send_packets();
            client.receive_packets();
        }

        let mut read_buffer: [u8; 2000] = [0; 2000];
        let message1 = b"Geht der nich noch?";
        client.write(message1).unwrap();
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(message1, &read_buffer[..length]);

        let message2 = b"Der geht ja noch!";
        client.write(message2).unwrap();
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(message2, &read_buffer[..length]);

        let message3 = b"Tut das Not dass der hier so rumoxidiert?";
        client.write(message3).unwrap();
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(message3, &read_buffer[..length]);
    }
}
