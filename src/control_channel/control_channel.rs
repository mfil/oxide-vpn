use std::cmp::min;
use std::convert::From;
use std::error::Error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::mem::swap;
use std::string::ToString;
use std::sync::mpsc::{Receiver, Sender};

use rand::CryptoRng;

use openssl;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, SslAcceptor, SslConnector, SslMethod, SslStream,
    SslVerifyMode, SslVersion,
};
use openssl::x509::{X509, store::X509StoreBuilder};

use super::control_channel_state::ControlChannelState;

use crate::packets::{ControlChannelPacket, Opcode};

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
    peer_name: String,
    receiver: Receiver<ControlChannelPacket>,
    sender: Sender<ControlChannelPacket>,
}

impl ControlChannel {
    /// Create new control channel.
    pub fn new<R: CryptoRng, S: ToString>(
        rng: &mut R,
        is_server: bool,
        ca: X509,
        certificate: X509,
        private_key: PKey<Private>,
        peer_name: S,
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
            peer_name: peer_name.to_string(),
            receiver,
            sender,
        }
    }

    fn is_connected(&self) -> bool {
        self.tls_session.is_connected()
    }

    fn begin_tls_handshake_client(&mut self) -> Result<(), HandshakeError<TlsRecordStream>> {
        let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
        connector_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        connector_builder.set_verify(SslVerifyMode::PEER);
        let mut ca_store = X509StoreBuilder::new()?;
        ca_store.add_cert(self.ca.clone())?;
        connector_builder.set_verify_cert_store(ca_store.build())?;
        connector_builder.set_certificate(&self.certificate)?;
        connector_builder.set_private_key(&self.private_key)?;
        let connector = connector_builder.build();
        let record_stream = TlsRecordStream::new();

        match connector.connect(&self.peer_name, record_stream) {
            Ok(stream) => self.tls_session = TlsSession::Connected(stream),
            Err(HandshakeError::WouldBlock(stream)) => {
                self.tls_session = TlsSession::Handshake(stream)
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    fn begin_tls_handshake_server(&mut self) -> Result<(), HandshakeError<TlsRecordStream>> {
        let mut acceptor_builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls())?;
        acceptor_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        acceptor_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut ca_store = X509StoreBuilder::new()?;
        ca_store.add_cert(self.ca.clone())?;
        acceptor_builder.set_verify_cert_store(ca_store.build())?;
        acceptor_builder.set_certificate(&self.certificate)?;
        acceptor_builder.set_private_key(&self.private_key)?;
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
                self.sender.send(ack_packet).unwrap();
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
    use super::ControlChannel;
    use crate::packets::Opcode;
    use openssl;
    use openssl::x509::X509;
    use rand::rng;
    use std::io::{Read, Write};
    use std::sync::mpsc::channel;

    // TODO: The proper way would be to make new certificates when testing, but the hard-coded
    // certificates below are valid until 2036, so that shouldn't matter. By writing this, I have
    // ensured that this program will see actual, long term use, of course!
    const CA_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIBtjCCAWigAwIBAgIUOqLE/7GfIrvwcOJXZqkd94HIfzYwBQYDK2VwMGExCzAJ
BgNVBAYTAk5MMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQxGjAYBgNVBAMMEU94aWRlIFZQTiBUZXN0IENBMB4X
DTI2MDMyODE2MTU0OVoXDTM2MDMyNTE2MTU0OVowYTELMAkGA1UEBhMCTkwxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDEaMBgGA1UEAwwRT3hpZGUgVlBOIFRlc3QgQ0EwKjAFBgMrZXADIQC5Zu95
rcIz/3ahqwrrxra/U+krsgNMPypuVyLkwC30dqMyMDAwDwYDVR0TAQH/BAUwAwEB
/zAdBgNVHQ4EFgQUEvhE0R20BY5NnAFYvn3PexqtyYwwBQYDK2VwA0EA034o+dZ6
s8z0YlKGp+GNjzhv2dd3H0ondbtpsKvz93SxoylUCPHdKIHV2UjcuFlgnOzRJQfd
b3x69z8muTGiDw==
-----END CERTIFICATE-----";

    const SERVER_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIB7DCCAZ6gAwIBAgIUY4qwfEA65HL0Hq9ndt+Zu2LOCqAwBQYDK2VwMGExCzAJ
BgNVBAYTAk5MMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQxGjAYBgNVBAMMEU94aWRlIFZQTiBUZXN0IENBMB4X
DTI2MDQwMzAwNTgyNVoXDTM2MDMzMTAwNTgyNVowZTELMAkGA1UEBhMCTkwxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDEeMBwGA1UEAwwVT3hpZGUgVlBOIFRlc3QgU2VydmVyMCowBQYDK2VwAyEA
rqNgtsVVOCl4FbFcqr3PL5Oq7Nv7Rxv7RpsiIXc8/eSjZDBiMAsGA1UdDwQEAwIH
gDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUC3q5TGtQ86pS5RR5Aosg
PeKdbgcwHwYDVR0jBBgwFoAUEvhE0R20BY5NnAFYvn3PexqtyYwwBQYDK2VwA0EA
HmNg+CL3AOpVO6qgNuy8mTq7LWS0PDZoeWzjU55nUpbN/6BWPCQealZAv70Gxk/e
nU7UBlPgOEvMwOSK+prqCg==
-----END CERTIFICATE-----";

    const SERVER_KEY: &'static [u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOYC8vaWDzkj24MZtD7Q4nobUo5T016f7yVRVooGmabx
-----END PRIVATE KEY-----";

    const CLIENT_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIB7DCCAZ6gAwIBAgIUNwQaliRY45G6/EjJe0vDNKXAflMwBQYDK2VwMGExCzAJ
BgNVBAYTAk5MMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQxGjAYBgNVBAMMEU94aWRlIFZQTiBUZXN0IENBMB4X
DTI2MDQwMzAwNTcwMFoXDTM2MDMzMTAwNTcwMFowZTELMAkGA1UEBhMCTkwxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDEeMBwGA1UEAwwVT3hpZGUgVlBOIFRlc3QgQ2xpZW50MCowBQYDK2VwAyEA
RJJKdjiJV6M6hwbFoilRSptu145KsLSBsIAWCAfxBWKjZDBiMAsGA1UdDwQEAwIH
gDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUdK+JTdmhfRRNYzaTdwzL
bKRMN3MwHwYDVR0jBBgwFoAUEvhE0R20BY5NnAFYvn3PexqtyYwwBQYDK2VwA0EA
1Qs/hX5CjbFYpHfqlLqDZZ0u+zVqHogGFX9s9QURywuSgjwKOyapnZXexLaJRLoX
x1FLmZyk94KX8bfj/1xtAA==
-----END CERTIFICATE-----";

    const CLIENT_KEY: &'static [u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPoLkAE/xkDbkwg7Qarhru2ykSodlmZ9H+fm66ZUTE7V
-----END PRIVATE KEY-----";

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
            "Oxide VPN Test Server",
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
            "Oxide VPN Test Server",
            receiver_client,
            sender_client,
        );
        let mut server = ControlChannel::new(
            &mut rng(),
            true,
            ca_cert,
            server_cert,
            server_key,
            "Oxide VPN Test Client",
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
