//! Handles the TLS session of the control channel.
use std::collections::VecDeque;
use std::io;
use std::io::{Read, Write};
use std::mem::swap;

use openssl;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, SslAcceptor, SslConnector, SslMethod, SslStream,
    SslVerifyMode, SslVersion,
};
use openssl::x509::{X509, store::X509StoreBuilder};

use crate::Error;
use crate::packets::ControlChannelPacketBuffer;

/// Assuming that record points at a TLS record header, calculate the length, including the header.
fn get_tls_record_length(record: &[u8]) -> usize {
    let (header, _) = record.split_first_chunk::<5>().unwrap();
    let (_, length_bytes) = header.split_last_chunk::<2>().unwrap();
    u16::from_be_bytes(*length_bytes) as usize + 5
}

/// Reader + Writer for use by an [`SslConnector`].
///
/// Each control channel packet needs to contain a single whole TLS record, so we chunk the data
/// from the [`SslConnector`] into TLS records. We assume that the data written to this object is
/// a stream of TLS records. We do not validate the TLS record headers, but simply take the length
/// from what should be the length field.
#[derive(Debug)]
pub struct TlsRecordStream {
    /// The payloads of the received packets.
    payloads_to_read: VecDeque<Vec<u8>>,
    /// Data to send to the peer.
    written_tls_records: VecDeque<ControlChannelPacketBuffer>,
    partial_record: Option<ControlChannelPacketBuffer>,
}

impl TlsRecordStream {
    fn new() -> Self {
        Self {
            payloads_to_read: VecDeque::new(),
            written_tls_records: VecDeque::new(),
            partial_record: None,
        }
    }

    /// Get the next TLS record written by the TLS session. These records are placed into buffers
    /// with enough headroom to write a control channel packet header.
    fn get_next(&mut self) -> Option<ControlChannelPacketBuffer> {
        self.written_tls_records.pop_front()
    }

    /// Insert a payload for the TLS session.
    fn insert_payload(&mut self, payload: Vec<u8>) {
        self.payloads_to_read.push_back(payload);
    }
}

impl Read for TlsRecordStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.payloads_to_read.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        let mut amount_read: usize = 0;
        let mut remaining_buffer = buffer;
        while let Some(mut payload) = self.payloads_to_read.pop_front() {
            if remaining_buffer.len() >= payload.len() {
                let write_to: &mut [u8];
                (write_to, remaining_buffer) = remaining_buffer.split_at_mut(payload.len());
                write_to.copy_from_slice(&payload);
                amount_read += payload.len();
            } else {
                remaining_buffer.copy_from_slice(&payload[..remaining_buffer.len()]);
                payload.copy_within(remaining_buffer.len().., 0);
                payload.truncate(payload.len() - remaining_buffer.len());
                self.payloads_to_read.push_front(payload);
                amount_read += remaining_buffer.len();
                break;
            }
        }
        Ok(amount_read)
    }
}

impl Write for TlsRecordStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut record: &[u8];
        let mut rest = buffer;

        if let Some(mut partial_record) = self.partial_record.take() {
            let missing_bytes =
                get_tls_record_length(partial_record.get_payload()) - partial_record.payload_len();
            if buffer.len() < missing_bytes {
                partial_record.extend_payload_from_slice(buffer);
                self.partial_record = Some(partial_record);
                return Ok(buffer.len());
            }

            let record_tail: &[u8];
            (record_tail, rest) = rest.split_at(missing_bytes);
            partial_record.extend_payload_from_slice(record_tail);
            self.written_tls_records.push_back(partial_record);
        }

        // We keep going until there are less than five bytes left. A TLS record header is five
        // bytes, so we can't do anything with less.
        while rest.len() >= 5 {
            let record_len = get_tls_record_length(rest);
            let mut next_record = ControlChannelPacketBuffer::with_payload_capacity(record_len);
            if record_len > rest.len() {
                next_record.extend_payload_from_slice(rest);
                self.partial_record = Some(next_record);
                return Ok(buffer.len());
            }

            (record, rest) = rest.split_at(record_len);
            next_record.extend_payload_from_slice(record);
            self.written_tls_records.push_back(next_record);
        }
        Ok(buffer.len() - rest.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum TlsSession {
    Uninitialized,
    Handshake(MidHandshakeSslStream<TlsRecordStream>),
    Connected(SslStream<TlsRecordStream>),
}

impl TlsSession {
    pub fn new() -> Self {
        TlsSession::Uninitialized
    }

    pub fn begin_tls_handshake_client(
        &mut self,
        ca: &X509,
        certificate: &X509,
        private_key: &PKey<Private>,
        peer_name: &str,
    ) -> Result<(), HandshakeError<TlsRecordStream>> {
        let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
        connector_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        connector_builder.set_verify(SslVerifyMode::PEER);
        let mut ca_store = X509StoreBuilder::new()?;
        ca_store.add_cert(ca.clone())?;
        connector_builder.set_verify_cert_store(ca_store.build())?;
        connector_builder.set_certificate(certificate)?;
        connector_builder.set_private_key(private_key)?;
        let connector = connector_builder.build();
        let record_stream = TlsRecordStream::new();

        match connector.connect(peer_name, record_stream) {
            Ok(stream) => *self = TlsSession::Connected(stream),
            Err(HandshakeError::WouldBlock(stream)) => *self = TlsSession::Handshake(stream),
            Err(e) => return Err(e),
        }

        Ok(())
    }

    pub fn begin_tls_handshake_server(
        &mut self,
        ca: &X509,
        certificate: &X509,
        private_key: &PKey<Private>,
    ) -> Result<(), Error> {
        let mut acceptor_builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls())?;
        acceptor_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        acceptor_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut ca_store = X509StoreBuilder::new()?;
        ca_store.add_cert(ca.clone())?;
        acceptor_builder.set_verify_cert_store(ca_store.build())?;
        acceptor_builder.set_certificate(certificate)?;
        acceptor_builder.set_private_key(private_key)?;
        let acceptor = acceptor_builder.build();
        let record_stream = TlsRecordStream::new();

        match acceptor.accept(record_stream) {
            Ok(stream) => *self = TlsSession::Connected(stream),
            Err(HandshakeError::WouldBlock(stream)) => *self = TlsSession::Handshake(stream),
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        if let Self::Connected(_) = self {
            true
        } else {
            false
        }
    }

    fn get_tls_record_stream(&mut self) -> Option<&mut TlsRecordStream> {
        match self {
            Self::Uninitialized => None,
            Self::Handshake(stream) => Some(stream.get_mut()),
            Self::Connected(stream) => Some(stream.get_mut()),
        }
    }

    pub fn get_stream(&self) -> Option<&SslStream<TlsRecordStream>> {
        if let Self::Connected(ssl_stream) = self {
            Some(ssl_stream)
        } else {
            None
        }
    }

    pub fn get_stream_mut(&mut self) -> Option<&mut SslStream<TlsRecordStream>> {
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

    /// Get the next TLS record written by the TLS session. These records are placed into buffers
    /// with enough headroom to write a control channel packet header.
    pub fn get_next_record(&mut self) -> Option<ControlChannelPacketBuffer> {
        if let Some(stream) = self.get_tls_record_stream() {
            stream.get_next()
        } else {
            None
        }
    }
}

impl Read for TlsSession {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let stream = self
            .get_stream_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
        stream.read(buffer)
    }
}

impl Write for TlsSession {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let stream = self
            .get_stream_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
        stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let stream = self
            .get_stream_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
        stream.flush()
    }
}

#[cfg(test)]
mod tls_record_stream_tests {
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
        let mut actual = Vec::new();
        while let Some(record) = record_stream.get_next() {
            actual.push(record);
        }
        assert_eq!(actual.len(), expected.len());
        for (record, expected_record) in actual.iter().zip(expected.iter()) {
            assert_eq!(record.get_payload(), *expected_record);
        }
    }

    #[test]
    fn handles_individual_records() {
        let mut record_stream = TlsRecordStream::new();
        checked_write(&mut record_stream, RECORD1);
        checked_write(&mut record_stream, RECORD2);
        check_written_records(&mut record_stream, &[RECORD1, RECORD2]);
    }

    #[test]
    fn handles_combined_records() {
        let mut record_stream = TlsRecordStream::new();
        let mut combined_records = Vec::new();
        combined_records.extend_from_slice(RECORD1);
        combined_records.extend_from_slice(RECORD2);
        checked_write(&mut record_stream, &combined_records);
        check_written_records(&mut record_stream, &[RECORD1, RECORD2]);
    }

    #[test]
    fn handles_partial_records() {
        let mut record_stream = TlsRecordStream::new();
        checked_write(&mut record_stream, RECORD1_PART1);
        check_written_records(&mut record_stream, &[]);

        checked_write(&mut record_stream, RECORD1_PART2);
        check_written_records(&mut record_stream, &[]);

        checked_write(&mut record_stream, RECORD1_PART3);
        check_written_records(&mut record_stream, &[RECORD1]);
    }

    #[test]
    fn handles_mixed_partial_and_full_records() {
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
    fn does_not_write_partial_header() {
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
    fn can_read() {
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
    fn says_would_block_if_empty() {
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
mod tls_session_tests {
    use super::TlsSession;
    use crate::control_channel::test_helpers::make_test_certs;

    use std::io::{Read, Write};

    #[test]
    fn can_communicate() {
        let test_certs = make_test_certs();
        let mut server = TlsSession::new();
        let mut client = TlsSession::new();

        client
            .begin_tls_handshake_client(
                &test_certs.ca_cert,
                &test_certs.client_cert,
                &test_certs.client_key,
                "Oxide VPN Test Server",
            )
            .unwrap();
        server
            .begin_tls_handshake_server(
                &test_certs.ca_cert,
                &test_certs.server_cert,
                &test_certs.server_key,
            )
            .unwrap();

        while !client.is_connected() || !server.is_connected() {
            while let Some(record) = client.get_next_record() {
                server.insert_payload(record.as_slice().to_vec()).unwrap();
            }
            while let Some(record) = server.get_next_record() {
                client.insert_payload(record.as_slice().to_vec()).unwrap();
            }
        }

        let message1 = b"Hello server";
        client.write(message1).unwrap();
        while let Some(record) = client.get_next_record() {
            server.insert_payload(record.as_slice().to_vec()).unwrap();
        }

        let mut read_buffer: [u8; 100] = [0; _];
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(&read_buffer[..length], message1);

        let message2 = b"Hello client";
        server.write(message2).unwrap();
        while let Some(record) = server.get_next_record() {
            client.insert_payload(record.as_slice().to_vec()).unwrap();
        }

        let length = client.read(&mut read_buffer).unwrap();
        assert_eq!(&read_buffer[..length], message2);
    }
}
