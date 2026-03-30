use std::cmp::min;
use std::io;
use std::io::{Read, Write};
use std::mem::swap;

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

#[cfg(test)]
mod test {
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
