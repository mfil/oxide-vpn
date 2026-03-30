use std::convert::From;
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
use super::tls_record_stream::TlsRecordStream;

use crate::packets::{ControlChannelPacket, Opcode};

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

    /// Receive as many incoming packets as are currently available. The payload of control packets
    /// is inserted into the TLS session. If a handshake is in progress, the state of the handshake
    /// is advanced.
    ///
    /// If many packets are received at once, this method may also send out ACK packets.
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

    /// Send out `ControlV1` packets with payloads produced by the TLS session.
    pub fn send_packets(&mut self) {
        // TODO: Need to track if packets are acked and resend them if they're not acked after some
        // time.
        if let Some(tls_record_stream) = self.tls_session.get_tls_record_stream() {
            for payload in tls_record_stream.get_written_records() {
                let packet = self.state.make_packet(Opcode::ControlV1, payload);
                self.sender.send(packet).unwrap();
            }
        }
    }
}

impl Read for ControlChannel {
    /// Read data from the [`ControlChannel`]. If a handshake is in progress, this function will try
    /// to complete the handshake and then read data. It returns `WouldBlock` if a a handshake
    /// cannot be completed at this time.
    ///
    /// An uninitialized client channel will attempt to initialize a connection.
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
    /// Write data to the [`ControlChannel`]. If a handshake is in progress, this function will try to
    /// complete the handshake and then send the data. It returns `WouldBlock` if a a handshake
    /// cannot be completed at this time.
    ///
    /// An uninitialized client channel will attempt to initialize a connection.
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
mod test {
    use super::ControlChannel;
    use crate::packets::Opcode;
    use openssl;
    use openssl::x509::X509;
    use rand::rng;
    use std::io::{Read, Write};
    use std::sync::mpsc::channel;

    // The certificates and keys below were specifically generated for these tests and should
    // never be used outside of it.

    // TODO: The proper way would be to make new certificates when testing, but the hard-coded
    // certificates below are valid until 2036, so that shouldn't matter. By writing this, I have
    // ensured that this program will see actual, long term use, as unlikely as that may seem!
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
