mod reliability;
mod tls;

pub mod messages;

use rand::CryptoRng;
use reliability::{IncomingQueue, PacketIdBuffer, ResendQueue};
use tls::TlsSession;

use std::collections::VecDeque;
use std::io;
use std::io::{Read, Write};
use std::string::ToString;
use std::time::Instant;

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

use crate::Error;
use crate::data_channel::{DataChannelKeys, EpochKey};
use crate::packets::{ControlChannelPacket, ControlChannelPacketBuffer, Opcode};

/// OpenVPN Control Channel.
#[derive(Debug)]
pub struct ControlChannel {
    incoming_queue: IncomingQueue,
    resend_queue: ResendQueue,
    packet_id_buffer: PacketIdBuffer,
    pending_packets: VecDeque<(Option<u32>, ControlChannelPacketBuffer)>,
    session_id: u64,
    peer_session_id: Option<u64>,
    next_packet_id: u32,
    tls_session: TlsSession,
    is_server: bool,
    ca: X509,
    certificate: X509,
    private_key: PKey<Private>,
    peer_name: String,
}

/// OpenVPN Control Channel.
///
/// Authenticates with the peer, exchanges configuration information and generates shared symmetric
/// data channel keys.
impl ControlChannel {
    pub fn new<R: CryptoRng, S: ToString>(
        rng: &mut R,
        is_server: bool,
        ca: X509,
        certificate: X509,
        private_key: PKey<Private>,
        peer_name: S,
    ) -> Self {
        ControlChannel {
            incoming_queue: IncomingQueue::new(),
            resend_queue: ResendQueue::new(),
            packet_id_buffer: PacketIdBuffer::new(),
            tls_session: TlsSession::new(),
            pending_packets: VecDeque::new(),
            session_id: rng.next_u64(),
            peer_session_id: None,
            next_packet_id: 0,
            is_server,
            ca,
            certificate,
            private_key,
            peer_name: peer_name.to_string(),
        }
    }

    /// Initializes the control channel.
    pub fn reset(&mut self) {
        if !self.is_server {
            let packet = self.make_outgoing_packet(
                Opcode::ControlHardResetClientV2,
                0,
                ControlChannelPacketBuffer::with_payload_capacity(0),
            );
            self.pending_packets.push_back(packet);
        }
    }

    /// Fill in the header in front of the payload in a [`ControlChannelPacketBuffer`].
    /// Returns the assigned packet ID (if any) and the filled-in buffer.
    pub fn make_outgoing_packet(
        &mut self,
        opcode: Opcode,
        key_id: u8,
        payload: ControlChannelPacketBuffer,
    ) -> (Option<u32>, ControlChannelPacketBuffer) {
        let mut packet = payload;
        let packet_id: Option<u32>;
        let max_acks: usize;
        if opcode == Opcode::ControlAckV1 {
            packet_id = None;
            max_acks = 8;
        } else {
            packet_id = Some(self.next_packet_id);
            self.next_packet_id += 1;
            max_acks = 4;
        }
        let acks = self.packet_id_buffer.ack(max_acks);

        packet.write_header(
            opcode,
            key_id,
            self.session_id,
            acks,
            self.peer_session_id,
            packet_id,
        );
        (packet_id, packet)
    }

    /// Receive a packet. The payload of control packets is inserted into the TLS session.
    pub fn receive_packet<'a>(&mut self, packet: ControlChannelPacket<'a>) -> Result<(), Error> {
        if let Some(expected_session_id) = self.peer_session_id {
            if packet.session_id != expected_session_id {
                return Err(Error::packet_error(
                    "Incorrect peer session ID in control channel.",
                ));
            }
        } else {
            self.peer_session_id = Some(packet.session_id);
        }
        self.resend_queue.remove_acked_packets(&packet.acks);

        if let Some(id) = packet.packet_id {
            if self.packet_id_buffer.filled_with_unacked_ids() {
                let (id, packet) = self.make_outgoing_packet(
                    Opcode::ControlAckV1,
                    0,
                    ControlChannelPacketBuffer::with_payload_capacity(0),
                );
                self.pending_packets.push_back((id, packet));
            }
            self.packet_id_buffer.insert(id);
            self.incoming_queue
                .insert(id, (packet.opcode, packet.key_id, packet.payload.to_vec()))
        }

        let mut started_server_handshake = false;
        for (opcode, _key_id, payload) in self.incoming_queue.iter() {
            if opcode == Opcode::ControlV1 {
                self.tls_session.insert_payload(payload)?;
            } else if opcode == Opcode::ControlHardResetClientV2 && self.is_server {
                self.tls_session.begin_tls_handshake_server(
                    &self.ca,
                    &self.certificate,
                    &self.private_key,
                )?;
                started_server_handshake = true;
            } else if opcode == Opcode::ControlHardResetServerV2 && !self.is_server {
                self.tls_session.begin_tls_handshake_client(
                    &self.ca,
                    &self.certificate,
                    &self.private_key,
                    &self.peer_name,
                )?;
            }
        }
        if started_server_handshake {
            let packet = self.make_outgoing_packet(
                Opcode::ControlHardResetServerV2,
                0,
                ControlChannelPacketBuffer::with_payload_capacity(0),
            );
            self.pending_packets.push_back(packet);
        }
        Ok(())
    }

    /// Try to send all the packets that the control channel wants to (re-)send at this time.
    pub fn send<T, F: FnMut(&[u8]) -> io::Result<T>>(
        &mut self,
        time: Instant,
        send_function: &mut F,
    ) -> std::io::Result<()> {
        // Resend old packets if their resend timeout expired.
        self.resend_queue.resend(time, send_function)?;

        // Send packets from pending_packets.
        while let Some((id, packet)) = self.pending_packets.pop_front() {
            if let Err(e) = send_function(packet.as_slice()) {
                self.pending_packets.push_front((id, packet));
                return Err(e);
            }
            if let Some(id) = id {
                self.resend_queue.add_packet(time, id, packet);
            }
        }

        // Make packets from the generated TLS records.
        while let Some(payload) = self.tls_session.get_next_record() {
            let (id, packet) = self.make_outgoing_packet(Opcode::ControlV1, 0, payload);
            if let Err(e) = send_function(packet.as_slice()) {
                // Put the failed packet into pending_packets so we can retry it later.
                self.pending_packets.push_back((id, packet));
                return Err(e);
            }
            if let Some(id) = id {
                self.resend_queue.add_packet(time, id, packet);
            }
        }

        // If there still are unacked IDs, send a dedicated ACK packet.
        if self.packet_id_buffer.has_unacked_ids() {
            let (id, packet) = self.make_outgoing_packet(
                Opcode::ControlAckV1,
                0,
                ControlChannelPacketBuffer::with_payload_capacity(0),
            );
            if let Err(e) = send_function(packet.as_slice()) {
                self.pending_packets.push_back((id, packet));
                return Err(e);
            }
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.tls_session.is_connected()
    }

    /// Run the TLS-Exporter to obtain a shared symmetric key for the data channel.
    pub fn derive_data_channel_keys(&self) -> Result<DataChannelKeys, Error> {
        // We need to generate more key material than we actually use due to backwards
        // compatibility in the OpenVPN protocol.
        let mut key_buffer: [u8; 256] = [0; _];

        if let Some(stream) = self.tls_session.get_stream() {
            stream.ssl().export_keying_material(
                &mut key_buffer,
                "EXPORTER-OpenVPN-datakeys",
                None,
            )?;
            let (chunks, _) = key_buffer.as_chunks::<32>();
            let client_to_server = EpochKey::from_key_material(&chunks[0]);
            let server_to_client = EpochKey::from_key_material(&chunks[4]);

            unsafe {
                memsec::memzero(key_buffer.as_mut_ptr(), key_buffer.len());
            }
            Ok(DataChannelKeys {
                client_to_server,
                server_to_client,
            })
        } else {
            Err(Error::ControlChannelNotReady)
        }
    }
}

impl Read for ControlChannel {
    /// Read plaintext messages from the peer on the control channel.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.tls_session.read(buffer)
    }
}

impl Write for ControlChannel {
    /// Write messages to the control channel that are encrypted and sent to the peer.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.tls_session.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tls_session.flush()
    }
}

#[cfg(test)]
mod test_helpers {
    use std::ops::Index;

    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{ExtendedKeyUsage, KeyUsage};
    use openssl::x509::{X509, X509Name};

    #[derive(PartialEq, Eq, Debug)]
    pub struct ChannelWriteBuffer {
        buffer: Vec<Vec<u8>>,
    }

    impl ChannelWriteBuffer {
        pub fn new() -> Self {
            Self { buffer: Vec::new() }
        }

        pub fn push_bytes(&mut self, data: &[u8]) {
            self.buffer.push(data.to_vec());
        }

        pub fn clear(&mut self) {
            self.buffer.clear();
        }

        pub fn len(&self) -> usize {
            self.buffer.len()
        }

        pub fn pop(&mut self) -> Option<Vec<u8>> {
            self.buffer.pop()
        }

        pub fn drain<'a>(&'a mut self) -> std::vec::Drain<'a, Vec<u8>> {
            self.buffer.drain(..)
        }

        pub fn iter(&mut self) -> impl Iterator<Item = &Vec<u8>> {
            self.buffer.iter()
        }

        pub fn get_send_function(&mut self) -> impl FnMut(&[u8]) -> std::io::Result<()> {
            |data| {
                self.push_bytes(data);
                Ok(())
            }
        }
    }

    impl Index<usize> for ChannelWriteBuffer {
        type Output = Vec<u8>;

        fn index(&self, index: usize) -> &Self::Output {
            &self.buffer[index]
        }
    }

    pub struct TestCertificates {
        pub ca_cert: X509,
        pub server_cert: X509,
        pub server_key: PKey<Private>,
        pub client_cert: X509,
        pub client_key: PKey<Private>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CertType {
        Ca,
        Server,
        Client,
    }

    fn x509_name_from_type(cert_type: CertType) -> X509Name {
        let common_name = match cert_type {
            CertType::Ca => "Oxide VPN Test CA",
            CertType::Server => "Oxide VPN Test Server",
            CertType::Client => "Oxide VPN Test Client",
        };
        let mut name_builder = X509Name::builder().unwrap();
        name_builder
            .append_entry_by_text("CN", common_name)
            .unwrap();
        name_builder.build()
    }

    fn make_key_and_cert(
        cert_type: CertType,
        ca_key: Option<&PKey<Private>>,
    ) -> (PKey<Private>, X509) {
        let key = PKey::generate_ed25519().unwrap();
        let mut cert_builder = X509::builder().unwrap();
        cert_builder
            .set_subject_name(&x509_name_from_type(cert_type))
            .unwrap();
        cert_builder
            .set_issuer_name(&x509_name_from_type(CertType::Ca))
            .unwrap();
        cert_builder
            .set_not_after(Asn1Time::days_from_now(30).unwrap().as_ref())
            .unwrap();
        cert_builder
            .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        cert_builder.set_pubkey(&key).unwrap();

        if cert_type != CertType::Ca {
            let key_usage = KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap();
            cert_builder.append_extension(key_usage).unwrap();
            let mut ext_key_usage_builder = ExtendedKeyUsage::new();
            ext_key_usage_builder.critical();
            if cert_type == CertType::Server {
                ext_key_usage_builder.server_auth();
            } else {
                ext_key_usage_builder.client_auth();
            }
            let ext_key_usage = ext_key_usage_builder.build().unwrap();
            cert_builder.append_extension(ext_key_usage).unwrap();
        }

        let sign_key = ca_key.unwrap_or(&key);
        cert_builder.sign(sign_key, MessageDigest::null()).unwrap();
        let cert = cert_builder.build();

        (key, cert)
    }

    pub fn make_test_certs() -> TestCertificates {
        let (ca_key, ca_cert) = make_key_and_cert(CertType::Ca, None);
        let (server_key, server_cert) = make_key_and_cert(CertType::Server, Some(&ca_key));
        let (client_key, client_cert) = make_key_and_cert(CertType::Client, Some(&ca_key));

        TestCertificates {
            ca_cert,
            server_cert,
            server_key,
            client_cert,
            client_key,
        }
    }
}

#[cfg(test)]
mod test {
    use super::ControlChannel;
    use super::test_helpers::{ChannelWriteBuffer, TestCertificates, make_test_certs};
    use crate::error::Error;
    use crate::packets::{ControlChannelPacket, Opcode};
    use rand::rng;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    fn create_client(certs: &TestCertificates) -> ControlChannel {
        ControlChannel::new(
            &mut rng(),
            false,
            certs.ca_cert.clone(),
            certs.client_cert.clone(),
            certs.client_key.clone(),
            "Oxide VPN Test Server",
        )
    }

    fn create_server(certs: &TestCertificates) -> ControlChannel {
        ControlChannel::new(
            &mut rng(),
            true,
            certs.ca_cert.clone(),
            certs.server_cert.clone(),
            certs.server_key.clone(),
            "Oxide VPN Test Client",
        )
    }

    /// Send messages from client to server and then vice versa.
    fn do_exchange(
        time: Instant,
        client: &mut ControlChannel,
        server: &mut ControlChannel,
    ) -> Result<(), Error> {
        let mut write_buffer = ChannelWriteBuffer::new();
        client.send(time, &mut write_buffer.get_send_function())?;
        for packet in write_buffer.drain() {
            let parsed_packet = ControlChannelPacket::parse(packet.as_slice())?;
            server.receive_packet(parsed_packet)?;
        }
        server.send(time, &mut write_buffer.get_send_function())?;
        for packet in write_buffer.drain() {
            let parsed_packet = ControlChannelPacket::parse(packet.as_slice())?;
            client.receive_packet(parsed_packet)?;
        }
        Ok(())
    }

    fn create_connected_pair() -> Result<(ControlChannel, ControlChannel), Error> {
        let certs = make_test_certs();
        let mut client = create_client(&certs);
        let mut server = create_server(&certs);

        let t0 = Instant::now();
        client.reset();
        while !client.is_connected() || !server.is_connected() {
            do_exchange(t0, &mut client, &mut server)?;
        }
        do_exchange(t0, &mut client, &mut server)?;

        Ok((client, server))
    }

    #[test]
    fn control_channel_sends_reset() {
        let certs = make_test_certs();
        let mut control_channel = create_client(&certs);
        control_channel.reset();

        let mut write_buffer = ChannelWriteBuffer::new();
        control_channel
            .send(Instant::now(), &mut write_buffer.get_send_function())
            .unwrap();
        assert_eq!(write_buffer.len(), 1);
        let packet = ControlChannelPacket::parse(&write_buffer[0]).unwrap();
        assert_eq!(packet.opcode, Opcode::ControlHardResetClientV2);
        assert_eq!(packet.acks, &[]);
        assert_eq!(packet.payload, &[]);
    }

    #[test]
    fn control_channel_can_read_and_write() {
        let certs = make_test_certs();
        let mut client = create_client(&certs);
        let mut server = create_server(&certs);
        client.reset();

        // Make all packets happen "simultaneously" so we don't have to bother with re-sends.
        let t0 = Instant::now();
        while !client.is_connected() || !server.is_connected() {
            do_exchange(t0, &mut client, &mut server).unwrap();
        }

        let mut read_buffer: [u8; 2000] = [0; 2000];
        let message1 = b"Geht der nich noch?";
        client.write(message1).unwrap();
        do_exchange(t0, &mut client, &mut server).unwrap();
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(message1, &read_buffer[..length]);

        let message2 = b"Der geht ja noch!";
        client.write(message2).unwrap();
        do_exchange(t0, &mut client, &mut server).unwrap();
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(message2, &read_buffer[..length]);

        let message3 = b"Tut das Not dass der hier so rumoxidiert?";
        client.write(message3).unwrap();
        do_exchange(t0, &mut client, &mut server).unwrap();
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(message3, &read_buffer[..length]);
    }

    #[test]
    fn control_channel_ignores_duplicate_packets() {
        let certs = make_test_certs();
        let mut client = create_client(&certs);
        let mut server = create_server(&certs);
        let mut write_buffer = ChannelWriteBuffer::new();
        client.reset();

        // Client hard reset.
        let t0 = Instant::now();
        client
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();
        assert_eq!(write_buffer.len(), 1);
        let packet1 = write_buffer.pop().unwrap();
        server
            .receive_packet(ControlChannelPacket::parse(packet1.as_slice()).unwrap())
            .unwrap();
        // Server hard reset.
        server
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();
        assert_eq!(write_buffer.len(), 1);
        let packet2 = write_buffer.pop().unwrap();
        client
            .receive_packet(ControlChannelPacket::parse(packet2.as_slice()).unwrap())
            .unwrap();
        // First TLS handshake packet (client -> server).
        client
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();
        assert_eq!(write_buffer.len(), 1);
        let packet3 = write_buffer.pop().unwrap();
        server
            .receive_packet(ControlChannelPacket::parse(packet3.as_slice()).unwrap())
            .unwrap();
        // First TLS handshake packet (server -> cient).
        server
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();
        let packet4 = write_buffer[0].clone();
        for packet in write_buffer.drain() {
            client
                .receive_packet(ControlChannelPacket::parse(packet.as_slice()).unwrap())
                .unwrap();
        }
        // Receive duplicate of packet4.
        client
            .receive_packet(ControlChannelPacket::parse(packet4.as_slice()).unwrap())
            .unwrap();

        // Try to complete the handshake.
        while !client.is_connected() || !server.is_connected() {
            do_exchange(t0, &mut client, &mut server).unwrap();
        }

        // Resend the server hard reset packet.
        client
            .receive_packet(ControlChannelPacket::parse(packet2.as_slice()).unwrap())
            .unwrap();

        // Send the first handshake packet again.
        client
            .receive_packet(ControlChannelPacket::parse(packet4.as_slice()).unwrap())
            .unwrap();

        // Send a message twice.
        client.write(b"Duplicate packet test").unwrap();
        client
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();
        assert_eq!(write_buffer.len(), 1);
        for packet in write_buffer.drain() {
            // Send the message twice.
            let parsed_packet = ControlChannelPacket::parse(packet.as_slice()).unwrap();
            server.receive_packet(parsed_packet).unwrap();
            let parsed_packet = ControlChannelPacket::parse(packet.as_slice()).unwrap();
            server.receive_packet(parsed_packet).unwrap();
        }

        let mut read_buffer: [u8; 1000] = [0; 1000];
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(&read_buffer[..length], b"Duplicate packet test");
        assert_eq!(
            server.read(&mut read_buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn control_channel_handles_out_of_order_packets() {
        let certs = make_test_certs();
        let mut client = create_client(&certs);
        let mut server = create_server(&certs);
        let mut write_buffer = ChannelWriteBuffer::new();
        let t0 = Instant::now();
        client.reset();

        // Try to complete the handshake. If one peer sends multiple packets in a row, reverse
        // the order.
        while !client.is_connected() || !server.is_connected() {
            client
                .send(t0, &mut write_buffer.get_send_function())
                .unwrap();
            for packet in write_buffer.drain().rev() {
                let parsed_packet = ControlChannelPacket::parse(packet.as_slice()).unwrap();
                server.receive_packet(parsed_packet).unwrap();
            }
            server
                .send(t0, &mut write_buffer.get_send_function())
                .unwrap();
            for packet in write_buffer.drain().rev() {
                let parsed_packet = ControlChannelPacket::parse(packet.as_slice()).unwrap();
                client.receive_packet(parsed_packet).unwrap();
            }
        }

        client.write(b"Message 1").unwrap();
        client.write(b"Message 2").unwrap();
        client.write(b"Message 3").unwrap();
        client
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();
        for packet_buffer in write_buffer.drain().rev() {
            let packet = ControlChannelPacket::parse(packet_buffer.as_slice()).unwrap();
            server.receive_packet(packet).unwrap();
        }
        let mut read_buffer: [u8; 1000] = [0; 1000];
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(&read_buffer[..length], b"Message 1");
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(&read_buffer[..length], b"Message 2");
        let length = server.read(&mut read_buffer).unwrap();
        assert_eq!(&read_buffer[..length], b"Message 3");
    }

    #[test]
    fn control_channel_resends_unacked_packets() {
        let (mut client, _) = create_connected_pair().unwrap();
        let mut send_buffer = ChannelWriteBuffer::new();

        let t0 = Instant::now();
        client.write(b"Message 1").unwrap();
        client.write(b"Message 2").unwrap();
        client.write(b"Message 3").unwrap();
        client
            .send(t0, &mut send_buffer.get_send_function())
            .unwrap();

        let t1 = t0 + Duration::from_secs(2);
        let mut resend_buffer = ChannelWriteBuffer::new();
        client
            .send(t1, &mut resend_buffer.get_send_function())
            .unwrap();

        assert_eq!(send_buffer, resend_buffer);
    }

    #[test]
    fn control_channel_sends_acks_with_packets() {
        let (mut client, mut server) = create_connected_pair().unwrap();
        let mut write_buffer = ChannelWriteBuffer::new();

        // Make the server send some stuff.
        server.write(b"Message 1").unwrap();
        server.write(b"Message 2").unwrap();
        server.write(b"Message 3").unwrap();
        let t0 = Instant::now();
        server
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();

        // Extract the packet IDs the client should ack.
        let to_ack = Vec::from_iter(write_buffer.iter().filter_map(|buf| {
            let packet = ControlChannelPacket::parse(buf).unwrap();
            packet.packet_id
        }));

        // Let the client receive the packets and send a new packet in response.
        for data in write_buffer.drain() {
            let packet = ControlChannelPacket::parse(&data).unwrap();
            client.receive_packet(packet).unwrap();
        }
        client.write(b"Response").unwrap();
        client
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();

        // Check that the client's packet contains all the previously unacked IDs.
        assert_eq!(write_buffer.len(), 1);
        let packet = ControlChannelPacket::parse(&write_buffer[0]).unwrap();
        for ack in to_ack {
            assert!(packet.acks.contains(&ack));
        }

        // Check that the server doesn't want to resend the packets after receiving the client's
        // packet.
        server.receive_packet(packet).unwrap();
        write_buffer.clear();
        let t1 = t0 + Duration::from_secs(2);
        server
            .send(t1, &mut write_buffer.get_send_function())
            .unwrap();
        assert_eq!(write_buffer.len(), 1);
        let packet = ControlChannelPacket::parse(&write_buffer[0]).unwrap();
        assert_eq!(packet.opcode, Opcode::ControlAckV1);
    }

    #[test]
    fn control_channel_sends_dedicated_ack_packets() {
        let (mut client, mut server) = create_connected_pair().unwrap();
        let mut write_buffer = ChannelWriteBuffer::new();

        // Make the server send some stuff.
        for i in 0..10 {
            server.write(&[i as u8]).unwrap();
        }
        let t0 = Instant::now();
        server
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();

        // Extract the packet IDs the client should ack.
        let to_ack = Vec::from_iter(write_buffer.iter().filter_map(|buf| {
            let packet = ControlChannelPacket::parse(buf).unwrap();
            packet.packet_id
        }));

        // Let the client receive the packets and send a new packet in response.
        for data in write_buffer.drain() {
            let packet = ControlChannelPacket::parse(&data).unwrap();
            client.receive_packet(packet).unwrap();
        }

        // We make the client send without writing any messages. This should trigger sending
        // dedicated ACK packets.
        client
            .send(t0, &mut write_buffer.get_send_function())
            .unwrap();

        // Check that the client's packet contains all the previously unacked IDs.
        assert_eq!(write_buffer.len(), 2);
        let packet1 = ControlChannelPacket::parse(&write_buffer[0]).unwrap();
        let packet2 = ControlChannelPacket::parse(&write_buffer[1]).unwrap();
        assert_eq!(packet1.opcode, Opcode::ControlAckV1);
        assert_eq!(packet2.opcode, Opcode::ControlAckV1);
        for ack in to_ack {
            assert!(packet1.acks.contains(&ack) || packet2.acks.contains(&ack));
        }

        // Check that the server doesn't want to resend the packets after receiving the client's
        // packets.
        server.receive_packet(packet1).unwrap();
        server.receive_packet(packet2).unwrap();
        write_buffer.clear();
        let t1 = t0 + Duration::from_secs(2);
        server
            .send(t1, &mut write_buffer.get_send_function())
            .unwrap();
        assert_eq!(write_buffer.len(), 0);
    }
}
