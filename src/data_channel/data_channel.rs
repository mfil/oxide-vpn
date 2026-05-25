use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;

use super::keys::{EncryptionKey, EpochKey, ImplicitIv};
use crate::Error;
use crate::packets::{DataChannelPacket, DataChannelPacketBuffer};

struct PacketCounter {
    pub epoch: u16,
    pub epoch_counter: u64,
    pub packets_per_epoch: u64,
}

impl PacketCounter {
    fn new(packets_per_epoch: u64) -> Self {
        Self {
            epoch: 1,
            epoch_counter: 1,
            packets_per_epoch,
        }
    }

    fn get_packet_id(&self) -> [u8; 8] {
        let mut packet_id = self.epoch_counter.to_be_bytes();
        packet_id[0] = (self.epoch >> 8) as u8;
        packet_id[1] = self.epoch as u8;
        packet_id
    }

    fn increment(&mut self) {
        if self.epoch_counter == self.packets_per_epoch {
            self.epoch += 1;
            self.epoch_counter = 1;
        } else {
            self.epoch_counter += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub struct Algorithm {
    packets_per_epoch: u64,
    cipher_ref: fn() -> &'static CipherRef,
}

pub const AES_256_GCM: Algorithm = Algorithm {
    packets_per_epoch: 1 << 24,
    cipher_ref: Cipher::aes_256_gcm,
};

pub struct DataChannel {
    peer_id: [u8; 3],
    algorithm: Algorithm,
    encryption_epoch_key: EpochKey,
    encryption_key: EncryptionKey,
    encryption_iv: ImplicitIv,
    decryption_epoch_key: EpochKey,
    decryption_key: EncryptionKey,
    decryption_iv: ImplicitIv,
    next_packet_id: PacketCounter,
}

fn combine_iv(packet_id: &[u8; 8], implicit_iv: &ImplicitIv) -> [u8; 12] {
    let mut iv = implicit_iv.iv_bytes;
    // let first64 = iv.first_chunk_mut::<8>().unwrap();
    // *first64 = (u64::from_be_bytes(*first64) ^ u64::from_be_bytes(*packet_id)).to_be_bytes();
    for (iv_byte, packet_id_byte) in iv.iter_mut().zip(packet_id) {
        *iv_byte ^= *packet_id_byte;
    }
    iv
}

impl DataChannel {
    pub fn new(
        peer_id: [u8; 3],
        algorithm: Algorithm,
        encryption_epoch_key: EpochKey,
        decryption_epoch_key: EpochKey,
    ) -> Self {
        let encryption_key = encryption_epoch_key.derive_encryption_key().unwrap();
        let encryption_iv = encryption_epoch_key.derive_implicit_iv().unwrap();
        let decryption_key = decryption_epoch_key.derive_encryption_key().unwrap();
        let decryption_iv = decryption_epoch_key.derive_implicit_iv().unwrap();
        Self {
            peer_id,
            algorithm,
            encryption_epoch_key,
            encryption_key,
            encryption_iv,
            decryption_epoch_key,
            decryption_key,
            decryption_iv,
            next_packet_id: PacketCounter::new(algorithm.packets_per_epoch),
        }
    }

    /// Takes a `DataChannelPacketBuffer` with a plaintext payload, fills in the header, encrypts
    /// the payload and adds the authentication tag.
    pub fn encrypt_packet(&mut self, buffer: &mut DataChannelPacketBuffer) -> Result<(), Error> {
        if self.encryption_key.epoch < self.next_packet_id.epoch {
            while self.encryption_epoch_key.epoch < self.next_packet_id.epoch {
                self.encryption_epoch_key.advance_epoch()?;
            }
            self.encryption_key = self.encryption_epoch_key.derive_encryption_key()?;
            self.encryption_iv = self.encryption_epoch_key.derive_implicit_iv()?;
        }
        let packet_id = self.next_packet_id.get_packet_id();
        self.next_packet_id.increment();
        buffer.write_header(0, self.peer_id, packet_id);

        let iv = combine_iv(&packet_id, &self.encryption_iv);
        let mut cipher_ctx = CipherCtx::new()?;
        cipher_ctx.encrypt_init(
            Some((self.algorithm.cipher_ref)()),
            Some(&self.encryption_key.key_bytes),
            Some(&iv),
        )?;

        // Additional authenticated data.
        cipher_ctx.cipher_update(buffer.get_header(), None)?;

        // Encrypt the payload in place.
        let payload = buffer.get_payload_mut();
        cipher_ctx.cipher_update_inplace(payload, payload.len())?;
        cipher_ctx.cipher_final(&mut [])?;
        cipher_ctx.tag(buffer.get_tag_mut())?;

        Ok(())
    }

    /// Process an incoming data channel packet and return the decrypted payload.
    pub fn decrypt_packet<'a>(&mut self, packet: DataChannelPacket<'a>) -> Result<&'a [u8], Error> {
        let mut cipher_ctx = CipherCtx::new()?;
        let packet_epoch = packet.get_epoch();

        if self.decryption_key.epoch > packet_epoch {
            println!(
                "bad epoch: {}, own epoch: {}",
                packet_epoch, self.decryption_key.epoch
            );
            return Err(Error::Unknown("Bad epoch".to_string()));
        }

        if self.decryption_key.epoch < packet_epoch {
            while self.decryption_epoch_key.epoch < packet_epoch {
                self.decryption_epoch_key.advance_epoch()?;
            }
            self.decryption_key = self.decryption_epoch_key.derive_encryption_key()?;
            self.decryption_iv = self.decryption_epoch_key.derive_implicit_iv()?;
        }

        let iv = combine_iv(packet.get_packet_id(), &self.decryption_iv);
        cipher_ctx
            .decrypt_init(
                Some(Cipher::aes_256_gcm()),
                Some(&self.decryption_key.key_bytes),
                Some(&iv),
            )
            .unwrap();
        cipher_ctx.set_tag(packet.get_auth_tag()).unwrap();
        cipher_ctx.cipher_update(packet.get_additional_authenticated_data(), None)?;
        let payload = packet.take_payload();
        let payload_length = payload.len();
        cipher_ctx.cipher_update_inplace(payload, payload_length)?;
        cipher_ctx.cipher_final(&mut [])?;

        Ok(payload)
    }
}

#[cfg(test)]
mod test {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;

    use crate::Error;
    use crate::data_channel::data_channel::PacketCounter;
    use crate::data_channel::keys::{EncryptionKey, EpochKey, ImplicitIv};
    use crate::packets::{DataChannelPacket, DataChannelPacketBuffer, Opcode, Packet};

    use super::{AES_256_GCM, DataChannel, combine_iv};

    fn make_test_packet<'a>(
        storage: &'a mut Vec<u8>,
        epoch_key: &EpochKey,
        packet_counter: u64,
        plaintext_payload: &[u8],
    ) -> DataChannelPacket<'a> {
        let encryption_key = epoch_key.derive_encryption_key().unwrap();
        let implicit_iv = epoch_key.derive_implicit_iv().unwrap();
        let mut cipher_ctx = CipherCtx::new().unwrap();
        let iv = combine_iv(&packet_counter.to_be_bytes(), &implicit_iv);

        storage.clear();
        storage.push((Opcode::DataV2 as u8) << 3);
        storage.extend_from_slice(&[0, 0, 0]);
        storage.extend_from_slice(&packet_counter.to_be_bytes());

        cipher_ctx
            .encrypt_init(
                Some(Cipher::aes_256_gcm()),
                Some(&encryption_key.key_bytes),
                Some(&iv),
            )
            .unwrap();
        cipher_ctx.cipher_update(&storage, None).unwrap();

        let payload_start = storage.len();
        storage.extend_from_slice(plaintext_payload);
        cipher_ctx
            .cipher_update_inplace(&mut storage[payload_start..], plaintext_payload.len())
            .unwrap();
        cipher_ctx.cipher_final(&mut []).unwrap();

        let tag_start = storage.len();
        storage.extend_from_slice(&[0; 16]);
        cipher_ctx.tag(&mut storage[tag_start..]).unwrap();

        if let Packet::Data(p) = Packet::parse(storage).unwrap() {
            return p;
        } else {
            panic!();
        }
    }

    fn decrypt_payload(
        packet_buffer: &mut DataChannelPacketBuffer,
        key: &EncryptionKey,
        iv: &ImplicitIv,
    ) -> Result<Vec<u8>, Error> {
        let mut cipher_ctx = CipherCtx::new().unwrap();
        let (_, packet_id) = packet_buffer.get_header().split_last_chunk::<8>().unwrap();
        let iv = combine_iv(packet_id, iv);
        let mut payload = packet_buffer.get_payload_mut().to_vec();
        cipher_ctx.decrypt_init(Some(Cipher::aes_256_gcm()), Some(&key.key_bytes), Some(&iv))?;
        cipher_ctx.set_tag(packet_buffer.get_tag_mut())?;
        cipher_ctx.cipher_update(packet_buffer.get_header(), None)?;
        let length = payload.len();
        cipher_ctx.cipher_update_inplace(&mut payload, length)?;
        cipher_ctx.cipher_final(&mut [])?;

        Ok(payload)
    }

    fn get_expected_header(key_id: u8, peer_id: [u8; 3], packet_id: [u8; 8]) -> [u8; 12] {
        let mut out = [0; 12];
        out[0] = ((Opcode::DataV2 as u8) << 3) | key_id;
        out[1..4].copy_from_slice(&peer_id);
        out[4..].copy_from_slice(&packet_id);
        out
    }

    #[test]
    fn packet_counter_correctly_formats_packet_id() {
        let mut packet_counter = PacketCounter {
            epoch: 1,
            epoch_counter: 1,
            packets_per_epoch: 1 << 24,
        };
        assert_eq!(packet_counter.get_packet_id(), [0, 1, 0, 0, 0, 0, 0, 1]);

        packet_counter.epoch = 23;
        packet_counter.epoch_counter = 1 << 23;
        assert_eq!(
            packet_counter.get_packet_id(),
            [0, 23, 0, 0, 0, 1 << 7, 0, 0]
        );

        packet_counter.epoch = (1 << 14) + 1;
        packet_counter.epoch_counter = 1 << 23;
        assert_eq!(
            packet_counter.get_packet_id(),
            [1 << 6, 1, 0, 0, 0, 1 << 7, 0, 0]
        );
    }

    #[test]
    fn packet_counter_correctly_increments() {
        let mut packet_counter = PacketCounter {
            epoch: 1,
            epoch_counter: 0,
            packets_per_epoch: 1 << 24,
        };

        packet_counter.increment();
        assert_eq!(packet_counter.epoch_counter, 1);
        packet_counter.increment();
        assert_eq!(packet_counter.epoch_counter, 2);
        packet_counter.increment();
        assert_eq!(packet_counter.epoch_counter, 3);
    }

    #[test]
    fn packet_counter_wraps_epoch() {
        let mut packet_counter = PacketCounter {
            epoch: 3,
            epoch_counter: 1 << 24,
            packets_per_epoch: 1 << 24,
        };

        packet_counter.increment();
        assert_eq!(packet_counter.epoch, 4);
        assert_eq!(packet_counter.epoch_counter, 1);
    }

    #[test]
    fn decrypt_first_epoch_packets() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let mut storage = Vec::new();
        let test_packet = make_test_packet(
            &mut storage,
            &epoch_key_decrypt,
            0x0001000000000000,
            b"Tut das Not dass das hier so rumoxidiert?",
        );
        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);
        assert_eq!(
            data_channel.decrypt_packet(test_packet).unwrap(),
            b"Tut das Not dass das hier so rumoxidiert?"
        );
    }

    #[test]
    fn decrypt_packet_advances_epoch() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);

        let mut epoch_key_decrypt_copy = EpochKey::from_key_material(&[0; 32]);
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        let mut storage = Vec::new();
        let test_packet = make_test_packet(
            &mut storage,
            &epoch_key_decrypt_copy,
            0x0004000000000001,
            b"Tut das Not dass das hier so rumoxidiert?",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);
        assert_eq!(
            data_channel.decrypt_packet(test_packet).unwrap(),
            b"Tut das Not dass das hier so rumoxidiert?"
        );
    }

    #[test]
    fn decrypt_packet_fails_for_previous_epoch_packet() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);

        let mut epoch_key_decrypt_copy = EpochKey::from_key_material(&[0; 32]);
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        let mut storage1 = Vec::new();
        let test_packet_epoch_2 = make_test_packet(
            &mut storage1,
            &epoch_key_decrypt_copy,
            0x0002000000000001,
            b"Epoch 2",
        );

        epoch_key_decrypt_copy.advance_epoch().unwrap();
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        let mut storage2 = Vec::new();
        let test_packet_epoch_5 = make_test_packet(
            &mut storage2,
            &epoch_key_decrypt_copy,
            0x0005000000000001,
            b"Epoch 5",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);
        assert_eq!(
            data_channel.decrypt_packet(test_packet_epoch_5).unwrap(),
            b"Epoch 5",
        );
        assert!(data_channel.decrypt_packet(test_packet_epoch_2).is_err());
    }

    #[test]
    fn decrypt_packet_fails_if_auth_tag_is_tampered() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let mut storage = Vec::new();
        let test_packet = make_test_packet(
            &mut storage,
            &epoch_key_decrypt,
            0x0001000000000000,
            b"Tut das Not dass das hier so rumoxidiert?",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);

        // Check that manipulating any byte in the authentication tag causes decryption to fail.
        let raw_packet = test_packet.to_vec();
        let auth_tag_start = raw_packet.len() - 16;
        let auth_tag_end = raw_packet.len();
        for index in auth_tag_start..auth_tag_end {
            let mut raw_tampered_packet = raw_packet.clone();
            raw_tampered_packet[index] ^= 1;
            let tampered_packet = DataChannelPacket::from_raw_bytes(&mut raw_tampered_packet);
            assert!(data_channel.decrypt_packet(tampered_packet).is_err());
        }
    }

    #[test]
    fn decrypt_packet_fails_if_additional_data_is_tampered() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let mut storage = Vec::new();
        let test_packet = make_test_packet(
            &mut storage,
            &epoch_key_decrypt,
            0x0001000000000001,
            b"Tut das Not dass das hier so rumoxidiert?",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);

        // Check that manipulating any byte before the payload causes decryption to fail.
        let raw_packet = test_packet.to_vec();
        for index in 0..12 {
            let mut raw_tampered_packet = raw_packet.clone();
            raw_tampered_packet[index] ^= 1;
            let tampered_packet = DataChannelPacket::from_raw_bytes(&mut raw_tampered_packet);
            assert!(data_channel.decrypt_packet(tampered_packet).is_err());
        }
    }

    #[test]
    fn decrypt_packet_fails_if_payload_is_tampered() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let mut storage = Vec::new();
        let test_packet = make_test_packet(
            &mut storage,
            &epoch_key_decrypt,
            0x0001000000000001,
            b"Tut das Not dass das hier so rumoxidiert?",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);

        // Check that manipulating any byte in the payload causes decryption to fail.
        let raw_packet = test_packet.to_vec();
        let payload_start = 12;
        let payload_end = raw_packet.len() - 16;
        for index in payload_start..payload_end {
            let mut raw_tampered_packet = raw_packet.clone();
            raw_tampered_packet[index] ^= 1;
            let tampered_packet = DataChannelPacket::from_raw_bytes(&mut raw_tampered_packet);
            assert!(data_channel.decrypt_packet(tampered_packet).is_err());
        }
    }

    #[test]
    fn encrypt_first_epoch_packet() {
        let mut storage = [0u8; 1000];
        let mut packet_buffer = DataChannelPacketBuffer::from_payload(
            &mut storage,
            b"Tut das Not dass das hier so rumoxidiert?",
        );
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let encryption_key = epoch_key_encrypt.derive_encryption_key().unwrap();
        let iv = epoch_key_encrypt.derive_implicit_iv().unwrap();
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);
        data_channel.encrypt_packet(&mut packet_buffer).unwrap();

        let expected_header = get_expected_header(0, [0, 0, 0], [0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(packet_buffer.get_header(), &expected_header);
        assert_eq!(
            decrypt_payload(&mut packet_buffer, &encryption_key, &iv).unwrap(),
            b"Tut das Not dass das hier so rumoxidiert?"
        );
    }

    #[test]
    fn encrypt_packet_advances_epoch() {
        let mut storage = [0u8; 1000];
        let mut packet_buffer =
            DataChannelPacketBuffer::from_payload(&mut storage, b"Der geht ja noch!");
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let mut epoch_key_encrypt_copy = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);
        data_channel.next_packet_id.epoch_counter = 1 << 24;

        let encryption_key = epoch_key_encrypt_copy.derive_encryption_key().unwrap();
        let iv = epoch_key_encrypt_copy.derive_implicit_iv().unwrap();
        data_channel.encrypt_packet(&mut packet_buffer).unwrap();

        let expected_header = get_expected_header(0, [0, 0, 0], [0, 1, 0, 0, 1, 0, 0, 0]);
        assert_eq!(packet_buffer.get_header(), &expected_header);
        assert_eq!(
            decrypt_payload(&mut packet_buffer, &encryption_key, &iv).unwrap(),
            b"Der geht ja noch!"
        );

        let mut packet_buffer = DataChannelPacketBuffer::from_payload(
            &mut storage,
            b"Tut das Not dass das hier so rumoxidiert?",
        );
        epoch_key_encrypt_copy.advance_epoch().unwrap();
        let encryption_key = epoch_key_encrypt_copy.derive_encryption_key().unwrap();
        let iv = epoch_key_encrypt_copy.derive_implicit_iv().unwrap();
        data_channel.encrypt_packet(&mut packet_buffer).unwrap();

        let expected_header = get_expected_header(0, [0, 0, 0], [0, 2, 0, 0, 0, 0, 0, 1]);
        assert_eq!(packet_buffer.get_header(), &expected_header);
        assert_eq!(
            decrypt_payload(&mut packet_buffer, &encryption_key, &iv).unwrap(),
            b"Tut das Not dass das hier so rumoxidiert?"
        );
    }

    #[test]
    fn data_channels_can_talk_to_each_other() {
        let mut storage = [0u8; 1000];
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let epoch_key_encrypt_copy = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt_copy = EpochKey::from_key_material(&[0; 32]);
        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);
        let mut data_channel_peer = DataChannel::new(
            [0, 0, 0],
            AES_256_GCM,
            epoch_key_decrypt_copy,
            epoch_key_encrypt_copy,
        );

        let mut packet_buffer = DataChannelPacketBuffer::from_payload(
            &mut storage,
            b"Tut das Not dass das hier so rumoxidiert?",
        );
        data_channel.encrypt_packet(&mut packet_buffer).unwrap();
        let mut raw_packet = packet_buffer.as_slice().to_vec();
        let packet_to_peer = match Packet::parse(&mut raw_packet).unwrap() {
            Packet::Data(p) => p,
            _ => panic!(),
        };
        let payload = data_channel_peer.decrypt_packet(packet_to_peer).unwrap();
        assert_eq!(payload, b"Tut das Not dass das hier so rumoxidiert?");

        let mut packet_buffer = DataChannelPacketBuffer::from_payload(
            &mut storage,
            b"Tut das Not dass das hier so rumoxidiert?",
        );
        data_channel_peer
            .encrypt_packet(&mut packet_buffer)
            .unwrap();
        let mut raw_packet = packet_buffer.as_slice().to_vec();
        let packet_from_peer = match Packet::parse(&mut raw_packet).unwrap() {
            Packet::Data(p) => p,
            _ => panic!(),
        };
        let payload = data_channel.decrypt_packet(packet_from_peer).unwrap();
        assert_eq!(payload, b"Tut das Not dass das hier so rumoxidiert?");
    }
}
