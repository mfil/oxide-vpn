use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

use super::keys::{EncryptionKey, EpochKey, ImplicitIv};
use crate::packets::DataChannelPacket;

struct PacketCounter {
    pub epoch: u16,
    pub epoch_counter: u64,
    pub packets_per_epoch: u64,
}

impl PacketCounter {
    fn new(packets_per_epoch: u64) -> Self {
        Self {
            epoch: 1,
            epoch_counter: 0,
            packets_per_epoch,
        }
    }

    fn get_packet_id(&self) -> [u8; 8] {
        let mut packet_id = self.epoch_counter.to_be_bytes();
        packet_id[0] = (self.epoch_counter >> 8) as u8;
        packet_id[1] = self.epoch_counter as u8;
        packet_id
    }

    fn increment(&mut self) {
        if self.epoch_counter == self.packets_per_epoch {
            self.epoch += 1;
            self.epoch_counter = 0;
        } else {
            self.epoch_counter += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub struct Algorithm {
    packets_per_epoch: u64,
}

pub const AES_256_GCM: Algorithm = Algorithm {
    packets_per_epoch: 1 << 24,
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

    pub fn decrypt_packet(&mut self, packet: DataChannelPacket) -> Option<Vec<u8>> {
        let mut cipher_ctx = CipherCtx::new().unwrap();
        let packet_epoch = packet.get_epoch();

        if self.decryption_key.epoch > packet_epoch {
            return None;
        }

        if self.decryption_key.epoch < packet_epoch {
            while self.decryption_epoch_key.epoch < packet_epoch {
                self.decryption_epoch_key.advance_epoch().unwrap();
            }
            self.decryption_key = self.decryption_epoch_key.derive_encryption_key().unwrap();
            self.decryption_iv = self.decryption_epoch_key.derive_implicit_iv().unwrap();
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
        let mut payload = packet.get_payload().to_vec();
        let payload_length = payload.len();
        cipher_ctx
            .cipher_update(packet.get_additional_authenticated_data(), None)
            .unwrap();
        cipher_ctx
            .cipher_update_inplace(&mut payload, payload_length)
            .unwrap();
        if let Err(e) = cipher_ctx.cipher_final(&mut []) {
            println!("{}", e);
            return None;
        }

        Some(payload)
    }
}

#[cfg(test)]
mod test {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;

    use crate::data_channel::keys::EpochKey;
    use crate::packets::{DataChannelPacket, Opcode};

    use super::{AES_256_GCM, DataChannel, combine_iv};

    fn make_test_packet(
        epoch_key: &EpochKey,
        packet_counter: u64,
        plaintext_payload: &[u8],
    ) -> DataChannelPacket {
        let encryption_key = epoch_key.derive_encryption_key().unwrap();
        let implicit_iv = epoch_key.derive_implicit_iv().unwrap();
        let mut cipher_ctx = CipherCtx::new().unwrap();
        let iv = combine_iv(&packet_counter.to_be_bytes(), &implicit_iv);

        let mut packet = Vec::new();
        packet.push((Opcode::DataV2 as u8) << 3);
        packet.extend_from_slice(&[0, 0, 0]);
        packet.extend_from_slice(&packet_counter.to_be_bytes());

        cipher_ctx
            .encrypt_init(
                Some(Cipher::aes_256_gcm()),
                Some(&encryption_key.key_bytes),
                Some(&iv),
            )
            .unwrap();
        cipher_ctx.cipher_update(&packet, None).unwrap();

        let payload_start = packet.len();
        packet.extend_from_slice(plaintext_payload);
        cipher_ctx
            .cipher_update_inplace(&mut packet[payload_start..], plaintext_payload.len())
            .unwrap();
        cipher_ctx.cipher_final(&mut []).unwrap();

        let tag_start = packet.len();
        packet.extend_from_slice(&[0; 16]);
        cipher_ctx.tag(&mut packet[tag_start..]).unwrap();

        DataChannelPacket {
            opcode: Opcode::DataV2,
            key_id: 0,
            packet_data: packet,
        }
    }

    #[test]
    fn decrypt_first_epoch_packets() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let test_packet = make_test_packet(
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
        let test_packet = make_test_packet(
            &epoch_key_decrypt_copy,
            0x0004000000000000,
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
        let test_packet_epoch_2 =
            make_test_packet(&epoch_key_decrypt_copy, 0x0002000000000000, b"Epoch 2");

        epoch_key_decrypt_copy.advance_epoch().unwrap();
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        epoch_key_decrypt_copy.advance_epoch().unwrap();
        let test_packet_epoch_5 =
            make_test_packet(&epoch_key_decrypt_copy, 0x0005000000000000, b"Epoch 5");

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);
        assert_eq!(
            data_channel.decrypt_packet(test_packet_epoch_5).unwrap(),
            b"Epoch 5",
        );
        assert!(data_channel.decrypt_packet(test_packet_epoch_2).is_none());
    }

    #[test]
    fn decrypt_packet_fails_if_auth_tag_is_tampered() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let test_packet = make_test_packet(
            &epoch_key_decrypt,
            0x0001000000000000,
            b"Tut das Not dass das hier so rumoxidiert?",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);

        // Check that manipulating any byte in the authentication tag causes decryption to fail.
        let auth_tag_start = test_packet.packet_data.len() - 16;
        let auth_tag_end = test_packet.packet_data.len();
        for index in auth_tag_start..auth_tag_end {
            let mut packet = test_packet.clone();
            packet.packet_data[index] ^= 1;
            assert!(data_channel.decrypt_packet(packet).is_none());
        }
    }

    #[test]
    fn decrypt_packet_fails_if_additional_data_is_tampered() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let test_packet = make_test_packet(
            &epoch_key_decrypt,
            0x0001000000000000,
            b"Tut das Not dass das hier so rumoxidiert?",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);

        // Check that manipulating any byte before the payload causes decryption to fail.
        for index in 0..12 {
            let mut packet = test_packet.clone();
            packet.packet_data[index] ^= 1;
            assert!(data_channel.decrypt_packet(packet).is_none());
        }
    }

    #[test]
    fn decrypt_packet_fails_if_payload_is_tampered() {
        let epoch_key_encrypt = EpochKey::from_key_material(&[23; 32]);
        let epoch_key_decrypt = EpochKey::from_key_material(&[0; 32]);
        let test_packet = make_test_packet(
            &epoch_key_decrypt,
            0x0001000000000000,
            b"Tut das Not dass das hier so rumoxidiert?",
        );

        let mut data_channel =
            DataChannel::new([0, 0, 0], AES_256_GCM, epoch_key_encrypt, epoch_key_decrypt);

        // Check that manipulating any byte in the payload causes decryption to fail.
        let payload_start = 12;
        let payload_end = test_packet.packet_data.len() - 16;
        for index in payload_start..payload_end {
            let mut packet = test_packet.clone();
            packet.packet_data[index] ^= 1;
            assert!(data_channel.decrypt_packet(packet).is_none());
        }
    }
}
