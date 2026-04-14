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
        cipher_ctx.cipher_final(&mut []).unwrap();
        Some(payload)
    }
}
