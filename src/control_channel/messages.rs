//! Messages to send through the TLS session established via the control channel.

use bitflags::bitflags;
use rand::CryptoRng;
use std::fmt::Write;

bitflags! {
    pub struct IvProto: u16 {
        const EMPTY = 0;
        const SUPPORT_DATA_V2 = 1 << 1;
        const EXPECT_PUSH_REPLY = 1 << 2;
        const CAN_DO_KEY_MAT_EXPORT = 1 << 3;
        const DYNAMIC_TLS_CRYPT = 1 << 9;
        const EPOCH_DATA_FORMAT = 1 << 10;
    }
}

/// Allows the peers to exchange information about each other's capabilities.
/// Sent through the [`ControlChannel`] TLS session.
///
/// Currently implementing only required fields.
pub struct PeerInfo<'a> {
    /// Indicates supported features.
    pub iv_proto: IvProto,
    /// List of supported data channel ciphers, separated by ':'.
    pub iv_ciphers: &'a str,
}

impl<'a> PeerInfo<'a> {
    pub fn to_buffer<R: CryptoRng>(&self, rng: &mut R, buffer: &mut [u8]) -> usize {
        // The peer info is technically part of a key exchange message that does not actually
        // exchange keys anymore in modern OpenVPN. It still should contain some random bytes so
        // that if we accidentally talk to an old version of OpenVPN, it doesn't send out data with
        // weak encryption.
        let (null, rest) = buffer.split_at_mut(4);
        null.fill(0);
        let (key_method, rest) = rest.split_at_mut(1);
        key_method[0] = 2;
        let (random, rest) = rest.split_at_mut(112);
        rng.fill_bytes(random);
        let (occ_string_len, rest) = rest.split_at_mut(2);
        occ_string_len[0] = 0;
        occ_string_len[1] = 1;
        let (occ_string, rest) = rest.split_at_mut(1);
        occ_string[0] = b'\0';
        let (username_string_len, rest) = rest.split_at_mut(2);
        username_string_len[0] = 0;
        username_string_len[1] = 1;
        let (username_string, rest) = rest.split_at_mut(1);
        username_string[0] = b'\0';
        let (password_string_len, rest) = rest.split_at_mut(2);
        password_string_len[0] = 0;
        password_string_len[1] = 1;
        let (password_string, rest) = rest.split_at_mut(1);
        password_string[0] = b'\0';
        let peer_info_string = self.peer_info_string();
        let peer_info_bytes = peer_info_string.as_bytes();
        let (peer_info_len, rest) = rest.split_at_mut(2);
        peer_info_len[0] = (peer_info_bytes.len() >> 8) as u8;
        peer_info_len[1] = peer_info_bytes.len() as u8;
        let (peer_info, _) = rest.split_at_mut(peer_info_bytes.len());
        peer_info.copy_from_slice(&peer_info_bytes);

        4 + 1 + 112 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + peer_info_bytes.len()
    }

    fn peer_info_string(&self) -> String {
        let mut out = String::new();
        write!(
            &mut out,
            "IV_PROTO={}\nIV_CIPHERS={}\n",
            self.iv_proto.bits(),
            self.iv_ciphers,
        )
        .unwrap();
        out
    }
}
