//! Contains the OpenVPN key derivation functions.

use std::convert::From;
use std::ops::Drop;

use openssl::error::ErrorStack;
use openssl::kdf::{HkdfMode, hkdf};
use openssl::md::Md;

#[derive(Debug)]
pub enum Error {
    InvalidArgument,
    SslError(ErrorStack),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Self::InvalidArgument => write!(formatter, "Invalid argument"),
            Self::SslError(e) => write!(formatter, "SSL Error: {}", e),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Self::SslError(e)
    }
}

impl std::error::Error for Error {}

pub struct DataChannelKeys {
    pub client_to_server: EpochKey,
    pub server_to_client: EpochKey,
}

/// OpenVPN key derivation function, based on the TLS-Exporter in TLS 1.3.
/// Fills the slice given in `out` with key material.
///
/// This function runs HKDF-Expand with the following struct as input:
/// ```
/// label {
///     output_length: u16,
///     prefixed_label: string,
///     context: bytes,
/// }
/// ```
/// where `prefixed_label` is the string `"ovpn " + label`, prefixed by a one-byte length field and
/// `context` is an array of bytes, likewise with a one-byte length field.
fn ovpn_expand_label(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() == 0 {
        return Ok(());
    }
    if out.len() > u16::max_value() as usize || label.len() > 250 || context.len() > 255 {
        return Err(Error::InvalidArgument);
    }
    let mut hkdf_input = Vec::<u8>::new();
    hkdf_input.extend_from_slice(&(out.len() as u16).to_be_bytes());

    let label_prefix = b"ovpn ";
    let prefixed_label_length = label_prefix.len() + label.len();
    hkdf_input.push(prefixed_label_length as u8);
    hkdf_input.extend_from_slice(label_prefix);
    hkdf_input.extend_from_slice(label);

    hkdf_input.push(context.len() as u8);
    hkdf_input.extend_from_slice(context);

    hkdf(
        Md::sha256(),
        secret,
        None,
        Some(&hkdf_input),
        HkdfMode::ExpandOnly,
        None,
        out,
    )?;
    Ok(())
}

/// A key-derivation key. With 64-bit packet IDs, data channels may send a large number of packets
/// before a key renegotiation happens, so the symmetric encryption keys need to be regularly
/// changed. An epoch key is used to derive an AEAD key, an implicit IV and the next epoch key. This
/// is illustrated in the following diagram: `E_i` are epoch keys, `K_i` are AEAD keys and arrows
/// indicate derivation.
///
/// ```
///     Control Channel TLS session --> E_1 --> K_1
///                                      |
///                                      V
///                                     E_2 --> K_2
///                                      |
///                                      V
///                                     E_3 --> K_3
/// ```
pub struct EpochKey {
    pub epoch: u16,
    key_bytes: [u8; 32],
}

impl Drop for EpochKey {
    fn drop(&mut self) {
        // Securely erase the key material when this goes out of scope.
        unsafe { memsec::memzero(self.key_bytes.as_mut_ptr(), self.key_bytes.len()) }
    }
}

/// A symmetric encryption (AEAD) key for encrypting and authenticating data channel packets.
pub struct EncryptionKey {
    pub epoch: u16,
    pub key_bytes: [u8; 32],
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // Securely erase the key material when this goes out of scope.
        unsafe { memsec::memzero(self.key_bytes.as_mut_ptr(), self.key_bytes.len()) }
    }
}

/// This value is combined with the 64-bit packet ID to generate an IV/nonce for the AEAD algorithm.
pub struct ImplicitIv {
    pub epoch: u16,
    pub iv_bytes: [u8; 12],
}

impl EpochKey {
    pub fn from_key_material(key_bytes: &[u8; 32]) -> Self {
        Self {
            epoch: 1,
            key_bytes: *key_bytes,
        }
    }

    /// Replace the epoch key with the next epoch key. The existing key material is overwritten.
    pub fn advance_epoch(&mut self) -> Result<(), Error> {
        let mut new_key_bytes: [u8; 32] = [0; _];
        ovpn_expand_label(&self.key_bytes, b"datakey upd", b"", &mut new_key_bytes)?;
        self.epoch += 1;
        self.key_bytes = new_key_bytes;
        unsafe {
            memsec::memzero(new_key_bytes.as_mut_ptr(), new_key_bytes.len());
        }
        Ok(())
    }

    /// Derive the encryption key for this epoch.
    pub fn derive_encryption_key(&self) -> Result<EncryptionKey, Error> {
        let mut key = EncryptionKey {
            epoch: self.epoch,
            key_bytes: [0; _],
        };
        ovpn_expand_label(&self.key_bytes, b"data_key", b"", &mut key.key_bytes)?;
        Ok(key)
    }

    /// Derive the implicit IV for this epoch.
    pub fn derive_implicit_iv(&self) -> Result<ImplicitIv, Error> {
        let mut iv = ImplicitIv {
            epoch: self.epoch,
            iv_bytes: [0; _],
        };
        ovpn_expand_label(&self.key_bytes, b"data_iv", b"", &mut iv.iv_bytes)?;
        Ok(iv)
    }
}

#[cfg(test)]
mod test {
    use crate::data_channel::EpochKey;

    use super::ovpn_expand_label;

    #[test]
    fn kat_ovpn_expand_label() {
        // Test vector from OpenVPN unit tests.
        let secret: [u8; _] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let label = b"unit test";
        let mut out: [u8; 16] = [0; _];
        ovpn_expand_label(&secret, label, b"", &mut out).unwrap();
        let out_expected: [u8; 16] = [
            0x18, 0x5e, 0xaa, 0x1c, 0x7f, 0x22, 0x8a, 0xb8, 0xeb, 0x29, 0x77, 0x32, 0x14, 0xd9,
            0x20, 0x46,
        ];
        assert_eq!(out, out_expected);
    }

    #[test]
    fn test_deriving_data_keys() {
        // Results extracted from OpenVPN logs.
        let epoch_key_bytes = [
            0xd1, 0x89, 0x60, 0xcb, 0x5b, 0xf1, 0x1c, 0x70, 0x09, 0x99, 0xec, 0x6f, 0x1c, 0xbe,
            0x00, 0x40, 0x7f, 0x26, 0xb7, 0xac, 0xe4, 0x7a, 0xb9, 0x63, 0x41, 0x9a, 0xe4, 0x09,
            0xd8, 0xed, 0xb9, 0xfb,
        ];
        let mut epoch_key = EpochKey::from_key_material(&epoch_key_bytes);
        let expected_data_keys = [
            [
                0xc4, 0xe6, 0xc8, 0x46, 0x7f, 0x67, 0x45, 0x4c, 0xc2, 0xdd, 0x08, 0x73, 0x53, 0x4b,
                0x93, 0xd8, 0x1f, 0x07, 0x3f, 0x3a, 0x82, 0x17, 0xe4, 0x19, 0xbd, 0xc9, 0x55, 0x26,
                0x26, 0x50, 0xed, 0x2d,
            ],
            [
                0xbd, 0x21, 0x60, 0x73, 0xec, 0xac, 0x56, 0xe6, 0x4a, 0x15, 0x05, 0xb3, 0x56, 0xc5,
                0xe8, 0x35, 0x11, 0x79, 0x1e, 0x44, 0x36, 0x0e, 0xeb, 0x22, 0xc3, 0x9d, 0x86, 0xfe,
                0x42, 0x2e, 0x3f, 0x0a,
            ],
            [
                0x53, 0xdd, 0xf8, 0xc0, 0x03, 0x58, 0x26, 0xbb, 0x5b, 0x9c, 0xe6, 0xd6, 0x5b, 0x80,
                0xaa, 0x98, 0xc6, 0xcc, 0x46, 0x04, 0x8b, 0xc7, 0x38, 0xc1, 0xf8, 0xb4, 0x4a, 0xde,
                0x34, 0x87, 0xfa, 0x58,
            ],
        ];
        for (i, expected_key) in expected_data_keys.iter().enumerate() {
            println!("Testing data key {}", i + 1);
            let data_key = epoch_key.derive_encryption_key().unwrap();
            assert_eq!(data_key.epoch, (i + 1) as u16);
            assert_eq!(data_key.key_bytes, *expected_key);
            epoch_key.advance_epoch().unwrap();
        }
    }
}
