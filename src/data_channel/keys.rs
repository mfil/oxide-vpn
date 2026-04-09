//! Contains the OpenVPN key derivation functions.

use std::convert::From;
use std::marker::PhantomData;
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

/// Marker trait for the direction of keys. This allows compile-time checks that keys are only used
/// for the appropriate direction.
pub trait Direction {}

/// Marks a key for the client-to-server direction.
pub struct ClientToServer();
impl Direction for ClientToServer {}
/// Marks a key for the server-to-client direction.
pub struct ServerToClient();
impl Direction for ServerToClient {}

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
pub struct EpochKey<D: Direction> {
    pub epoch: u16,
    key_bytes: [u8; 32],
    _phantom_data: PhantomData<D>,
}

impl<D: Direction> Drop for EpochKey<D> {
    fn drop(&mut self) {
        // Securely erase the key material when this goes out of scope.
        unsafe { memsec::memzero(self.key_bytes.as_mut_ptr(), self.key_bytes.len()) }
    }
}

/// A symmetric encryption (AEAD) key for encrypting and authenticating data channel packets.
pub struct EncryptionKey<D: Direction> {
    pub epoch: u16,
    pub key_bytes: [u8; 32],
    _phantom_data: PhantomData<D>,
}

impl<D: Direction> Drop for EncryptionKey<D> {
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

impl<D: Direction> EpochKey<D> {
    pub fn from_key_material(key_bytes: &[u8; 32]) -> Self {
        Self {
            epoch: 1,
            key_bytes: *key_bytes,
            _phantom_data: PhantomData {},
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
    pub fn derive_encryption_key(&self) -> Result<EncryptionKey<D>, Error> {
        let mut key = EncryptionKey {
            epoch: self.epoch,
            key_bytes: [0; _],
            _phantom_data: PhantomData {},
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
}
