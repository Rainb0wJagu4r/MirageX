use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{CryptoRng, RngCore};

use crate::crypto::CryptoError;

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

/// Generates a cryptographically random 12-byte nonce.
pub fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext using AES-256-GCM with associated data (AAD).
/// Returns ciphertext_with_tag (the 16-byte tag is appended).
pub fn encrypt_aes_gcm(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidLength { expected: KEY_SIZE, got: key.len() })?;

    let nonce_arr = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce_arr, payload)
        .map_err(|_| CryptoError::AeadAuthFailed)?;

    Ok(ciphertext_with_tag)
}

/// Decrypts ciphertext (which has the 16-byte GCM tag appended) using AES-256-GCM with associated data (AAD).
pub fn decrypt_aes_gcm(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(CryptoError::AeadAuthFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidLength { expected: KEY_SIZE, got: key.len() })?;

    let nonce_arr = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce_arr, payload)
        .map_err(|_| CryptoError::AeadAuthFailed)?;

    Ok(plaintext)
}
