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

/// Generates a deterministic 12-byte nonce according to NIST SP 800-38D (4-byte fixed salt/prefix + 8-byte big-endian counter).
/// Guarantees zero nonce reuse or collision across chunks under the same DEK.
pub fn generate_chunk_nonce(nonce_prefix: [u8; 4], chunk_index: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..4].copy_from_slice(&nonce_prefix);
    nonce[4..12].copy_from_slice(&chunk_index.to_be_bytes());
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
