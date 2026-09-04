use std::time::SystemTime;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::aead::{decrypt_aes_gcm, encrypt_aes_gcm, generate_nonce, NONCE_SIZE};
use crate::wraith::WraithError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub original_filename: String,
    pub original_size: u64,
    pub sha256_hash: [u8; 32],
    pub created_at: u64,
    pub total_chunks: u64,
}

impl Manifest {
    pub fn new(original_filename: String, original_size: u64, sha256_hash: [u8; 32], total_chunks: u64) -> Self {
        let created_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            original_filename,
            original_size,
            sha256_hash,
            created_at,
            total_chunks,
        }
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        manifest_key: &[u8; 32],
        container_uuid: &[u8; 16],
        rng: &mut R,
    ) -> Result<Vec<u8>, WraithError> {
        let json_bytes = serde_json::to_vec(self)
            .map_err(|_| WraithError::ManifestAuthFailed)?;

        let nonce = generate_nonce(rng);
        let ciphertext_with_tag = encrypt_aes_gcm(manifest_key, &nonce, &json_bytes, container_uuid)?;

        // Output format: Nonce (12B) || CiphertextWithTag (len + 16B)
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext_with_tag.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext_with_tag);

        Ok(out)
    }

    pub fn decrypt(
        encrypted_data: &[u8],
        manifest_key: &[u8; 32],
        container_uuid: &[u8; 16],
    ) -> Result<Self, WraithError> {
        if encrypted_data.len() < NONCE_SIZE + 16 {
            return Err(WraithError::ManifestAuthFailed);
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&encrypted_data[..NONCE_SIZE]);
        let ciphertext_with_tag = &encrypted_data[NONCE_SIZE..];

        let plaintext = decrypt_aes_gcm(manifest_key, &nonce, ciphertext_with_tag, container_uuid)
            .map_err(|_| WraithError::ManifestAuthFailed)?;

        let manifest = serde_json::from_slice(&plaintext)
            .map_err(|_| WraithError::ManifestAuthFailed)?;

        Ok(manifest)
    }
}
