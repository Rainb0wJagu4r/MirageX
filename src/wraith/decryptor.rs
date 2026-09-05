use std::io::{Read, Write};
use std::time::Instant;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::{
    aead::{decrypt_aes_gcm, NONCE_SIZE, TAG_SIZE},
    kdf::{derive_master_keys, derive_password_key, derive_pqc_wrap_key, DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST},
    kem::pqc_decapsulate,
};
use crate::wraith::{
    header::WraithHeader,
    manifest::Manifest,
    ProgressReport, WraithError,
};

pub const MAX_WRAPPED_KEY_LEN: usize = 8 * 1024;              // 8 KiB max
pub const MAX_CHUNK_PAYLOAD_LEN: usize = 256 * 1024 * 1024;  // 256 MiB max
pub const MAX_MANIFEST_LEN: usize = 64 * 1024;                // 64 KiB max

pub struct DecryptOptions {
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
}

impl Default for DecryptOptions {
    fn default() -> Self {
        Self {
            argon2_m_cost: DEFAULT_ARGON2_M_COST,
            argon2_t_cost: DEFAULT_ARGON2_T_COST,
            argon2_p_cost: DEFAULT_ARGON2_P_COST,
        }
    }
}

/// Decrypts a WRAITH v4 container from an input stream to an output stream, verifying cryptographic integrity.
pub fn decrypt_stream<R: Read, W: Write, F: FnMut(ProgressReport)>(
    mut reader: R,
    mut writer: W,
    password: &[u8],
    _options: DecryptOptions,
    mut progress_callback: F,
) -> Result<Manifest, WraithError> {
    let start_time = Instant::now();

    // 1. Read & Validate Header
    let header = WraithHeader::read_from(&mut reader)?;
    let header_bytes = header.to_bytes();

    // 2. Read PQC Envelope (Enforcing strict bounds against allocation bombs)
    let mut u32_buf = [0u8; 4];
    reader.read_exact(&mut u32_buf)?;
    let pqc_ct_len = u32::from_be_bytes(u32_buf) as usize;

    // Validate pqc_ct_len strictly against expected suite ciphertext size (NIST FIPS 203)
    if pqc_ct_len != header.suite.ciphertext_size() {
        return Err(WraithError::InvalidContainer);
    }

    let mut pqc_ct = vec![0u8; pqc_ct_len];
    reader.read_exact(&mut pqc_ct)?;

    reader.read_exact(&mut u32_buf)?;
    let wrapped_len = u32::from_be_bytes(u32_buf) as usize;
    if wrapped_len < NONCE_SIZE + TAG_SIZE || (wrapped_len - NONCE_SIZE) > MAX_WRAPPED_KEY_LEN {
        return Err(WraithError::InvalidContainer);
    }

    let mut wrap_nonce = [0u8; NONCE_SIZE];
    reader.read_exact(&mut wrap_nonce)?;

    let mut wrapped_decaps_key = vec![0u8; wrapped_len - NONCE_SIZE];
    reader.read_exact(&mut wrapped_decaps_key)?;

    // 3. Derive Password Key via Argon2id using parameters embedded in container header
    let password_key = derive_password_key(
        password,
        &header.salt,
        header.argon2_m_cost,
        header.argon2_t_cost,
        header.argon2_p_cost,
    )?;

    // 4. Derive PQC Wrap Key
    let pqc_wrap_key = derive_pqc_wrap_key(&*password_key, &header.salt, &header.uuid)?;

    // 5. Decrypt PQC Decapsulation Key (Authenticated against full 80-byte Header)
    // Fails immediately if password is wrong OR if any byte in the header was altered
    let decaps_key_bytes = decrypt_aes_gcm(
        &*pqc_wrap_key,
        &wrap_nonce,
        &wrapped_decaps_key,
        &header_bytes,
    ).map_err(|_| WraithError::ManifestAuthFailed)?;

    // 6. Decapsulate PQC Shared Secret (ML-KEM NIST FIPS 203)
    let pqc_shared_secret = pqc_decapsulate(header.suite, &decaps_key_bytes, &pqc_ct)?;

    // 7. Derive Master Keys via HKDF-SHA512
    let master_keys = derive_master_keys(
        &*password_key,
        &*pqc_shared_secret,
        &header.uuid,
        &header.salt,
    )?;

    // 8. Stream & Decrypt Chunks
    let mut expected_chunk_index = 0u64;
    let mut total_bytes_written = 0u64;
    let mut sha256_hasher = Sha256::new();

    loop {
        let mut idx_buf = [0u8; 8];
        reader.read_exact(&mut idx_buf)?;
        let chunk_index = u64::from_be_bytes(idx_buf);

        if chunk_index != expected_chunk_index {
            return Err(WraithError::ChunkTampered { index: chunk_index });
        }

        let mut final_buf = [0u8; 1];
        reader.read_exact(&mut final_buf)?;
        // Strict canonical boolean check: only 0x00 and 0x01 are valid
        let is_final = match final_buf[0] {
            0 => false,
            1 => true,
            _ => return Err(WraithError::InvalidContainer),
        };

        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let payload_len = u32::from_be_bytes(len_buf) as usize;
        if payload_len > MAX_CHUNK_PAYLOAD_LEN {
            return Err(WraithError::InvalidContainer);
        }

        let mut chunk_nonce = [0u8; NONCE_SIZE];
        reader.read_exact(&mut chunk_nonce)?;

        let mut encrypted_payload = vec![0u8; payload_len + TAG_SIZE];
        reader.read_exact(&mut encrypted_payload)?;

        // Construct Chunk AAD for verification
        let mut aad = Vec::with_capacity(29);
        aad.extend_from_slice(&header.uuid);
        aad.extend_from_slice(&chunk_index.to_be_bytes());
        aad.push(if is_final { 1 } else { 0 });
        aad.extend_from_slice(&(payload_len as u32).to_be_bytes());

        let mut plaintext_chunk = decrypt_aes_gcm(&master_keys.dek, &chunk_nonce, &encrypted_payload, &aad)
            .map_err(|_| WraithError::ChunkTampered { index: chunk_index })?;

        sha256_hasher.update(&plaintext_chunk);
        writer.write_all(&plaintext_chunk)?;
        total_bytes_written += plaintext_chunk.len() as u64;

        plaintext_chunk.zeroize();
        expected_chunk_index += 1;

        // Progress Telemetry
        let elapsed = start_time.elapsed().as_secs_f64().max(0.001);
        let speed_mb_s = (total_bytes_written as f64 / (1024.0 * 1024.0)) / elapsed;

        progress_callback(ProgressReport {
            total_bytes: total_bytes_written,
            processed_bytes: total_bytes_written,
            current_chunk: expected_chunk_index,
            total_chunks: expected_chunk_index,
            percentage: if is_final { 100.0 } else { 50.0 },
            speed_mb_s,
        });

        if is_final {
            break;
        }
    }

    writer.flush()?;

    // 9. Read and Verify Manifest Trailer
    let mut trailer_magic = [0u8; 8];
    reader.read_exact(&mut trailer_magic)?;
    if &trailer_magic != b"WRAITHMF" {
        return Err(WraithError::InvalidMagic);
    }

    reader.read_exact(&mut u32_buf)?;
    let manifest_len = u32::from_be_bytes(u32_buf) as usize;
    if manifest_len > MAX_MANIFEST_LEN {
        return Err(WraithError::InvalidContainer);
    }

    let mut encrypted_manifest = vec![0u8; manifest_len];
    reader.read_exact(&mut encrypted_manifest)?;

    let manifest = Manifest::decrypt(&encrypted_manifest, &master_keys.manifest_key, &header.uuid)?;

    // 10. Verify Total Chunks Count & Hash in Constant Time & Size
    if manifest.total_chunks != expected_chunk_index {
        return Err(WraithError::IntegrityHashMismatch);
    }

    let final_hash: [u8; 32] = sha256_hasher.finalize().into();
    let hash_match: bool = manifest.sha256_hash.ct_eq(&final_hash).into();
    if !hash_match || manifest.original_size != total_bytes_written {
        return Err(WraithError::IntegrityHashMismatch);
    }

    // 11. Reject Trailing Garbage / Verify EOF
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(WraithError::InvalidContainer);
    }

    Ok(manifest)
}
