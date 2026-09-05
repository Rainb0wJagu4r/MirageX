use std::io::{Read, Write};
use std::time::Instant;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::{
    aead::{encrypt_aes_gcm, generate_chunk_nonce, generate_nonce, NONCE_SIZE},
    kdf::{derive_master_keys, derive_password_key, derive_pqc_wrap_key, DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST},
    kem::pqc_encapsulate,
    PqcSuite,
};
use crate::wraith::{
    header::WraithHeader,
    manifest::Manifest,
    ProgressReport, WraithError, DEFAULT_CHUNK_SIZE,
};

pub struct EncryptOptions {
    pub suite: PqcSuite,
    pub chunk_size: u32,
    pub original_filename: String,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            suite: PqcSuite::MlKem768,
            chunk_size: DEFAULT_CHUNK_SIZE,
            original_filename: "payload.bin".into(),
            argon2_m_cost: DEFAULT_ARGON2_M_COST,
            argon2_t_cost: DEFAULT_ARGON2_T_COST,
            argon2_p_cost: DEFAULT_ARGON2_P_COST,
        }
    }
}

/// Encrypts an input stream to an output stream producing a valid WRAITH v4 container.
pub fn encrypt_stream<R: Read, W: Write, F: FnMut(ProgressReport)>(
    mut reader: R,
    mut writer: W,
    password: &[u8],
    total_file_size: u64,
    options: EncryptOptions,
    mut progress_callback: F,
) -> Result<u64, WraithError> {
    let mut rng = OsRng;
    let start_time = Instant::now();

    // 1. Generate Header & Serialize full 80-byte Header Block (storing Argon2id KDF parameters)
    let header = WraithHeader::new(
        options.suite,
        options.chunk_size,
        options.argon2_m_cost,
        options.argon2_t_cost,
        options.argon2_p_cost,
        &mut rng,
    );
    let header_bytes = header.to_bytes();
    writer.write_all(&header_bytes)?;

    // 2. Perform PQC Encapsulation (NIST FIPS 203 ML-KEM)
    let pqc_res = pqc_encapsulate(options.suite, &mut rng)?;

    // 3. Derive Password Key via Argon2id (Zeroizing wrapper)
    let password_key = derive_password_key(
        password,
        &header.salt,
        header.argon2_m_cost,
        header.argon2_t_cost,
        header.argon2_p_cost,
    )?;

    // 4. Derive PQC Wrap Key and Master Keys via HKDF-SHA512
    let pqc_wrap_key = derive_pqc_wrap_key(&*password_key, &header.salt, &header.uuid)?;
    let master_keys = derive_master_keys(
        &*password_key,
        &*pqc_res.shared_secret,
        &header.uuid,
        &header.salt,
    )?;

    // 5. Wrap PQC Decapsulation Key with pqc_wrap_key via AES-256-GCM
    // Authentication Binding: We bind the ENTIRE 80-byte Header as AAD to seal version, suite, salt, uuid, chunk size, and KDF params
    let wrap_nonce = generate_nonce(&mut rng);
    let wrapped_decaps_key = encrypt_aes_gcm(
        &*pqc_wrap_key,
        &wrap_nonce,
        &*pqc_res.decapsulation_key_bytes,
        &header_bytes,
    )?;

    // 6. Write PQC Envelope Block
    // [pqc_ct_len (4B)] || [pqc_ct] || [wrapped_len (4B)] || [wrap_nonce (12B)] || [wrapped_key_with_tag]
    let pqc_ct_len = pqc_res.ciphertext.len() as u32;
    writer.write_all(&pqc_ct_len.to_be_bytes())?;
    writer.write_all(&pqc_res.ciphertext)?;

    let wrapped_len = (NONCE_SIZE + wrapped_decaps_key.len()) as u32;
    writer.write_all(&wrapped_len.to_be_bytes())?;
    writer.write_all(&wrap_nonce)?;
    writer.write_all(&wrapped_decaps_key)?;

    // 7. Calculate total chunks count
    let chunk_size = options.chunk_size as usize;
    let total_chunks = if total_file_size == 0 {
        1
    } else {
        (total_file_size + chunk_size as u64 - 1) / (chunk_size as u64)
    };

    // 8. Stream Chunks with AEAD AES-256-GCM (Deterministic NIST SP 800-38D Nonces & Lookahead EOF)
    let mut chunk_buf = vec![0u8; chunk_size];
    let mut chunk_index = 0u64;
    let mut total_bytes_read = 0u64;
    let mut sha256_hasher = Sha256::new();
    let mut lookahead_byte: Option<u8> = None;

    let mut chunk_nonce_prefix = [0u8; 4];
    rng.fill_bytes(&mut chunk_nonce_prefix);

    loop {
        let mut n = 0;
        if let Some(b) = lookahead_byte.take() {
            chunk_buf[0] = b;
            n = 1;
        }

        while n < chunk_size {
            let read_bytes = reader.read(&mut chunk_buf[n..])?;
            if read_bytes == 0 {
                break;
            }
            n += read_bytes;
        }

        let is_final;
        if n < chunk_size {
            is_final = true;
        } else {
            // We filled a complete chunk buffer (n == chunk_size).
            // Probe 1 byte to check for genuine EOF without relying on pre-calculated file size.
            let mut probe = [0u8; 1];
            let probe_n = reader.read(&mut probe)?;
            if probe_n == 0 {
                is_final = true;
            } else {
                is_final = false;
                lookahead_byte = Some(probe[0]);
            }
        }

        sha256_hasher.update(&chunk_buf[..n]);
        total_bytes_read += n as u64;

        // Construct Chunk AAD: UUID (16B) || ChunkIndex (8B) || IsFinal (1B) || PayloadLen (4B)
        let mut aad = Vec::with_capacity(29);
        aad.extend_from_slice(&header.uuid);
        aad.extend_from_slice(&chunk_index.to_be_bytes());
        aad.push(if is_final { 1 } else { 0 });
        aad.extend_from_slice(&(n as u32).to_be_bytes());

        // Deterministic NIST SP 800-38D chunk nonce: [Prefix (4B)] || [ChunkIndex (8B)]
        let chunk_nonce = generate_chunk_nonce(chunk_nonce_prefix, chunk_index);
        let encrypted_chunk = encrypt_aes_gcm(&master_keys.dek, &chunk_nonce, &chunk_buf[..n], &aad)?;

        // Write Chunk: [chunk_index (8B)] || [is_final (1B)] || [payload_len (4B)] || [nonce (12B)] || [encrypted_payload_with_tag]
        writer.write_all(&chunk_index.to_be_bytes())?;
        writer.write_all(&[if is_final { 1 } else { 0 }])?;
        writer.write_all(&(n as u32).to_be_bytes())?;
        writer.write_all(&chunk_nonce)?;
        writer.write_all(&encrypted_chunk)?;

        chunk_index += 1;

        // Progress Telemetry
        let elapsed = start_time.elapsed().as_secs_f64().max(0.001);
        let speed_mb_s = (total_bytes_read as f64 / (1024.0 * 1024.0)) / elapsed;
        let percentage = if total_file_size > 0 {
            ((total_bytes_read as f32 / total_file_size as f32) * 100.0).min(100.0)
        } else {
            100.0
        };

        progress_callback(ProgressReport {
            total_bytes: total_file_size.max(total_bytes_read),
            processed_bytes: total_bytes_read,
            current_chunk: chunk_index,
            total_chunks: total_chunks.max(chunk_index),
            percentage,
            speed_mb_s,
        });

        if is_final {
            break;
        }
    }

    // Clean chunk buffer memory
    chunk_buf.zeroize();

    // 9. Write Encrypted Manifest Trailer (containing original filename, SHA-256 hash, and exact size)
    let final_hash: [u8; 32] = sha256_hasher.finalize().into();
    let manifest = Manifest::new(
        options.original_filename,
        total_bytes_read,
        final_hash,
        chunk_index,
    );
    let encrypted_manifest = manifest.encrypt(&master_keys.manifest_key, &header.uuid, &mut rng)?;

    // Trailer: [MAGIC_TRAILER (8B)] || [manifest_len (4B)] || [encrypted_manifest]
    writer.write_all(b"WRAITHMF")?;
    writer.write_all(&(encrypted_manifest.len() as u32).to_be_bytes())?;
    writer.write_all(&encrypted_manifest)?;
    writer.flush()?;

    Ok(total_bytes_read)
}
