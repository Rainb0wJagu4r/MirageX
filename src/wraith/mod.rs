pub mod header;
pub mod manifest;
pub mod encryptor;
pub mod decryptor;
pub mod inspect;

use serde::{Deserialize, Serialize};

pub const MAGIC_BYTES: &[u8; 6] = b"WRAITH";
pub const CURRENT_VERSION: u8 = 4;
pub const DEFAULT_CHUNK_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, thiserror::Error)]
pub enum WraithError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto Error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("Invalid WRAITH Container Magic bytes")]
    InvalidMagic,

    #[error("Unsupported WRAITH Version: {0}")]
    UnsupportedVersion(u8),

    #[error("Container Tampered: Chunk {index} authentication failed or corrupted")]
    ChunkTampered { index: u64 },

    #[error("Container Integrity Check Failed: SHA-256 hash mismatch")]
    IntegrityHashMismatch,

    #[error("Manifest Decryption Failed: Invalid password or corrupted header")]
    ManifestAuthFailed,

    #[error("Invalid Container Structure: Unexpected end of stream")]
    UnexpectedEof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressReport {
    pub total_bytes: u64,
    pub processed_bytes: u64,
    pub current_chunk: u64,
    pub total_chunks: u64,
    pub percentage: f32,
    pub speed_mb_s: f64,
}
