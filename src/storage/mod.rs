pub mod local;
pub mod memory;

use std::io::Read;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Storage corrupted or truncated")]
    Corrupted,

    #[error("Secure wipe error: {0}")]
    ShredFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified_timestamp: u64,
}

/// Decoupled Storage Adapter Interface for WRAITH v4 Containers
pub trait StorageAdapter: Send + Sync {
    /// Save streaming data to the destination path atomically.
    fn save_stream(&self, path: &Path, reader: &mut dyn Read) -> Result<u64, StorageError>;

    /// Open an input stream from the given path.
    fn open_stream(&self, path: &Path) -> Result<Box<dyn Read + Send>, StorageError>;

    /// Securely shred and overwrite a file using CSPRNG multi-pass.
    fn shred_file(&self, path: &Path, passes: u8) -> Result<(), StorageError>;

    /// Remove a file.
    fn delete_file(&self, path: &Path) -> Result<(), StorageError>;

    /// Retrieve file metadata.
    fn stat(&self, path: &Path) -> Result<StorageMetadata, StorageError>;

    /// Check if a path exists.
    fn exists(&self, path: &Path) -> bool;
}
