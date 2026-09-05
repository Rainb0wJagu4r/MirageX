pub mod kdf;
pub mod kem;
pub mod aead;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("KDF Error: {0}")]
    KdfError(String),

    #[error("PQC KEM Error: {0}")]
    KemError(String),

    #[error("AEAD Decryption / Authentication Failed: data may be corrupted, header modified, or password incorrect")]
    AeadAuthFailed,

    #[error("Invalid Key or Nonce Length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("Unsupported MirageX Suite ID: {0:#04x}")]
    UnsupportedSuite(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqcSuite {
    MlKem768 = 0x01,
    MlKem1024 = 0x02,
}

impl PqcSuite {
    pub fn from_u8(val: u8) -> Result<Self, CryptoError> {
        match val {
            0x01 => Ok(PqcSuite::MlKem768),
            0x02 => Ok(PqcSuite::MlKem1024),
            other => Err(CryptoError::UnsupportedSuite(other)),
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn name(&self) -> &'static str {
        match self {
            PqcSuite::MlKem768 => "MirageX Standard (ML-KEM-768 / NIST Level 3)",
            PqcSuite::MlKem1024 => "MirageX Ultra (ML-KEM-1024 / NIST Level 5)",
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            PqcSuite::MlKem768 => 1088,
            PqcSuite::MlKem1024 => 1568,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKeys {
    pub dek: [u8; 32],
    pub manifest_key: [u8; 32],
}
