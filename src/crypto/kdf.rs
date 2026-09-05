use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, MasterKeys};

pub const DEFAULT_ARGON2_M_COST: u32 = 64 * 1024; // 64 MB
pub const DEFAULT_ARGON2_T_COST: u32 = 3;         // 3 iterations
pub const DEFAULT_ARGON2_P_COST: u32 = 4;         // 4 parallel threads

/// Derives a 32-byte intermediate key from a password and salt using Argon2id.
/// The returned key is automatically zeroized upon drop.
pub fn derive_password_key(
    password: &[u8],
    salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| CryptoError::KdfError(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived_key = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(password, salt, &mut *derived_key)
        .map_err(|e| CryptoError::KdfError(format!("Argon2 hash error: {}", e)))?;

    Ok(derived_key)
}

/// Derives the PQC key-wrapping key from the password key, salt, and container UUID.
pub fn derive_pqc_wrap_key(
    password_key: &[u8; 32],
    salt: &[u8; 32],
    container_uuid: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut hkdf_salt = [0u8; 48];
    hkdf_salt[..32].copy_from_slice(salt);
    hkdf_salt[32..].copy_from_slice(container_uuid);

    let hk = Hkdf::<Sha512>::new(Some(&hkdf_salt), password_key);
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"miragex-v4-pqc-wrap-key", &mut *wrap_key)
        .map_err(|e| CryptoError::KdfError(format!("HKDF PQC Wrap expand error: {}", e)))?;

    Ok(wrap_key)
}

/// Derives domain-separated MasterKeys from the combined password key, PQC shared secret, and container UUID.
pub fn derive_master_keys(
    password_key: &[u8; 32],
    pqc_shared_secret: &[u8; 32],
    container_uuid: &[u8; 16],
    salt: &[u8; 32],
) -> Result<MasterKeys, CryptoError> {
    // Combine entropy sources: Password Key (32B) + PQC Shared Secret (32B)
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(password_key);
    ikm[32..].copy_from_slice(pqc_shared_secret);

    // Salt for HKDF combines container Salt + UUID
    let mut hkdf_salt = [0u8; 48];
    hkdf_salt[..32].copy_from_slice(salt);
    hkdf_salt[32..].copy_from_slice(container_uuid);

    let hk = Hkdf::<Sha512>::new(Some(&hkdf_salt), &*ikm);

    let mut dek = [0u8; 32];
    let mut manifest_key = [0u8; 32];

    hk.expand(b"miragex-v4-aes256-gcm-dek", &mut dek)
        .map_err(|e| CryptoError::KdfError(format!("HKDF DEK expand error: {}", e)))?;

    hk.expand(b"miragex-v4-manifest-key", &mut manifest_key)
        .map_err(|e| CryptoError::KdfError(format!("HKDF Manifest expand error: {}", e)))?;

    Ok(MasterKeys {
        dek,
        manifest_key,
    })
}
