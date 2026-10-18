//! VeraCrypt & Arcanum compatible Keyfile derivation and generation engine.
//!
//! Implements byte-for-byte identical keyfile pool mixing algorithm used by
//! VeraCrypt (Common/Keyfiles.c) and Arcanum (vc_header.cpp).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const KEYFILE_POOL_LEGACY_SIZE: usize = 64;
pub const KEYFILE_POOL_SIZE: usize = 128;
pub const KEYFILE_MAX_READ_LEN: usize = 1024 * 1024; // 1 MiB
pub const KEYFILE_DEFAULT_SIZE: usize = 64;

/// IEEE 802.3 CRC32 lookup table (polynomial 0xEDB88320)
const CRC_TABLE: [u32; 256] = {
    let mut tab = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            if (c & 1) != 0 {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        tab[i] = c;
        i += 1;
    }
    tab
};

/// Step standard IEEE 802.3 CRC-32 (unfinalized, running)
#[inline(always)]
pub fn crc32_step(crc: u32, b: u8) -> u32 {
    CRC_TABLE[((crc ^ (b as u32)) & 0xFF) as usize] ^ (crc >> 8)
}

/// Computes the keyfile pool size based on original password byte length.
/// Matches VeraCrypt Keyfiles.c:239 and Arcanum vc_header.cpp.
#[inline]
pub fn vc_keyfile_pool_size(orig_pwd_len: usize) -> usize {
    if orig_pwd_len <= KEYFILE_POOL_LEGACY_SIZE {
        KEYFILE_POOL_LEGACY_SIZE
    } else {
        KEYFILE_POOL_SIZE
    }
}

/// Processes a slice of keyfile bytes into the key pool buffer.
/// Reads at most 1 MiB (1048576 bytes).
pub fn process_keyfile_buf(data: &[u8], pool: &mut [u8], pool_size: usize) {
    debug_assert!(pool_size % 4 == 0, "pool size must be multiple of 4");
    debug_assert!(pool.len() >= pool_size);

    let mut crc = 0xFFFFFFFFu32;
    let mut write_pos = 0;
    let limit = data.len().min(KEYFILE_MAX_READ_LEN);

    for &b in &data[..limit] {
        crc = crc32_step(crc, b);
        pool[write_pos] = pool[write_pos].wrapping_add((crc >> 24) as u8);
        pool[write_pos + 1] = pool[write_pos + 1].wrapping_add((crc >> 16) as u8);
        pool[write_pos + 2] = pool[write_pos + 2].wrapping_add((crc >> 8) as u8);
        pool[write_pos + 3] = pool[write_pos + 3].wrapping_add(crc as u8);
        write_pos += 4;
        if write_pos >= pool_size {
            write_pos = 0;
        }
    }
}

/// Applies one or more keyfiles to a base password, producing the effective password.
/// Byte-for-byte identical to VeraCrypt & Arcanum.
///
/// Empty keyfiles are rejected: VeraCrypt's `KeyFileProcess` treats a zero-byte
/// keyfile as an error, and accepting it would derive a predictable password.
pub fn apply_keyfiles(password: &[u8], keyfiles: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>, String> {
    if keyfiles.is_empty() {
        return Ok(Zeroizing::new(password.to_vec()));
    }

    if keyfiles.iter().any(|kf| kf.is_empty()) {
        return Err(
            "Keyfile is empty or unreadable: VeraCrypt/Arcanum require non-empty keyfiles"
                .to_string(),
        );
    }

    let orig_len = password.len();
    let pool_size = vc_keyfile_pool_size(orig_len);
    let mut pool = Zeroizing::new(vec![0u8; pool_size]);

    for kf in keyfiles {
        process_keyfile_buf(kf, &mut pool, pool_size);
    }

    let new_len = orig_len.max(pool_size);
    let mut effective = Zeroizing::new(vec![0u8; new_len]);
    effective[..orig_len].copy_from_slice(password);

    for i in 0..pool_size {
        effective[i] = effective[i].wrapping_add(pool[i]);
    }

    Ok(effective)
}

/// Reads a keyfile from disk up to the 1 MiB cap.
pub fn read_keyfile_from_path<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, String> {
    let p = path.as_ref();
    let mut file = File::open(p)
        .map_err(|e| format!("Failed to open keyfile '{}': {}", p.display(), e))?;

    let mut buf = Vec::new();
    let mut take = (&mut file).take(KEYFILE_MAX_READ_LEN as u64);
    take.read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read keyfile '{}': {}", p.display(), e))?;

    if buf.is_empty() {
        return Err(format!(
            "Keyfile '{}' is empty (0 bytes). VeraCrypt/Arcanum require a non-empty keyfile.",
            p.display()
        ));
    }

    Ok(buf)
}

/// Convenience function to apply keyfiles given paths on disk.
pub fn apply_keyfile_paths<P: AsRef<Path>>(
    password: &[u8],
    paths: &[P],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if paths.is_empty() {
        return Ok(Zeroizing::new(password.to_vec()));
    }

    let mut kf_data = Vec::with_capacity(paths.len());
    for p in paths {
        kf_data.push(read_keyfile_from_path(p)?);
    }

    apply_keyfiles(password, &kf_data)
}

/// Generates a cryptographically secure keyfile using `OsRng` fold-mixed with
/// optional user-collected entropy (e.g., mouse gestures / touch events).
pub fn generate_keyfile(
    size_bytes: usize,
    extra_entropy: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if size_bytes == 0 || size_bytes > KEYFILE_MAX_READ_LEN {
        return Err(format!(
            "Invalid keyfile size: {} bytes. Must be between 1 and {} bytes.",
            size_bytes, KEYFILE_MAX_READ_LEN
        ));
    }

    let mut output = Zeroizing::new(vec![0u8; size_bytes]);
    OsRng.fill_bytes(&mut output);

    // If extra entropy is supplied, fold it cryptographically across the buffer
    if let Some(entropy) = extra_entropy {
        if !entropy.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"miragex-keyfile-entropy-fold-v1");
            hasher.update(entropy);
            let mut digest = hasher.finalize();

            // Stream cipher-style expansion to XOR fold into output
            let mut block_idx: u32 = 0;
            let mut offset = 0;
            while offset < size_bytes {
                let mut blk_hasher = Sha256::new();
                blk_hasher.update(&digest);
                blk_hasher.update(&block_idx.to_be_bytes());
                let blk = blk_hasher.finalize();

                let to_mix = (size_bytes - offset).min(32);
                for i in 0..to_mix {
                    output[offset + i] ^= blk[i];
                }
                offset += to_mix;
                block_idx = block_idx.wrapping_add(1);
            }
            digest.zeroize();
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_step_known_vector() {
        // Standard check: CRC-32 of "123456789" with init=0xFFFFFFFF and final XOR=0xFFFFFFFF is 0xCBF43926
        let input = b"123456789";
        let mut crc = 0xFFFFFFFFu32;
        for &b in input {
            crc = crc32_step(crc, b);
        }
        let finalized = crc ^ 0xFFFFFFFF;
        assert_eq!(finalized, 0xCBF43926);
    }

    #[test]
    fn test_empty_keyfiles_returns_original_password() {
        let pwd = b"my_secure_password";
        let res = apply_keyfiles(pwd, &[]).unwrap();
        assert_eq!(&*res, pwd);
    }

    #[test]
    fn test_empty_password_with_keyfile_derives_64_byte_key() {
        let kf = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let res = apply_keyfiles(b"", &[kf]).unwrap();
        assert_eq!(res.len(), KEYFILE_POOL_LEGACY_SIZE);
        assert_ne!(&*res, &[0u8; 64]);
    }

    #[test]
    fn test_empty_keyfile_rejected() {
        // VeraCrypt/Arcanum treat a zero-byte keyfile as an error.
        assert!(apply_keyfiles(b"password", &[Vec::new()]).is_err());
        assert!(apply_keyfiles(b"", &[Vec::new()]).is_err());
        // An empty *list* is fine: no keyfile is applied.
        assert!(apply_keyfiles(b"password", &[]).is_ok());
    }

    #[test]
    fn test_keyfile_pool_size_selection() {
        assert_eq!(vc_keyfile_pool_size(0), 64);
        assert_eq!(vc_keyfile_pool_size(64), 64);
        assert_eq!(vc_keyfile_pool_size(65), 128);
        assert_eq!(vc_keyfile_pool_size(128), 128);
    }

    #[test]
    fn test_generate_keyfile_size_and_entropy() {
        let kf1 = generate_keyfile(64, None).unwrap();
        assert_eq!(kf1.len(), 64);

        let kf2 = generate_keyfile(256, Some(b"user_mouse_coordinates_123")).unwrap();
        assert_eq!(kf2.len(), 256);
        assert_ne!(&kf1[..], &kf2[..64]);

        assert!(generate_keyfile(0, None).is_err());
        assert!(generate_keyfile(KEYFILE_MAX_READ_LEN + 1, None).is_err());
    }
}
