use std::io::Read;
use serde::{Deserialize, Serialize};

use crate::wraith::{header::WraithHeader, WraithError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInspection {
    pub magic: String,
    pub version: u8,
    pub generation: String,
    pub suite_id: u8,
    pub suite_name: String,
    pub salt_hex: String,
    pub uuid_hex: String,
    pub chunk_size_bytes: u32,
    pub chunk_size_mb: f32,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub flags: u32,
    pub pqc_ciphertext_size: usize,
    pub is_pqc: bool,
    pub legacy_project_mirage: bool,
    pub details: String,
}

/// Reads the container header and parameters without needing the password.
/// Supports modern MirageX v4 (PQC) and legacy Project Mirage (MIRG v2 / MIRAGE v1) containers.
pub fn inspect_container<R: Read>(mut reader: R) -> Result<ContainerInspection, WraithError> {
    let mut initial_buf = [0u8; 4];
    reader.read_exact(&mut initial_buf).map_err(|_| WraithError::UnexpectedEof)?;

    if &initial_buf == b"WRAI" {
        // Must be "WRAITH" (v4)
        let mut rest_magic = [0u8; 2];
        reader.read_exact(&mut rest_magic).map_err(|_| WraithError::UnexpectedEof)?;
        if &rest_magic != b"TH" {
            return Err(WraithError::InvalidMagic);
        }

        let mut rest_buf = [0u8; 74]; // 80 - 6 = 74 bytes
        reader.read_exact(&mut rest_buf).map_err(|_| WraithError::UnexpectedEof)?;

        let mut full_header_buf = [0u8; 80];
        full_header_buf[..4].copy_from_slice(&initial_buf);
        full_header_buf[4..6].copy_from_slice(&rest_magic);
        full_header_buf[6..].copy_from_slice(&rest_buf);

        let mut cursor = std::io::Cursor::new(full_header_buf);
        let header = WraithHeader::read_from(&mut cursor)?;

        let mut u32_buf = [0u8; 4];
        reader.read_exact(&mut u32_buf).unwrap_or_default();
        let pqc_ct_len = u32::from_be_bytes(u32_buf) as usize;

        Ok(ContainerInspection {
            magic: "WRAITH".into(),
            version: header.version,
            generation: "MirageX v4 (Post-Quantum PQC Engine)".into(),
            suite_id: header.suite.as_u8(),
            suite_name: header.suite.name().to_string(),
            salt_hex: hex::encode(header.salt),
            uuid_hex: hex::encode(header.uuid),
            chunk_size_bytes: header.chunk_size,
            chunk_size_mb: header.chunk_size as f32 / (1024.0 * 1024.0),
            argon2_m_cost: header.argon2_m_cost,
            argon2_t_cost: header.argon2_t_cost,
            argon2_p_cost: header.argon2_p_cost,
            flags: header.flags,
            pqc_ciphertext_size: pqc_ct_len,
            is_pqc: true,
            legacy_project_mirage: false,
            details: format!(
                "Formato WRAITH v4 oficial con cifrado híbrido envelope NIST FIPS 203 ML-KEM + Argon2id (m={}MB, t={}, p={}) + AES-256-GCM Streaming por bloques autenticados.",
                header.argon2_m_cost / 1024,
                header.argon2_t_cost,
                header.argon2_p_cost
            ),
        })
    } else if &initial_buf == b"MIRG" {
        // Project Mirage Legacy (v2 - https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE)
        let mut hdr_tail = [0u8; 8]; // Total header is 12 bytes
        reader.read_exact(&mut hdr_tail).map_err(|_| WraithError::UnexpectedEof)?;

        let version = hdr_tail[0];    // 0x02
        let mode = hdr_tail[1];       // 0x11 (Single), 0x12 (Duress), 0x13 (Vault)
        let flags = hdr_tail[2];      // Flags (Hardware lock, Second factor, etc)
        let block_count = hdr_tail[3];// 1 or 2
        let _kdf_id = hdr_tail[4];    // 1 (scrypt-HKDF-v2)
        let cipher_id = hdr_tail[5];  // 1 (Cascade C4), 2 (AES-GCM)

        // Read first 32 bytes of block metadata (salt)
        let mut salt_buf = [0u8; 32];
        let _ = reader.read_exact(&mut salt_buf);

        let is_c4 = cipher_id == 1;
        let is_duress = mode == 0x12;
        let is_vault = mode == 0x13;

        let suite_name = if is_c4 {
            if is_duress {
                "Project Mirage C4 (Duress Decoy Cascade)".into()
            } else if is_vault {
                "Project Mirage C4 (Multi-Block Vault)".into()
            } else {
                "Project Mirage C4 (4-Layer: Camellia+ARIA+ChaCha+AES)".into()
            }
        } else {
            "Project Mirage Standard (AES-256-GCM)".into()
        };

        Ok(ContainerInspection {
            magic: "MIRG".into(),
            version,
            generation: "Project Mirage Legacy (v2 - https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE)".into(),
            suite_id: cipher_id,
            suite_name,
            salt_hex: hex::encode(salt_buf),
            uuid_hex: "N/A (Legacy Monolithic Archive)".into(),
            chunk_size_bytes: 0,
            chunk_size_mb: 0.0,
            argon2_m_cost: 0,
            argon2_t_cost: 0,
            argon2_p_cost: 0,
            flags: flags as u32,
            pqc_ciphertext_size: 0,
            is_pqc: false,
            legacy_project_mirage: true,
            details: format!(
                "Contenedor .wraith de Project Mirage clásico (v2.x). Cifrado: {}. Modo: {} ({} bloque(s)). KDF: scrypt (N=131072, r=8, p=1) + HKDF.",
                if is_c4 { "Cascada Cuádruple C4" } else { "AES-256-GCM" },
                if is_duress { "Coacción / Duress" } else if is_vault { "Vault" } else { "Estándar" },
                block_count
            ),
        })
    } else if &initial_buf == b"MIRA" {
        // Older v1 header starting with "MIRAGE\x01"
        let mut rest_magic = [0u8; 4];
        reader.read_exact(&mut rest_magic).map_err(|_| WraithError::UnexpectedEof)?;

        let legacy_version = rest_magic[2];
        let legacy_mode = rest_magic[3];

        let mut salt_buf = [0u8; 16];
        let _ = reader.read_exact(&mut salt_buf);

        Ok(ContainerInspection {
            magic: "MIRAGE".into(),
            version: legacy_version,
            generation: "Project Mirage Legacy (v1 - https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE)".into(),
            suite_id: legacy_mode,
            suite_name: "Project Mirage v1 Legacy Container".into(),
            salt_hex: hex::encode(salt_buf),
            uuid_hex: "N/A (Legacy v1 Archive)".into(),
            chunk_size_bytes: 0,
            chunk_size_mb: 0.0,
            argon2_m_cost: 0,
            argon2_t_cost: 0,
            argon2_p_cost: 0,
            flags: 0,
            pqc_ciphertext_size: 0,
            is_pqc: false,
            legacy_project_mirage: true,
            details: "Contenedor de versión inicial Project Mirage v1 (JavaScript / Node.js).".into(),
        })
    } else {
        Err(WraithError::InvalidMagic)
    }
}
