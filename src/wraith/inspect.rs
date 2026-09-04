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
    pub flags: u32,
    pub pqc_ciphertext_size: usize,
    pub is_pqc: bool,
    pub legacy_project_mirage: bool,
    pub details: String,
}

/// Reads the container header and parameters without needing the password.
/// Supports both modern MirageX v4 (PQC) and legacy Project Mirage v1 containers.
pub fn inspect_container<R: Read>(mut reader: R) -> Result<ContainerInspection, WraithError> {
    let mut magic_buf = [0u8; 6];
    reader.read_exact(&mut magic_buf).map_err(|_| WraithError::UnexpectedEof)?;

    if &magic_buf == b"WRAITH" {
        // Modern MirageX v4 Container
        let mut rest_buf = [0u8; 58]; // 64 - 6 = 58 bytes
        reader.read_exact(&mut rest_buf).map_err(|_| WraithError::UnexpectedEof)?;

        let mut full_header_buf = [0u8; 64];
        full_header_buf[..6].copy_from_slice(&magic_buf);
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
            flags: header.flags,
            pqc_ciphertext_size: pqc_ct_len,
            is_pqc: true,
            legacy_project_mirage: false,
            details: "Formato WRAITH v4 oficial con cifrado híbrido envelope NIST FIPS 203 ML-KEM + Argon2id + AES-256-GCM Streaming por bloques autenticados.".into(),
        })
    } else if &magic_buf == b"MIRAGE" {
        // Legacy Project Mirage v1 Container (https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE)
        let mut ver_mode_buf = [0u8; 2];
        reader.read_exact(&mut ver_mode_buf).map_err(|_| WraithError::UnexpectedEof)?;

        let legacy_version = ver_mode_buf[0]; // 0x01
        let legacy_mode = ver_mode_buf[1];    // 0x01 = AES-GCM, 0x02 = Duress AES-GCM, 0x03 = Mirage-C4, 0x04 = Duress Mirage-C4

        let mut salt_buf = [0u8; 16];
        reader.read_exact(&mut salt_buf).unwrap_or_default();

        let (mode_name, is_c4, is_duress) = match legacy_mode {
            0x01 => ("Project Mirage v1 Standard (AES-256-GCM)", false, false),
            0x02 => ("Project Mirage v1 Duress Decoy (AES-256-GCM)", false, true),
            0x03 => ("Project Mirage v1 Mirage-C4 Cascade (Camellia+ARIA+ChaCha+AES)", true, false),
            0x04 => ("Project Mirage v1 Mirage-C4 Duress Cascade", true, true),
            _ => ("Project Mirage v1 Desconocido", false, false),
        };

        Ok(ContainerInspection {
            magic: "MIRAGE".into(),
            version: legacy_version,
            generation: "Project Mirage Legacy (v1 - https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE)".into(),
            suite_id: legacy_mode,
            suite_name: mode_name.into(),
            salt_hex: hex::encode(salt_buf),
            uuid_hex: "N/A (Legacy v1 Monolithic Container)".into(),
            chunk_size_bytes: 0,
            chunk_size_mb: 0.0,
            flags: if is_duress { 1 } else { 0 },
            pqc_ciphertext_size: 0,
            is_pqc: false,
            legacy_project_mirage: true,
            details: format!(
                "Contenedor de versión anterior de Project Mirage (v1.x). Modo: {}. {}",
                if is_c4 { "Cascada Criptográfica C4 de 4 capas" } else { "AES-256-GCM" },
                if is_duress { "Modo Coacción / Duress activo." } else { "Modo Estándar." }
            ),
        })
    } else {
        Err(WraithError::InvalidMagic)
    }
}
