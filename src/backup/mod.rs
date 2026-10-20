use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::keyfile::apply_keyfile_paths;
use crate::crypto::PqcSuite;
use crate::wraith::decryptor::{decrypt_stream, DecryptOptions};
use crate::wraith::encryptor::{encrypt_stream, EncryptOptions};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifestEntry {
    pub blinded_id: String,
    pub relative_path: String,
    pub original_size: u64,
    pub original_sha256: String,
    pub modified_timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: u8,
    pub created_at: u64,
    pub total_files: usize,
    pub total_bytes: u64,
    pub suite_id: u8,
    pub entries: Vec<BackupManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupResult {
    pub success: bool,
    pub total_files: usize,
    pub total_bytes: u64,
    pub manifest_file: String,
    pub destination_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub success: bool,
    pub restored_files: usize,
    pub restored_bytes: u64,
    pub restore_dir: String,
}

fn compute_file_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("Error abriendo para hash: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("Error leyendo para hash: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn compute_blinded_id(relative_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"WRAITH_BACKUP_BLINDED_V1:");
    hasher.update(relative_path.as_bytes());
    format!("{}.wraith", hex::encode(hasher.finalize()))
}

fn collect_files_recursive(dir: &Path, base: &Path, list: &mut Vec<PathBuf>) -> Result<(), String> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_files_recursive(&p, base, list)?;
            } else if p.is_file() {
                // Ignore backup manifest if it already exists in the same tree
                if p.file_name().map(|n| n == "backup_manifest.wraith").unwrap_or(false) {
                    continue;
                }
                list.push(p);
            }
        }
    }
    Ok(())
}

pub fn create_backup_archive(
    source_dir: &str,
    destination_dir: &str,
    mut password: String,
    keyfile_paths: &[String],
    suite: PqcSuite,
) -> Result<BackupResult, String> {
    let src_p = PathBuf::from(source_dir);
    let dest_p = PathBuf::from(destination_dir);

    if !src_p.is_dir() {
        return Err(format!("El directorio fuente '{}' no existe o no es carpeta", source_dir));
    }
    fs::create_dir_all(&dest_p).map_err(|e| format!("No se pudo crear carpeta de respaldo: {}", e))?;

    let effective_key = apply_keyfile_paths(password.as_bytes(), keyfile_paths)
        .map_err(|e| format!("Error procesando credenciales: {}", e))?;
    password.zeroize();

    let mut all_files = Vec::new();
    collect_files_recursive(&src_p, &src_p, &mut all_files)?;

    let mut entries = Vec::new();
    let mut total_bytes = 0u64;

    for file_path in all_files {
        let relative_path = file_path
            .strip_prefix(&src_p)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");

        let meta = fs::metadata(&file_path).map_err(|e| e.to_string())?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sha256_hash = compute_file_sha256(&file_path)?;
        let blinded_id = compute_blinded_id(&relative_path);
        let dest_file_path = dest_p.join(&blinded_id);

        let in_file = File::open(&file_path).map_err(|e| format!("Error abriendo '{}': {}", relative_path, e))?;
        let mut tmp_out = File::create(&dest_file_path)
            .map_err(|e| format!("Error creando destino '{}': {}", blinded_id, e))?;

        let options = EncryptOptions {
            suite,
            chunk_size: 16 * 1024 * 1024,
            original_filename: blinded_id.clone(),
            ..Default::default()
        };

        encrypt_stream(
            in_file,
            &mut tmp_out,
            &effective_key,
            size,
            options,
            |_| {},
        ).map_err(|e| format!("Error cifrando '{}': {}", relative_path, e))?;

        total_bytes += size;
        entries.push(BackupManifestEntry {
            blinded_id,
            relative_path,
            original_size: size,
            original_sha256: sha256_hash,
            modified_timestamp: mtime,
        });
    }

    let now_ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let manifest = BackupManifest {
        version: 1,
        created_at: now_ts,
        total_files: entries.len(),
        total_bytes,
        suite_id: suite.as_u8(),
        entries,
    };

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("Error serializando manifiesto: {}", e))?;

    // Encrypt the manifest into backup_manifest.wraith
    let manifest_path = dest_p.join("backup_manifest.wraith");
    let mut manifest_out = File::create(&manifest_path)
        .map_err(|e| format!("Error creando archivo de manifiesto: {}", e))?;

    let manifest_cursor = std::io::Cursor::new(&manifest_bytes);
    let manifest_options = EncryptOptions {
        suite,
        chunk_size: 16 * 1024 * 1024,
        original_filename: "backup_manifest.json".into(),
        ..Default::default()
    };

    encrypt_stream(
        manifest_cursor,
        &mut manifest_out,
        &effective_key,
        manifest_bytes.len() as u64,
        manifest_options,
        |_| {},
    ).map_err(|e| format!("Error cifrando manifiesto de respaldo: {}", e))?;

    Ok(BackupResult {
        success: true,
        total_files: manifest.total_files,
        total_bytes,
        manifest_file: manifest_path.to_string_lossy().to_string(),
        destination_dir: destination_dir.to_string(),
    })
}

pub fn restore_backup_archive(
    backup_dir: &str,
    restore_dir: &str,
    mut password: String,
    keyfile_paths: &[String],
) -> Result<RestoreResult, String> {
    let bkp_p = PathBuf::from(backup_dir);
    let rst_p = PathBuf::from(restore_dir);

    if !bkp_p.is_dir() {
        return Err(format!("El directorio de respaldo '{}' no existe", backup_dir));
    }
    fs::create_dir_all(&rst_p).map_err(|e| format!("No se pudo crear carpeta destino: {}", e))?;

    let effective_key = apply_keyfile_paths(password.as_bytes(), keyfile_paths)
        .map_err(|e| format!("Error procesando credenciales: {}", e))?;
    password.zeroize();

    // 1. Decrypt manifest
    let manifest_path = bkp_p.join("backup_manifest.wraith");
    if !manifest_path.is_file() {
        return Err("No se encontró 'backup_manifest.wraith' en el directorio de respaldo especificado.".into());
    }

    let manifest_in = File::open(&manifest_path).map_err(|e| e.to_string())?;
    let mut decrypted_manifest_bytes = Vec::new();

    decrypt_stream(
        manifest_in,
        &mut decrypted_manifest_bytes,
        &effective_key,
        DecryptOptions::default(),
        |_| {},
    ).map_err(|e| format!("Error descifrando manifiesto (¿contraseña o keyfile incorrectos?): {}", e))?;

    let manifest: BackupManifest = serde_json::from_slice(&decrypted_manifest_bytes)
        .map_err(|e| format!("Formato de manifiesto inválido: {}", e))?;

    let mut restored_count = 0usize;
    let mut restored_bytes = 0u64;

    for entry in &manifest.entries {
        let encrypted_file_path = bkp_p.join(&entry.blinded_id);
        if !encrypted_file_path.is_file() {
            return Err(format!("Falta el archivo anonimizado '{}' en el respaldo.", entry.blinded_id));
        }

        let target_file_path = rst_p.join(&entry.relative_path);
        if let Some(parent) = target_file_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let enc_in = File::open(&encrypted_file_path).map_err(|e| e.to_string())?;
        let mut target_out = File::create(&target_file_path).map_err(|e| e.to_string())?;

        decrypt_stream(
            enc_in,
            &mut target_out,
            &effective_key,
            DecryptOptions::default(),
            |_| {},
        ).map_err(|e| format!("Error descifrando '{}': {}", entry.relative_path, e))?;

        // Verify restored file hash
        let check_hash = compute_file_sha256(&target_file_path)?;
        if check_hash != entry.original_sha256 {
            let _ = fs::remove_file(&target_file_path);
            return Err(format!("Verificación de integridad fallida en '{}'", entry.relative_path));
        }

        restored_count += 1;
        restored_bytes += entry.original_size;
    }

    Ok(RestoreResult {
        success: true,
        restored_files: restored_count,
        restored_bytes,
        restore_dir: restore_dir.to_string(),
    })
}
