use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialFilePayload {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub action: Option<String>,
}

static INITIAL_FILE: Mutex<Option<InitialFilePayload>> = Mutex::new(None);

pub fn set_initial_file(path_str: &str, action: Option<&str>) {
    let path = Path::new(path_str);
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path_str.to_string());
    if let Ok(mut lock) = INITIAL_FILE.lock() {
        *lock = Some(InitialFilePayload {
            path: path_str.to_string(),
            name,
            size,
            action: action.map(|s| s.to_string()),
        });
    }
}

use crate::crypto::{
    aead::{encrypt_aes_gcm, generate_nonce},
    kdf::derive_password_key,
    kem::pqc_encapsulate,
    PqcSuite,
};
use crate::storage::{local::LocalStorageAdapter, StorageAdapter};
use crate::wraith::{
    decryptor::{decrypt_stream, DecryptOptions},
    encryptor::{encrypt_stream, EncryptOptions},
    inspect::{inspect_container, ContainerInspection},
    manifest::Manifest,
    DEFAULT_CHUNK_SIZE,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionResult {
    pub success: bool,
    pub input_path: String,
    pub output_path: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub suite_name: String,
    pub chunks_count: u64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptionResult {
    pub success: bool,
    pub input_path: String,
    pub output_path: String,
    pub original_filename: String,
    pub restored_size: u64,
    pub sha256_hex: String,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub miragex_768_encap_ops_sec: f64,
    pub miragex_1024_encap_ops_sec: f64,
    pub argon2id_time_ms: u128,
    pub aes_256_gcm_throughput_mb_s: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PqcKeyInfo {
    pub suite_name: String,
    pub ciphertext_size: usize,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelectedFileInfo {
    pub path: String,
    pub name: String,
    pub size: u64,
}

/// Sanitizes a filename from the container manifest to prevent Path Traversal attacks cross-platform.
pub fn sanitize_filename(raw_filename: &str) -> String {
    // 1. Remove null bytes and control characters
    let cleaned: String = raw_filename
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .collect();

    // 2. Normalize backslashes to forward slashes for universal path separation
    let normalized = cleaned.replace('\\', "/");
    let path = Path::new(&normalized);
    let basename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // 3. Trim trailing dots and whitespaces (invalid in Windows/cross-platform)
    let trimmed = basename.trim_matches(|c: char| c.is_whitespace() || c == '.');

    // 4. Reject forbidden characters and dangerous directory references
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains(':')
        || trimmed.contains('*')
        || trimmed.contains('?')
        || trimmed.contains('"')
        || trimmed.contains('<')
        || trimmed.contains('>')
        || trimmed.contains('|')
    {
        return "recovered_file.bin".to_string();
    }

    // 5. Reject Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    let stem = Path::new(trimmed)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(trimmed);
    let stem_upper = stem.to_ascii_uppercase();
    const RESERVED_NAMES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED_NAMES.contains(&stem_upper.as_str()) {
        return "recovered_file.bin".to_string();
    }

    trimmed.to_string()
}

#[tauri::command]
pub fn select_file_dialog() -> Result<Option<SelectedFileInfo>, String> {
    if let Some(path) = rfd::FileDialog::new().pick_file() {
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        Ok(Some(SelectedFileInfo {
            path: path.to_string_lossy().to_string(),
            name,
            size: meta.len(),
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub fn select_wraith_dialog() -> Result<Option<SelectedFileInfo>, String> {
    if let Some(path) = rfd::FileDialog::new().add_filter("WRAITH Container", &["wraith"]).pick_file() {
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        Ok(Some(SelectedFileInfo {
            path: path.to_string_lossy().to_string(),
            name,
            size: meta.len(),
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub fn select_keyfile_dialog() -> Result<Option<SelectedFileInfo>, String> {
    if let Some(path) = rfd::FileDialog::new().pick_file() {
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        Ok(Some(SelectedFileInfo {
            path: path.to_string_lossy().to_string(),
            name,
            size: meta.len(),
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub fn generate_keyfile_cmd(
    size: usize,
    entropy: Vec<u8>,
    default_name: Option<String>,
) -> Result<Option<SelectedFileInfo>, String> {
    let filename = default_name.unwrap_or_else(|| "miragex.key".to_string());
    if let Some(dest_path) = rfd::FileDialog::new()
        .set_file_name(&filename)
        .save_file()
    {
        let key_bytes = crate::crypto::keyfile::generate_keyfile(size, Some(&entropy))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&dest_path)
                .map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut file, &key_bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&dest_path)
                .map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut file, &key_bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
        }

        let meta = std::fs::metadata(&dest_path).map_err(|e| e.to_string())?;
        let name = dest_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or(filename);

        Ok(Some(SelectedFileInfo {
            path: dest_path.to_string_lossy().to_string(),
            name,
            size: meta.len(),
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub fn select_vault_sources_dialog() -> Result<Vec<SelectedFileInfo>, String> {
    if let Some(paths) = rfd::FileDialog::new().pick_files() {
        let mut list = Vec::new();
        for p in paths {
            let meta = std::fs::metadata(&p).map_err(|e| e.to_string())?;
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            list.push(SelectedFileInfo {
                path: p.to_string_lossy().to_string(),
                name,
                size: meta.len(),
            });
        }
        Ok(list)
    } else {
        Ok(Vec::new())
    }
}

#[tauri::command]
pub fn select_vault_source_folder_dialog() -> Result<Option<SelectedFileInfo>, String> {
    if let Some(path) = rfd::FileDialog::new().pick_folder() {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());
        Ok(Some(SelectedFileInfo {
            path: path.to_string_lossy().to_string(),
            name,
            // Folder size is resolved during vault packaging; 0 = "not computed".
            size: 0,
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub fn select_vault_dialog() -> Result<Option<SelectedFileInfo>, String> {
    if let Some(path) = rfd::FileDialog::new()
        .add_filter("MirageX Cyber Vault", &["wvault", "wraith"])
        .pick_file()
    {
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        Ok(Some(SelectedFileInfo {
            path: path.to_string_lossy().to_string(),
            name,
            size: meta.len(),
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub fn create_vault_cmd(
    source_paths: Vec<String>,
    output_path: Option<String>,
    password: Option<String>,
    keyfile_path: Option<String>,
    suite_id: Option<u8>,
) -> Result<String, String> {
    let pwd_str = password.unwrap_or_default();
    let pwd_bytes = pwd_str.as_bytes();

    let kf_paths: Vec<PathBuf> = match keyfile_path.as_deref() {
        Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p)],
        _ => Vec::new(),
    };

    if pwd_bytes.is_empty() && kf_paths.is_empty() {
        return Err("A password or at least one keyfile must be provided".to_string());
    }

    let sources: Vec<PathBuf> = source_paths.into_iter().map(PathBuf::from).collect();
    if sources.is_empty() {
        return Err("No source files selected".to_string());
    }

    let out_p = match output_path {
        Some(p) => PathBuf::from(p),
        None => {
            if let Some(dest) = rfd::FileDialog::new()
                .set_file_name("secure_vault.wvault")
                .add_filter("Cyber Vault", &["wvault", "wraith"])
                .save_file()
            {
                dest
            } else {
                return Err("Vault creation cancelled: no destination picked".to_string());
            }
        }
    };

    let suite = match suite_id {
        Some(id) => PqcSuite::from_u8(id).map_err(|e| e.to_string())?,
        None => PqcSuite::MlKem768,
    };

    crate::vault::create_vault(&out_p, &sources, pwd_bytes, &kf_paths, suite)?;
    Ok(out_p.to_string_lossy().to_string())
}

#[tauri::command]
pub fn open_vault_cmd(
    vault_path: String,
    password: Option<String>,
    keyfile_path: Option<String>,
) -> Result<crate::vault::VaultSessionInfo, String> {
    let pwd_str = password.unwrap_or_default();
    let pwd_bytes = pwd_str.as_bytes();

    let kf_paths: Vec<PathBuf> = match keyfile_path.as_deref() {
        Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p)],
        _ => Vec::new(),
    };

    if pwd_bytes.is_empty() && kf_paths.is_empty() {
        return Err("A password or keyfile must be provided".to_string());
    }

    let v_path = Path::new(&vault_path);
    crate::vault::open_vault(v_path, pwd_bytes, &kf_paths)
}

#[tauri::command]
pub fn list_vault_entries_cmd(session_id: String) -> Result<Vec<crate::vault::VaultEntryInfo>, String> {
    crate::vault::list_vault_entries(&session_id)
}

#[tauri::command]
pub fn extract_vault_entry_cmd(
    session_id: String,
    entry_path: String,
    destination_dir: Option<String>,
) -> Result<String, String> {
    let dest = match destination_dir {
        Some(d) => PathBuf::from(d),
        None => {
            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                folder
            } else {
                return Err("Extraction cancelled: no folder selected".to_string());
            }
        }
    };
    let res = crate::vault::extract_vault_entry(&session_id, &entry_path, &dest)?;
    Ok(res.to_string_lossy().to_string())
}

#[tauri::command]
pub fn extract_all_vault_cmd(
    session_id: String,
    destination_dir: Option<String>,
) -> Result<usize, String> {
    let dest = match destination_dir {
        Some(d) => PathBuf::from(d),
        None => {
            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                folder
            } else {
                return Err("Extraction cancelled: no folder selected".to_string());
            }
        }
    };
    crate::vault::extract_all_vault(&session_id, &dest)
}

#[tauri::command]
pub fn close_vault_cmd(session_id: String) -> Result<(), String> {
    crate::vault::close_vault(&session_id)
}

/// Returns `desired` if it does not exist, otherwise a non-colliding
/// `"<stem> (N)<ext>"` sibling. Used for automatic output names so a malicious
/// container manifest can never silently overwrite an existing file.
fn unique_output_path(desired: &Path) -> PathBuf {
    if fs::symlink_metadata(desired).is_err() {
        return desired.to_path_buf();
    }

    let parent = desired.parent().unwrap_or_else(|| Path::new("."));
    let stem = desired
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "output".to_string());
    let ext = desired
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    for n in 1..=9999u32 {
        let candidate = parent.join(format!("{} ({}){}", stem, n, ext));
        if fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }

    parent.join(format!("{}-{}", stem, OsRng.next_u64()))
}

/// Refuses to write through a symbolic link. This matters on Windows, where the
/// `fs::copy` fallback would follow the link and overwrite its target.
fn reject_symlink_destination(path: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing to overwrite symbolic link '{}'",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Atomically commits a temporary file to its final destination, falling back to copy+delete on cross-device links (EXDEV).
fn commit_file_atomic(tmp_path: &Path, final_path: &Path) -> Result<(), String> {
    reject_symlink_destination(final_path)?;

    if fs::rename(tmp_path, final_path).is_ok() {
        return Ok(());
    }
    // Fallback for cross-device links (EXDEV)
    fs::copy(tmp_path, final_path).map_err(|e| format!("Failed to copy file to destination: {}", e))?;
    let _ = fs::remove_file(tmp_path);
    Ok(())
}

#[tauri::command]
pub fn encrypt_file_cmd(
    input_path: String,
    output_path: Option<String>,
    mut password: String,
    keyfile_path: Option<String>,
    suite_id: Option<u8>,
    chunk_size_mb: Option<u32>,
    shred_source: bool,
    shred_mode: Option<String>,
    shred_passes: Option<u8>,
) -> Result<EncryptionResult, String> {
    let keyfile_paths: Vec<PathBuf> = match keyfile_path.as_deref() {
        Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p)],
        _ => Vec::new(),
    };

    if password.is_empty() && keyfile_paths.is_empty() {
        return Err("A password or at least one keyfile must be provided".to_string());
    }

    let in_p = Path::new(&input_path);
    if !in_p.exists() {
        return Err(format!("Input file not found on disk: '{}'. Ensure the full path is provided.", input_path));
    }

    let storage = LocalStorageAdapter::new();
    let meta = storage.stat(in_p).map_err(|e| e.to_string())?;

    let out_p = match output_path {
        Some(p) => PathBuf::from(p),
        None => {
            let mut p = in_p.to_path_buf();
            let orig_name = in_p.file_name().unwrap_or_default().to_string_lossy();
            p.set_file_name(format!("{}.wraith", orig_name));
            // Never silently overwrite an existing container when the user did
            // not choose an explicit destination.
            unique_output_path(&p)
        }
    };

    let suite = match suite_id {
        Some(id) => PqcSuite::from_u8(id).map_err(|e| e.to_string())?,
        None => PqcSuite::MlKem768,
    };

    // Safe chunk calculation with checked_mul and strict bounds
    let chunk_size = chunk_size_mb
        .and_then(|mb| mb.checked_mul(1024 * 1024))
        .map(|bytes| bytes.clamp(crate::wraith::MIN_CHUNK_SIZE, crate::wraith::MAX_CHUNK_SIZE))
        .unwrap_or(DEFAULT_CHUNK_SIZE);

    let original_filename = in_p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed.bin".into());

    let options = EncryptOptions {
        suite,
        chunk_size,
        original_filename,
        ..Default::default()
    };

    let in_file = File::open(in_p).map_err(|e| e.to_string())?;

    // Atomic write to temporary file with 0600 mode
    let mut rng = OsRng;
    let rand_suffix: u64 = rng.next_u64();
    let tmp_out_path = match out_p.file_name() {
        Some(fname) => out_p.with_file_name(format!("{}.tmp.{}", fname.to_string_lossy(), rand_suffix)),
        None => PathBuf::from(format!("miragex_enc_{}.tmp", rand_suffix)),
    };

    #[cfg(unix)]
    let mut tmp_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_out_path)
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(unix))]
    let mut tmp_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&tmp_out_path)
        .map_err(|e| e.to_string())?;

    let effective_password = crate::crypto::keyfile::apply_keyfile_paths(password.as_bytes(), &keyfile_paths)?;
    password.zeroize();

    let start = Instant::now();
    let total_encrypted_res = encrypt_stream(
        in_file,
        &mut tmp_file,
        &effective_password,
        meta.size,
        options,
        |_| {},
    );

    let total_encrypted = match total_encrypted_res {
        Ok(bytes) => bytes,
        Err(e) => {
            let storage = LocalStorageAdapter::new();
            let _ = storage.shred_file_with_mode(&tmp_out_path, 1, crate::storage::ShredMode::Hdd);
            return Err(e.to_string());
        }
    };

    // fsync before rename to guarantee data durability (MXA-11)
    if let Err(e) = tmp_file.sync_all() {
        let storage = LocalStorageAdapter::new();
        let _ = storage.shred_file_with_mode(&tmp_out_path, 1, crate::storage::ShredMode::Hdd);
        return Err(format!("Failed to fsync temporary encrypted file: {}", e));
    }
    drop(tmp_file);

    let elapsed = start.elapsed().as_millis();

    // Atomic commit (with EXDEV cross-device fallback)
    if let Err(e) = commit_file_atomic(&tmp_out_path, &out_p) {
        let storage = LocalStorageAdapter::new();
        let _ = storage.shred_file_with_mode(&tmp_out_path, 1, crate::storage::ShredMode::Hdd);
        return Err(format!("Failed to commit encrypted file: {}", e));
    }

    let out_meta = storage.stat(&out_p).map_err(|e| e.to_string())?;

    if shred_source {
        let mode = match shred_mode.as_deref() {
            Some("ssd") | Some("SSD") | Some("nvme") | Some("NVMe") => crate::storage::ShredMode::Ssd,
            _ => crate::storage::ShredMode::Hdd,
        };
        let passes = shred_passes.unwrap_or(3);
        // Surface failures loudly: the user explicitly requested secure deletion
        // (AUDIT.md L5)
        storage.shred_file_with_mode(in_p, passes, mode).map_err(|e| {
            format!("Encryption succeeded, but failed to securely shred the source file: {}", e)
        })?;
    }

    let chunks_count = if chunk_size > 0 {
        (meta.size + (chunk_size as u64) - 1) / (chunk_size as u64)
    } else {
        1
    };

    Ok(EncryptionResult {
        success: true,
        input_path,
        output_path: out_p.to_string_lossy().to_string(),
        original_size: total_encrypted,
        encrypted_size: out_meta.size,
        suite_name: suite.name().to_string(),
        chunks_count,
        elapsed_ms: elapsed,
    })
}

#[tauri::command]
pub fn decrypt_file_cmd(
    input_path: String,
    output_path: Option<String>,
    mut password: String,
    keyfile_path: Option<String>,
    shred_source: bool,
    shred_mode: Option<String>,
    shred_passes: Option<u8>,
) -> Result<DecryptionResult, String> {
    let keyfile_paths: Vec<PathBuf> = match keyfile_path.as_deref() {
        Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p)],
        _ => Vec::new(),
    };

    if password.is_empty() && keyfile_paths.is_empty() {
        return Err("A password or at least one keyfile must be provided".to_string());
    }

    let in_p = Path::new(&input_path);
    if !in_p.exists() {
        return Err(format!("Container file not found on disk: '{}'.", input_path));
    }

    let in_file = File::open(in_p).map_err(|e| e.to_string())?;

    // Streaming direct to atomic temporary file with 0600 permissions
    let mut rng = OsRng;
    let rand_suffix: u64 = rng.next_u64();
    let parent_dir = in_p.parent().unwrap_or_else(|| Path::new("."));
    let tmp_out_path = parent_dir.join(format!(".miragex_dec_{}.tmp", rand_suffix));

    #[cfg(unix)]
    let mut tmp_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_out_path)
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(unix))]
    let mut tmp_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&tmp_out_path)
        .map_err(|e| e.to_string())?;

    let effective_password = crate::crypto::keyfile::apply_keyfile_paths(password.as_bytes(), &keyfile_paths)?;
    password.zeroize();

    let start = Instant::now();
    let decrypt_res: Result<Manifest, _> = decrypt_stream(
        in_file,
        &mut tmp_file,
        &effective_password,
        DecryptOptions::default(),
        |_| {},
    );

    // Scrub password string
    password.zeroize();

    let manifest = match decrypt_res {
        Ok(m) => m,
        Err(e) => {
            // Decryption or integrity check failed: securely wipe temporary file with shredder
            let storage = LocalStorageAdapter::new();
            let _ = storage.shred_file_with_mode(&tmp_out_path, 1, crate::storage::ShredMode::Hdd);
            return Err(e.to_string());
        }
    };

    // fsync before rename to guarantee data durability (MXA-11)
    if let Err(e) = tmp_file.sync_all() {
        let storage = LocalStorageAdapter::new();
        let _ = storage.shred_file_with_mode(&tmp_out_path, 1, crate::storage::ShredMode::Hdd);
        return Err(format!("Failed to fsync temporary decrypted file: {}", e));
    }
    drop(tmp_file);

    let elapsed = start.elapsed().as_millis();

    // Security Hardening: Sanitize original_filename to prevent Path Traversal
    let sanitized_filename = sanitize_filename(&manifest.original_filename);

    let out_p = match output_path {
        Some(p) => PathBuf::from(p),
        // The filename comes from the (attacker-controllable) manifest: never
        // silently overwrite an existing file with it.
        None => unique_output_path(&parent_dir.join(&sanitized_filename)),
    };

    // Commit decrypted file atomically (with EXDEV fallback)
    if let Err(e) = commit_file_atomic(&tmp_out_path, &out_p) {
        let storage = LocalStorageAdapter::new();
        let _ = storage.shred_file_with_mode(&tmp_out_path, 1, crate::storage::ShredMode::Hdd);
        return Err(format!("Failed to save decrypted file: {}", e));
    }

    if shred_source {
        let storage = LocalStorageAdapter::new();
        let mode = match shred_mode.as_deref() {
            Some("ssd") | Some("SSD") | Some("nvme") | Some("NVMe") => crate::storage::ShredMode::Ssd,
            _ => crate::storage::ShredMode::Hdd,
        };
        let passes = shred_passes.unwrap_or(3);
        // Surface failures loudly: the user explicitly requested secure deletion
        // (AUDIT.md L5)
        storage.shred_file_with_mode(in_p, passes, mode).map_err(|e| {
            format!("Decryption succeeded, but failed to securely shred the container: {}", e)
        })?;
    }

    Ok(DecryptionResult {
        success: true,
        input_path,
        output_path: out_p.to_string_lossy().to_string(),
        original_filename: sanitized_filename,
        restored_size: manifest.original_size,
        sha256_hex: hex::encode(manifest.sha256_hash),
        elapsed_ms: elapsed,
    })
}

#[tauri::command]
pub fn inspect_container_cmd(input_path: String) -> Result<ContainerInspection, String> {
    let in_p = Path::new(&input_path);
    if !in_p.exists() {
        return Err(format!("File not found: {}", input_path));
    }

    let file = File::open(in_p).map_err(|e| e.to_string())?;
    inspect_container(file).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn shred_file_cmd(
    input_path: String,
    passes: Option<u8>,
    mode: Option<String>,
) -> Result<String, String> {
    let in_p = Path::new(&input_path);
    if !in_p.exists() {
        return Err(format!("Target file not found: {}", input_path));
    }

    // Backend Safety Scope: Ensure target is not a symlink and is a regular file before proceeding with destruction (MXA-03)
    let sym_meta = fs::symlink_metadata(in_p).map_err(|e| e.to_string())?;
    if sym_meta.file_type().is_symlink() {
        return Err(format!("Security restriction: '{}' is a symbolic link. Shredding symlinks is prohibited.", input_path));
    }
    if !sym_meta.is_file() {
        return Err(format!("Security restriction: '{}' is a directory or special device, not a regular file.", input_path));
    }

    let storage = LocalStorageAdapter::new();
    let num_passes = passes.unwrap_or(3);
    let shred_mode = match mode.as_deref() {
        Some("ssd") | Some("SSD") | Some("nvme") | Some("NVMe") => crate::storage::ShredMode::Ssd,
        _ => crate::storage::ShredMode::Hdd,
    };

    storage.shred_file_with_mode(in_p, num_passes, shred_mode).map_err(|e| e.to_string())?;

    let mode_desc = match shred_mode {
        crate::storage::ShredMode::Ssd => "SSD/NVMe Wear-Leveling Mitigation",
        crate::storage::ShredMode::Hdd => "HDD Physical Magnetic Multi-Pass",
    };

    Ok(format!(
        "Successfully wiped and deleted '{}' ({} with {} passes)",
        input_path, mode_desc, num_passes
    ))
}

#[tauri::command]
pub fn generate_pqc_key_cmd(suite_id: Option<u8>) -> Result<PqcKeyInfo, String> {
    let suite = match suite_id {
        Some(id) => PqcSuite::from_u8(id).map_err(|e| e.to_string())?,
        None => PqcSuite::MlKem768,
    };

    let mut rng = OsRng;
    let enc_res = pqc_encapsulate(suite, &mut rng).map_err(|e| e.to_string())?;

    Ok(PqcKeyInfo {
        suite_name: suite.name().to_string(),
        ciphertext_size: enc_res.ciphertext.len(),
        status: "MirageX PQC Keypair and Encapsulation Verified".into(),
    })
}

#[tauri::command]
pub fn run_benchmark_cmd() -> Result<BenchmarkResult, String> {
    let mut rng = OsRng;

    // 1. Benchmark MirageX-768
    let start_768 = Instant::now();
    let iterations = 100;
    for _ in 0..iterations {
        let _ = pqc_encapsulate(PqcSuite::MlKem768, &mut rng).map_err(|e| e.to_string())?;
    }
    let elapsed_768 = start_768.elapsed().as_secs_f64();
    let ml_kem_768_ops = iterations as f64 / elapsed_768;

    // 2. Benchmark MirageX-1024
    let start_1024 = Instant::now();
    for _ in 0..iterations {
        let _ = pqc_encapsulate(PqcSuite::MlKem1024, &mut rng).map_err(|e| e.to_string())?;
    }
    let elapsed_1024 = start_1024.elapsed().as_secs_f64();
    let ml_kem_1024_ops = iterations as f64 / elapsed_1024;

    // 3. Benchmark Argon2id
    let salt = [0x42u8; 32];
    let start_argon = Instant::now();
    let _ = derive_password_key(b"benchmark_password_2026", &salt, 64 * 1024, 3, 4)
        .map_err(|e| e.to_string())?;
    let argon_ms = start_argon.elapsed().as_millis();

    // 4. Benchmark AES-256-GCM
    let key = [0x99u8; 32];
    let nonce = generate_nonce(&mut rng);
    let sample_data = vec![0x33u8; 10 * 1024 * 1024]; // 10 MB
    let start_aes = Instant::now();
    let _ = encrypt_aes_gcm(&key, &nonce, &sample_data, b"bench_aad").map_err(|e| e.to_string())?;
    let elapsed_aes = start_aes.elapsed().as_secs_f64();
    let aes_throughput = 10.0 / elapsed_aes;

    Ok(BenchmarkResult {
        miragex_768_encap_ops_sec: ml_kem_768_ops,
        miragex_1024_encap_ops_sec: ml_kem_1024_ops,
        argon2id_time_ms: argon_ms,
        aes_256_gcm_throughput_mb_s: aes_throughput,
    })
}

#[tauri::command]
pub fn get_initial_file_cmd() -> Result<Option<InitialFilePayload>, String> {
    if let Ok(mut lock) = INITIAL_FILE.lock() {
        Ok(lock.take())
    } else {
        Ok(None)
    }
}

#[cfg(windows)]
pub fn ensure_windows_nobug_icon() -> std::path::PathBuf {
    const NOBUG_ICO_BYTES: &[u8] = include_bytes!("../../icons/nobug.ico");

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let candidate = parent.join("nobug.ico");
            if candidate.exists() {
                return candidate;
            }
            let candidate_res = parent.join("icons").join("nobug.ico");
            if candidate_res.exists() {
                return candidate_res;
            }
        }
    }

    let base_dir = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("APPDATA")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        });
    let target_dir = base_dir.join("MirageX");
    let _ = std::fs::create_dir_all(&target_dir);
    let target_ico = target_dir.join("nobug.ico");

    let should_write = match std::fs::metadata(&target_ico) {
        Ok(meta) => meta.len() != NOBUG_ICO_BYTES.len() as u64,
        Err(_) => true,
    };
    if should_write {
        let _ = std::fs::write(&target_ico, NOBUG_ICO_BYTES);
    }
    target_ico
}

#[cfg(not(windows))]
pub fn ensure_windows_nobug_icon() -> std::path::PathBuf {
    std::path::PathBuf::from("icons/nobug.ico")
}

#[tauri::command]
pub fn setup_context_menu_cmd() -> Result<String, String> {
    #[cfg(windows)]
    {
        if let Ok(exe_path) = std::env::current_exe() {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let exe_str = exe_path.to_string_lossy().to_string();
            let icon_path = ensure_windows_nobug_icon();
            let icon_str = icon_path.to_string_lossy().to_string();

            let run_reg = |args: &[&str]| {
                let _ = std::process::Command::new("reg")
                    .args(args)
                    .creation_flags(CREATE_NO_WINDOW)
                    .output();
            };

            // 1. File Context Menu (*\shell\MirageX.Encrypt)
            run_reg(&["add", "HKCU\\Software\\Classes\\*\\shell\\MirageX.Encrypt", "/ve", "/d", "Cifrar con MirageX (Post-Quantum)", "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\*\\shell\\MirageX.Encrypt", "/v", "Icon", "/d", &format!("\"{}\",0", exe_str), "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\*\\shell\\MirageX.Encrypt\\command", "/ve", "/d", &format!("\"{}\" --gui-encrypt \"%1\"", exe_str), "/f"]);

            // 2. Directory Context Menu (Directory\shell\MirageX.Encrypt)
            run_reg(&["add", "HKCU\\Software\\Classes\\Directory\\shell\\MirageX.Encrypt", "/ve", "/d", "Cifrar con MirageX (Post-Quantum)", "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\Directory\\shell\\MirageX.Encrypt", "/v", "Icon", "/d", &format!("\"{}\",0", exe_str), "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\Directory\\shell\\MirageX.Encrypt\\command", "/ve", "/d", &format!("\"{}\" --gui-encrypt \"%1\"", exe_str), "/f"]);

            // 3. .wraith Context Menu (MirageX.wraith\shell) -> Uses nobug.ico!
            run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\DefaultIcon", "/ve", "/d", &format!("\"{}\",0", icon_str), "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\open", "/ve", "/d", "Descifrar con MirageX (Post-Quantum)", "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\open", "/v", "Icon", "/d", &format!("\"{}\",0", icon_str), "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\open\\command", "/ve", "/d", &format!("\"{}\" --gui-decrypt \"%1\"", exe_str), "/f"]);

            run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\inspect", "/ve", "/d", "Inspeccionar Contenedor WRAITH", "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\inspect", "/v", "Icon", "/d", &format!("\"{}\",0", icon_str), "/f"]);
            run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\inspect\\command", "/ve", "/d", &format!("\"{}\" --gui-inspect \"%1\"", exe_str), "/f"]);

            let _ = std::process::Command::new("ie4uinit.exe")
                .arg("-show")
                .creation_flags(CREATE_NO_WINDOW)
                .output();

            Ok("Menú contextual de Windows Explorer registrado exitosamente.".into())
        } else {
            Err("No se pudo obtener la ruta del ejecutable actual en Windows.".into())
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let services_dir = PathBuf::from(home).join("Library/Services");
            let _ = fs::create_dir_all(&services_dir);

            // Helper to generate automator workflow
            let create_workflow = |name: &str, title: &str, send_types: &str| {
                let workflow_dir = services_dir.join(format!("{}.workflow", name));
                let contents_dir = workflow_dir.join("Contents");
                let _ = fs::create_dir_all(&contents_dir);

                let info_plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSServices</key>
    <array>
        <dict>
            <key>NSBackgroundColorName</key>
            <string>background</string>
            <key>NSBackgroundStrokeColorName</key>
            <string>line</string>
            <key>NSIconName</key>
            <string>NSActionTemplate</string>
            <key>NSMenuItem</key>
            <dict>
                <key>default</key>
                <string>{}</string>
            </dict>
            <key>NSMessage</key>
            <string>runWorkflowAsService</string>
            <key>NSRequiredContext</key>
            <dict>
                <key>NSApplicationIdentifier</key>
                <string>com.apple.finder</string>
            </dict>
            <key>NSSendFileTypes</key>
            <array>
                {}
            </array>
        </dict>
    </array>
</dict>
</plist>"#, title, send_types);

                let doc_wflow = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AMApplicationBuild</key>
    <string>523</string>
    <key>AMApplicationVersion</key>
    <string>2.10</string>
    <key>AMDocumentVersion</key>
    <string>2</string>
    <key>actions</key>
    <array>
        <dict>
            <key>action</key>
            <dict>
                <key>AMAccepts</key>
                <dict>
                    <key>Container</key>
                    <string>List</string>
                    <key>Optional</key>
                    <true/>
                    <key>Types</key>
                    <array>
                        <string>com.apple.cocoa.path</string>
                    </array>
                </dict>
                <key>AMActionVersion</key>
                <string>2.0.3</string>
                <key>AMParameterProperties</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <dict/>
                </dict>
                <key>AMProvides</key>
                <dict>
                    <key>Container</key>
                    <string>List</string>
                    <key>Types</key>
                    <array>
                        <string>com.apple.cocoa.path</string>
                    </array>
                </dict>
                <key>ActionBundlePath</key>
                <string>/System/Library/Automator/Run Shell Script.action</string>
                <key>ActionName</key>
                <string>Run Shell Script</string>
                <key>ActionParameters</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <string>for f in "$@"
do
    open -a "MirageX" "$f" 2>/dev/null || open -a "/Applications/MirageX.app" "$f" 2>/dev/null
done</string>
                    <key>inputMethod</key>
                    <integer>1</integer>
                    <key>shell</key>
                    <string>/bin/bash</string>
                    <key>source</key>
                    <string></string>
                </dict>
                <key>BundleIdentifier</key>
                <string>com.apple.RunShellScript</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"#;

                let _ = fs::write(contents_dir.join("Info.plist"), info_plist);
                let _ = fs::write(contents_dir.join("document.wflow"), doc_wflow);
            };

            // 1. Cifrar con MirageX
            create_workflow(
                "Cifrar con MirageX (Post-Quantum)",
                "Cifrar con MirageX (Post-Quantum)",
                "<string>public.item</string>\n                <string>public.folder</string>"
            );

            // 2. Descifrar con MirageX
            create_workflow(
                "Descifrar con MirageX (Post-Quantum)",
                "Descifrar con MirageX (Post-Quantum)",
                "<string>com.miragesecurity.wraith</string>\n                <string>public.data</string>"
            );

            // 3. Inspeccionar Contenedor WRAITH
            create_workflow(
                "Inspeccionar Contenedor WRAITH",
                "Inspeccionar Contenedor WRAITH",
                "<string>com.miragesecurity.wraith</string>\n                <string>public.data</string>"
            );

            let _ = std::process::Command::new("/System/Library/CoreServices/pbs")
                .arg("-flush")
                .output();

            Ok("Acciones Rápidas y Servicios de Finder en macOS registrados correctamente.".into())
        } else {
            Err("No se pudo resolver el directorio HOME en macOS.".into())
        }
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Ok("Integración de menú contextual completada.".into())
    }
}

pub mod linux_mime;
pub mod preview;
pub mod updater;

pub use updater::{
    check_app_update_cmd, get_changelog_history_cmd, install_app_update_cmd, restart_app_cmd,
    ChangelogEntry, UpdateCheckResult, UpdateProgress,
};

#[tauri::command]
pub fn start_folder_watcher_cmd(config: crate::watcher::WatcherConfig) -> Result<String, String> {
    crate::watcher::start_folder_watcher(config)
}

#[tauri::command]
pub fn stop_folder_watcher_cmd() -> Result<String, String> {
    crate::watcher::stop_folder_watcher()
}

#[tauri::command]
pub fn get_watcher_status_cmd() -> crate::watcher::WatcherStatus {
    crate::watcher::get_watcher_status()
}

#[tauri::command]
pub fn create_backup_archive_cmd(
    source_path: String,
    dest_path: String,
    password: String,
    keyfile_paths: Option<Vec<String>>,
    suite: Option<String>,
) -> Result<crate::backup::BackupResult, String> {
    let pqc_suite = match suite.as_deref() {
        Some("1024") => PqcSuite::MlKem1024,
        _ => PqcSuite::MlKem768,
    };
    crate::backup::create_backup_archive(
        &source_path,
        &dest_path,
        password,
        &keyfile_paths.unwrap_or_default(),
        pqc_suite,
    )
}

#[tauri::command]
pub fn restore_backup_archive_cmd(
    backup_path: String,
    restore_path: String,
    password: String,
    keyfile_paths: Option<Vec<String>>,
) -> Result<crate::backup::RestoreResult, String> {
    crate::backup::restore_backup_archive(
        &backup_path,
        &restore_path,
        password,
        &keyfile_paths.unwrap_or_default(),
    )
}

#[tauri::command]
pub fn inspect_header_for_preview_cmd(file_path: String) -> Result<preview::HeaderPreviewInfo, String> {
    preview::inspect_header_for_preview(&file_path)
}

#[tauri::command]
pub fn setup_quicklook_preview_cmd() -> Result<String, String> {
    preview::setup_quicklook_preview()
}

#[tauri::command]
pub fn setup_linux_desktop_integration_cmd() -> Result<String, String> {
    linux_mime::setup_linux_desktop_integration()
}

#[tauri::command]
pub fn get_linux_integration_status_cmd() -> linux_mime::LinuxIntegrationStatus {
    linux_mime::get_linux_integration_status()
}

#[tauri::command]
pub fn remove_context_menu_cmd() -> Result<String, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let run_reg = |args: &[&str]| {
            let _ = std::process::Command::new("reg")
                .args(args)
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        };

        run_reg(&["delete", "HKCU\\Software\\Classes\\*\\shell\\MirageX.Encrypt", "/f"]);
        run_reg(&["delete", "HKCU\\Software\\Classes\\Directory\\shell\\MirageX.Encrypt", "/f"]);
        run_reg(&["delete", "HKCU\\Software\\Classes\\MirageX.wraith", "/f"]);
        run_reg(&["delete", "HKCU\\Software\\Classes\\.wraith", "/f"]);

        let _ = std::process::Command::new("ie4uinit.exe")
            .arg("-show")
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        Ok("Menú contextual y asociación de .wraith desinstalados de Windows Explorer.".into())
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let services_dir = PathBuf::from(home).join("Library/Services");
            let _ = fs::remove_dir_all(services_dir.join("Cifrar con MirageX (Post-Quantum).workflow"));
            let _ = fs::remove_dir_all(services_dir.join("Descifrar con MirageX (Post-Quantum).workflow"));
            let _ = fs::remove_dir_all(services_dir.join("Inspeccionar Contenedor WRAITH.workflow"));
            let _ = fs::remove_dir_all(services_dir.join("Vista Previa Cabecera WRAITH.workflow"));

            let _ = std::process::Command::new("/System/Library/CoreServices/pbs")
                .arg("-flush")
                .output();

            Ok("Servicios y Acciones Rápidas de MirageX desinstalados de macOS Finder.".into())
        } else {
            Err("No se pudo resolver el directorio HOME.".into())
        }
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Ok("Desinstalación de integración completada.".into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextMenuScripts {
    pub windows_bat: String,
    pub windows_reg: String,
    pub linux_sh: String,
}

#[tauri::command]
pub fn export_context_menu_scripts_cmd() -> ContextMenuScripts {
    let windows_bat = r#"@echo off
title MirageX - Registro de Menu Contextual e Icono .wraith
set "APP_DIR=%~dp0"
set "EXE_PATH=%APP_DIR%miragex.exe"
set "ICO_PATH=%APP_DIR%nobug.ico"

echo [*] Registrando Menu Contextual de Cifrado MirageX...
reg add "HKCU\Software\Classes\*\shell\MirageX.Encrypt" /ve /d "Cifrar con MirageX (Post-Quantum)" /f >nul
reg add "HKCU\Software\Classes\*\shell\MirageX.Encrypt" /v "Icon" /d "\"%EXE_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\*\shell\MirageX.Encrypt\command" /ve /d "\"%EXE_PATH%\" --gui-encrypt \"%%1\"" /f >nul

reg add "HKCU\Software\Classes\Directory\shell\MirageX.Encrypt" /ve /d "Cifrar con MirageX (Post-Quantum)" /f >nul
reg add "HKCU\Software\Classes\Directory\shell\MirageX.Encrypt" /v "Icon" /d "\"%EXE_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\Directory\shell\MirageX.Encrypt\command" /ve /d "\"%EXE_PATH%\" --gui-encrypt \"%%1\"" /f >nul

reg add "HKCU\Software\Classes\.wraith" /ve /d "MirageX.wraith" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith" /ve /d "WRAITH Encrypted Container" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\DefaultIcon" /ve /d "\"%ICO_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\open" /ve /d "Descifrar con MirageX (Post-Quantum)" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\open" /v "Icon" /d "\"%ICO_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\open\command" /ve /d "\"%EXE_PATH%\" --gui-decrypt \"%%1\"" /f >nul

reg add "HKCU\Software\Classes\MirageX.wraith\shell\inspect" /ve /d "Inspeccionar Contenedor WRAITH" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\inspect" /v "Icon" /d "\"%ICO_PATH%\",0" /f >nul
reg add "HKCU\Software\Classes\MirageX.wraith\shell\inspect\command" /ve /d "\"%EXE_PATH%\" --gui-inspect \"%%1\"" /f >nul

ie4uinit.exe -show >nul 2>&1
echo [OK] Menu contextual e icono de MirageX registrados con exito!
pause
"#.into();

    let windows_reg = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\*\shell\MirageX.Encrypt]
@="Cifrar con MirageX (Post-Quantum)"

[HKEY_CURRENT_USER\Software\Classes\Directory\shell\MirageX.Encrypt]
@="Cifrar con MirageX (Post-Quantum)"

[HKEY_CURRENT_USER\Software\Classes\.wraith]
@="MirageX.wraith"

[HKEY_CURRENT_USER\Software\Classes\MirageX.wraith]
@="WRAITH Encrypted Container"
"#.into();

    let linux_sh = r#"#!/usr/bin/env bash
set -e
echo "[*] Instalando asociacion MIME y accesos de MirageX en Linux..."
mkdir -p ~/.local/share/mime/packages ~/.local/share/applications ~/.local/share/icons/hicolor/128x128/mimetypes
cat << 'EOF' > ~/.local/share/mime/packages/miragex-wraith.xml
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
    <mime-type type="application/x-wraith">
        <comment>Contenedor Cifrado Post-Cuantico WRAITH</comment>
        <glob pattern="*.wraith"/>
        <icon name="application-x-wraith"/>
    </mime-type>
</mime-info>
EOF

update-mime-database ~/.local/share/mime 2>/dev/null || true
update-desktop-database ~/.local/share/applications 2>/dev/null || true
echo "[OK] Integracion Linux completada con exito!"
"#.into();

    ContextMenuScripts {
        windows_bat,
        windows_reg,
        linux_sh,
    }
}

#[tauri::command]
pub fn select_folder_dialog() -> Result<Option<String>, String> {
    if let Some(path) = rfd::FileDialog::new().pick_folder() {
        Ok(Some(path.to_string_lossy().to_string()))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub fn open_external_url_cmd(url: String) -> Result<(), String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("Solo se permiten URLs seguras con protocolo http o https".into());
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        std::process::Command::new("cmd")
            .args(&["/c", "start", "", &url])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}




