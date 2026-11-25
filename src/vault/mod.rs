//! MirageX Cyber Vault Engine (VeraCrypt & Arcanum inspired container system).
//!
//! Provides portable, driver-free encrypted multi-file vaults (.wvault / .wraith)
//! supporting VeraCrypt/Arcanum-style Password + Keyfile authentication, directory
//! tree packing, in-memory browsing, selective extraction, and memory zeroization.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::keyfile::apply_keyfile_paths;
use crate::crypto::PqcSuite;
use crate::wraith::decryptor::{decrypt_stream, DecryptOptions};
use crate::wraith::encryptor::{encrypt_stream, EncryptOptions};
use crate::wraith::DEFAULT_CHUNK_SIZE;

/// Manifest `original_filename` marker that identifies a WRAITH container as a
/// MirageX vault payload (as opposed to a regular single-file container).
pub const VAULT_PAYLOAD_NAME: &str = "vault_payload.tar";

/// Hard ceiling for the plaintext TAR of a vault. Vaults are packed and
/// decrypted in memory, so this bounds peak RAM usage for both legitimate and
/// attacker-crafted containers (availability / memory-exhaustion defense).
pub const MAX_VAULT_PLAINTEXT_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Reserve for TAR headers and padding when validating source sizes, so a
/// vault created at the limit can still be opened within the same ceiling.
const VAULT_TAR_OVERHEAD_MARGIN: u64 = 64 * 1024 * 1024; // 64 MiB

/// A `Write` sink that refuses to buffer more than `limit` bytes and zeroizes
/// its plaintext buffer when dropped (including every error path).
struct LimitedWriter {
    buf: Zeroizing<Vec<u8>>,
    limit: u64,
}

impl LimitedWriter {
    fn new(limit: u64) -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            limit,
        }
    }

    fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

impl std::io::Write for LimitedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let new_len = (self.buf.len() as u64).saturating_add(data.len() as u64);
        if new_len > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Vault plaintext exceeds the {} GiB in-memory limit",
                    MAX_VAULT_PLAINTEXT_SIZE / (1024 * 1024 * 1024)
                ),
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntryInfo {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSessionInfo {
    pub session_id: String,
    pub vault_path: String,
    pub total_entries: usize,
    pub total_unpacked_size: u64,
    pub entries: Vec<VaultEntryInfo>,
}

pub struct VaultSession {
    pub vault_path: PathBuf,
    pub archive_data: Zeroizing<Vec<u8>>,
    pub entries: Vec<VaultEntryInfo>,
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.archive_data.zeroize();
    }
}

static VAULT_SESSIONS: Mutex<Option<HashMap<String, VaultSession>>> = Mutex::new(None);

fn get_sessions_guard() -> Result<std::sync::MutexGuard<'static, Option<HashMap<String, VaultSession>>>, String> {
    let mut guard = VAULT_SESSIONS
        .lock()
        .map_err(|_| "Failed to lock vault sessions".to_string())?;
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    Ok(guard)
}

/// Verifies that an archive relative path does not escape the destination directory.
pub fn is_safe_tar_path(rel_path: &Path) -> bool {
    for comp in rel_path.components() {
        match comp {
            Component::Normal(_) => {}
            _ => return false,
        }
    }
    !rel_path.as_os_str().is_empty()
}

/// Whether an archive entry is safe for extraction. Symlinks, hard links, devices
/// and FIFOs are rejected: a vault created by MirageX only contains regular files
/// and directories, so anything else can only come from a crafted archive and
/// could be used to write outside the extraction root (tar-slip).
fn is_extractable_entry_type(entry_type: tar::EntryType) -> bool {
    entry_type.is_file() || entry_type.is_dir()
}

/// Validates that every source (and everything inside folders) is a regular file
/// or directory, and that the total plaintext stays within the in-memory limit.
/// Symlinks and special files are rejected: following them while packaging could
/// silently include files outside the selected tree, and symlink loops could
/// hang or exhaust memory.
fn validate_source_paths(source_paths: &[PathBuf]) -> Result<u64, String> {
    let mut stack: Vec<PathBuf> = source_paths.to_vec();
    let mut total: u64 = 0;
    let max_sources = MAX_VAULT_PLAINTEXT_SIZE.saturating_sub(VAULT_TAR_OVERHEAD_MARGIN);

    while let Some(path) = stack.pop() {
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("Cannot access source '{}': {}", path.display(), e))?;
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            return Err(format!(
                "Source '{}' is a symbolic link. Vaults only accept regular files and folders; \
                 add the real path instead.",
                path.display()
            ));
        }

        if file_type.is_dir() {
            let entries = fs::read_dir(&path)
                .map_err(|e| format!("Cannot read folder '{}': {}", path.display(), e))?;
            for entry in entries {
                let entry = entry
                    .map_err(|e| format!("Cannot read folder '{}': {}", path.display(), e))?;
                stack.push(entry.path());
            }
        } else if !file_type.is_file() {
            return Err(format!(
                "Source '{}' is not a regular file or folder (device, socket or FIFO).",
                path.display()
            ));
        } else {
            total = total
                .checked_add(meta.len())
                .ok_or_else(|| "Vault source size overflow".to_string())?;
            if total > max_sources {
                return Err(format!(
                    "Vault sources exceed the {} GiB in-memory limit. \
                     Split the content into smaller vaults.",
                    MAX_VAULT_PLAINTEXT_SIZE / (1024 * 1024 * 1024)
                ));
            }
        }
    }

    Ok(total)
}

/// Creates a new encrypted vault container from one or more source paths.
pub fn create_vault(
    output_vault_path: &Path,
    source_paths: &[PathBuf],
    password: &[u8],
    keyfile_paths: &[PathBuf],
    suite: PqcSuite,
) -> Result<u64, String> {
    if password.is_empty() && keyfile_paths.is_empty() {
        return Err("A password or at least one keyfile must be provided".to_string());
    }

    if source_paths.is_empty() {
        return Err("No source files or folders selected for the vault".to_string());
    }

    // Reject symlinks / special files and enforce the in-memory size ceiling.
    validate_source_paths(source_paths)?;

    // 1. Pack sources into a TAR archive in memory (zeroized on every exit path)
    let mut tar_buf = Zeroizing::new(Vec::new());
    {
        let mut builder = tar::Builder::new(&mut *tar_buf);
        // Defense-in-depth against TOCTOU: never dereference a symlink during packing.
        builder.follow_symlinks(false);

        for src in source_paths {
            if !src.exists() {
                return Err(format!("Source path '{}' does not exist", src.display()));
            }

            let file_name = src
                .file_name()
                .ok_or_else(|| format!("Invalid source path '{}'", src.display()))?;

            if src.is_dir() {
                builder
                    .append_dir_all(file_name, src)
                    .map_err(|e| format!("Failed to archive directory '{}': {}", src.display(), e))?;
            } else {
                let mut f = File::open(src)
                    .map_err(|e| format!("Failed to open file '{}': {}", src.display(), e))?;
                builder
                    .append_file(file_name, &mut f)
                    .map_err(|e| format!("Failed to archive file '{}': {}", src.display(), e))?;
            }
        }

        builder
            .finish()
            .map_err(|e| format!("Failed to finalize TAR archive: {}", e))?;
    }

    let unencrypted_len = tar_buf.len() as u64;
    if unencrypted_len > MAX_VAULT_PLAINTEXT_SIZE {
        return Err(format!(
            "Packed vault is {} bytes, exceeding the {} GiB in-memory limit. \
             Split the content into smaller vaults.",
            unencrypted_len,
            MAX_VAULT_PLAINTEXT_SIZE / (1024 * 1024 * 1024)
        ));
    }

    // 2. Derive effective password using VeraCrypt/Arcanum keyfile pool
    let effective_pwd = apply_keyfile_paths(password, keyfile_paths)?;

    // 3. Encrypt archive into temporary file atomically
    let mut rng = OsRng;
    let rand_suffix: u64 = rng.next_u64();
    let tmp_vault_path = match output_vault_path.file_name() {
        Some(name) => output_vault_path.with_file_name(format!(
            "{}.tmp.{}",
            name.to_string_lossy(),
            rand_suffix
        )),
        None => PathBuf::from(format!("miragex_vault_{}.tmp", rand_suffix)),
    };

    #[cfg(unix)]
    let mut tmp_file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_vault_path)
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(unix))]
    let mut tmp_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&tmp_vault_path)
        .map_err(|e| e.to_string())?;

    let options = EncryptOptions {
        suite,
        chunk_size: DEFAULT_CHUNK_SIZE,
        original_filename: VAULT_PAYLOAD_NAME.into(),
        ..Default::default()
    };

    let enc_res = encrypt_stream(
        Cursor::new(&tar_buf[..]),
        &mut tmp_file,
        &effective_pwd,
        unencrypted_len,
        options,
        |_| {},
    );

    tar_buf.zeroize();

    if let Err(e) = enc_res {
        let _ = fs::remove_file(&tmp_vault_path);
        return Err(format!("Vault encryption failed: {}", e));
    }

    if let Err(e) = tmp_file.sync_all() {
        let _ = fs::remove_file(&tmp_vault_path);
        return Err(format!("Failed to sync temporary vault file: {}", e));
    }
    drop(tmp_file);

    // Commit file atomically. Refuse to write through a symlink: the Windows
    // copy fallback would otherwise follow it and overwrite the link target.
    if let Ok(meta) = fs::symlink_metadata(output_vault_path) {
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(&tmp_vault_path);
            return Err(format!(
                "Refusing to write the vault through symbolic link '{}'",
                output_vault_path.display()
            ));
        }
    }

    if fs::rename(&tmp_vault_path, output_vault_path).is_err() {
        fs::copy(&tmp_vault_path, output_vault_path)
            .map_err(|e| format!("Failed to commit vault container: {}", e))?;
        let _ = fs::remove_file(&tmp_vault_path);
    }

    let meta = fs::metadata(output_vault_path).map_err(|e| e.to_string())?;
    Ok(meta.len())
}

/// Opens an existing encrypted vault container, returning session details for in-app browsing.
pub fn open_vault(
    vault_path: &Path,
    password: &[u8],
    keyfile_paths: &[PathBuf],
) -> Result<VaultSessionInfo, String> {
    if !vault_path.exists() {
        return Err(format!("Vault file '{}' not found", vault_path.display()));
    }

    let effective_pwd = apply_keyfile_paths(password, keyfile_paths)?;

    let mut in_file = File::open(vault_path)
        .map_err(|e| format!("Failed to open vault file '{}': {}", vault_path.display(), e))?;

    // Bounded, zeroizing sink: a malicious container cannot exhaust RAM and the
    // plaintext is scrubbed on every error path as well.
    let mut limited = LimitedWriter::new(MAX_VAULT_PLAINTEXT_SIZE);
    let manifest = decrypt_stream(
        &mut in_file,
        &mut limited,
        &effective_pwd,
        DecryptOptions::default(),
        |_| {},
    )
    .map_err(|e| format!("Vault decryption / authentication failed: {}", e))?;

    // A regular single-file WRAITH container decrypts fine but is not a vault.
    if manifest.original_filename != VAULT_PAYLOAD_NAME {
        return Err(
            "This WRAITH container is a regular encrypted file, not a MirageX vault. \
             Open it from the DECRYPT tab instead."
                .to_string(),
        );
    }

    let decrypted_tar = limited.into_inner();

    // Parse TAR archive entries
    let mut archive = tar::Archive::new(Cursor::new(&decrypted_tar[..]));
    let mut entries_info = Vec::new();
    let mut total_unpacked_size = 0u64;

    let entries = archive
        .entries()
        .map_err(|e| format!("Corrupt TAR archive inside vault: {}", e))?;

    for entry_res in entries {
        let entry = entry_res.map_err(|e| format!("Failed reading TAR entry: {}", e))?;
        let header = entry.header();
        let path = entry
            .path()
            .map_err(|e| format!("Invalid path in archive: {}", e))?
            .to_string_lossy()
            .to_string();

        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());

        let size = header.size().unwrap_or(0);
        let entry_type = header.entry_type();
        let is_dir = entry_type.is_dir();
        let modified = header.mtime().unwrap_or(0);

        // Never expose links/devices/FIFOs: they are not produced by MirageX and
        // cannot be extracted safely.
        if !is_extractable_entry_type(entry_type) {
            continue;
        }

        if !is_dir {
            total_unpacked_size = total_unpacked_size.saturating_add(size);
        }

        entries_info.push(VaultEntryInfo {
            path,
            name,
            size,
            is_dir,
            modified,
        });
    }

    // Generate random 128-bit hex session ID
    let mut session_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut session_bytes);
    let session_id = hex::encode(session_bytes);

    let session = VaultSession {
        vault_path: vault_path.to_path_buf(),
        archive_data: decrypted_tar,
        entries: entries_info.clone(),
    };

    let session_info = VaultSessionInfo {
        session_id: session_id.clone(),
        vault_path: vault_path.to_string_lossy().to_string(),
        total_entries: entries_info.len(),
        total_unpacked_size,
        entries: entries_info,
    };

    let mut lock_guard = get_sessions_guard()?;
    let map = lock_guard.as_mut().unwrap();
    map.insert(session_id, session);

    Ok(session_info)
}

/// Extracts a single entry from an open vault session into the destination directory.
pub fn extract_vault_entry(
    session_id: &str,
    entry_path: &str,
    destination_dir: &Path,
) -> Result<PathBuf, String> {
    if !destination_dir.exists() {
        fs::create_dir_all(destination_dir)
            .map_err(|e| format!("Failed to create destination folder: {}", e))?;
    }

    let lock_guard = get_sessions_guard()?;
    let map = lock_guard.as_ref().unwrap();
    let session = map
        .get(session_id)
        .ok_or_else(|| "Vault session not found or expired".to_string())?;

    let mut archive = tar::Archive::new(Cursor::new(&*session.archive_data));
    let entries = archive
        .entries()
        .map_err(|e| format!("Failed reading TAR entries: {}", e))?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| format!("Archive entry read error: {}", e))?;
        let current_path = entry
            .path()
            .map_err(|e| format!("Invalid path in archive: {}", e))?
            .to_string_lossy()
            .to_string();

        if current_path == entry_path {
            if !entry.header().entry_type().is_file() {
                return Err("Only regular files can be extracted from a vault".to_string());
            }

            let rel_path = Path::new(&current_path);
            if !is_safe_tar_path(rel_path) {
                return Err("Path traversal detected in archive entry".to_string());
            }

            // `unpack_in` canonicalizes the destination parent and refuses to write
            // outside it, defending against symlink-based tar-slip attacks.
            let unpacked = entry
                .unpack_in(destination_dir)
                .map_err(|e| format!("Failed to extract entry: {}", e))?;

            if !unpacked {
                return Err("Entry path escapes the destination directory".to_string());
            }

            return Ok(destination_dir.join(rel_path));
        }
    }

    Err(format!("Entry '{}' not found in vault", entry_path))
}

/// Extracts all entries from an open vault session into the destination directory.
pub fn extract_all_vault(session_id: &str, destination_dir: &Path) -> Result<usize, String> {
    if !destination_dir.exists() {
        fs::create_dir_all(destination_dir)
            .map_err(|e| format!("Failed to create destination folder: {}", e))?;
    }

    let lock_guard = get_sessions_guard()?;
    let map = lock_guard.as_ref().unwrap();
    let session = map
        .get(session_id)
        .ok_or_else(|| "Vault session not found or expired".to_string())?;

    let mut archive = tar::Archive::new(Cursor::new(&*session.archive_data));
    let entries = archive
        .entries()
        .map_err(|e| format!("Failed reading TAR entries: {}", e))?;

    let mut extracted_count = 0;
    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| format!("Archive entry error: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Invalid entry path: {}", e))?
            .to_string_lossy()
            .to_string();

        if !is_safe_tar_path(Path::new(&path)) {
            continue; // Skip dangerous entries with path traversal
        }

        let entry_type = entry.header().entry_type();
        if !is_extractable_entry_type(entry_type) {
            // Links/devices/FIFOs are never created by MirageX and are unsafe to unpack.
            continue;
        }

        let unpacked = entry
            .unpack_in(destination_dir)
            .map_err(|e| format!("Failed to extract '{}': {}", path, e))?;

        if !unpacked {
            continue;
        }

        if entry_type.is_file() {
            extracted_count += 1;
        }
    }

    Ok(extracted_count)
}

/// Closes an active vault session, scrubbing in-memory decrypted archive buffers.
pub fn close_vault(session_id: &str) -> Result<(), String> {
    let mut lock_guard = get_sessions_guard()?;
    let map = lock_guard.as_mut().unwrap();

    if let Some(mut session) = map.remove(session_id) {
        session.archive_data.zeroize();
        Ok(())
    } else {
        Err("Session not found or already closed".to_string())
    }
}

/// Lists entries of an active vault session.
pub fn list_vault_entries(session_id: &str) -> Result<Vec<VaultEntryInfo>, String> {
    let lock_guard = get_sessions_guard()?;
    let map = lock_guard.as_ref().unwrap();
    let session = map
        .get(session_id)
        .ok_or_else(|| "Session not found or expired".to_string())?;
    Ok(session.entries.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_limited_writer_enforces_limit_and_zeroizes() {
        let mut writer = LimitedWriter::new(4);
        writer.write_all(b"abcd").unwrap();
        assert!(writer.write_all(b"e").is_err());
        assert_eq!(&*writer.into_inner(), b"abcd");
    }

    #[test]
    fn test_vault_create_open_extract_roundtrip() {
        let tmp_dir = std::env::temp_dir().join(format!("miragex_test_vault_{}", OsRng.next_u64()));
        fs::create_dir_all(&tmp_dir).unwrap();

        let src_file1 = tmp_dir.join("hello.txt");
        let mut f1 = File::create(&src_file1).unwrap();
        f1.write_all(b"Hello MirageX Cyber Vault!").unwrap();

        let src_file2 = tmp_dir.join("subfolder");
        fs::create_dir_all(&src_file2).unwrap();
        let src_file3 = src_file2.join("document.pdf");
        let mut f3 = File::create(&src_file3).unwrap();
        f3.write_all(b"%PDF-1.4 Mock document bytes").unwrap();

        let vault_file = tmp_dir.join("my_secret.wvault");
        let password = b"vault_password_123";

        // Create vault
        let enc_size = create_vault(
            &vault_file,
            &[src_file1.clone(), src_file2.clone()],
            password,
            &[],
            PqcSuite::MlKem768,
        )
        .unwrap();
        assert!(enc_size > 0);
        assert!(vault_file.exists());

        // Open vault
        let session_info = open_vault(&vault_file, password, &[]).unwrap();
        assert_eq!(session_info.vault_path, vault_file.to_string_lossy());
        assert!(!session_info.entries.is_empty());

        // Extract single entry
        let extract_dir = tmp_dir.join("extracted");
        let ext_file = extract_vault_entry(&session_info.session_id, "hello.txt", &extract_dir).unwrap();
        assert!(ext_file.exists());
        let content = fs::read(&ext_file).unwrap();
        assert_eq!(content, b"Hello MirageX Cyber Vault!");

        // Extract all
        let extract_all_dir = tmp_dir.join("extracted_all");
        let count = extract_all_vault(&session_info.session_id, &extract_all_dir).unwrap();
        assert!(count >= 2);
        assert!(extract_all_dir.join("hello.txt").exists());
        assert!(extract_all_dir.join("subfolder/document.pdf").exists());

        // Close vault
        close_vault(&session_info.session_id).unwrap();
        assert!(list_vault_entries(&session_info.session_id).is_err());

        // Cleanup
        let _ = fs::remove_dir_all(tmp_dir);
    }
}
