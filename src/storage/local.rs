use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::storage::{StorageAdapter, StorageError, StorageMetadata};

pub struct LocalStorageAdapter;

impl LocalStorageAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl StorageAdapter for LocalStorageAdapter {
    fn save_stream(&self, path: &Path, reader: &mut dyn Read) -> Result<u64, StorageError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write to temporary atomic file first
        let mut rng = OsRng;
        let rand_suffix: u64 = rng.next_u64();
        let tmp_path = match path.file_name() {
            Some(fname) => path.with_file_name(format!("{}.tmp.{}", fname.to_string_lossy(), rand_suffix)),
            None => PathBuf::from(format!("miragex_tmp_{}", rand_suffix)),
        };

        let mut file = File::create(&tmp_path)?;
        let mut buffer = [0u8; 64 * 1024]; // 64 KB buffer for streaming
        let mut total_bytes = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            file.write_all(&buffer[..bytes_read])?;
            total_bytes += bytes_read as u64;
        }

        file.flush()?;
        file.sync_all()?;
        drop(file);

        // Atomic rename to target path
        fs::rename(&tmp_path, path)?;

        Ok(total_bytes)
    }

    fn open_stream(&self, path: &Path) -> Result<Box<dyn Read + Send>, StorageError> {
        if !path.exists() {
            return Err(StorageError::NotFound(path.display().to_string()));
        }
        let file = File::open(path)?;
        Ok(Box::new(file))
    }

    fn shred_file(&self, path: &Path, passes: u8) -> Result<(), StorageError> {
        if !path.exists() {
            return Err(StorageError::NotFound(path.display().to_string()));
        }

        let metadata = fs::metadata(path)?;
        let file_size = metadata.len();
        let num_passes = passes.max(1);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let mut rng = OsRng;
        let chunk_size = 64 * 1024; // 64 KB wipe chunk
        let mut wipe_buf = vec![0u8; chunk_size];

        for pass in 0..num_passes {
            file.seek(SeekFrom::Start(0))?;
            let mut remaining = file_size;

            while remaining > 0 {
                let write_size = remaining.min(chunk_size as u64) as usize;
                let slice = &mut wipe_buf[..write_size];

                match pass % 3 {
                    0 => rng.fill_bytes(slice),     // Random CSPRNG
                    1 => slice.fill(0x55),           // Complement pattern
                    _ => slice.fill(0x00),           // Zero out
                }

                file.write_all(slice)?;
                remaining -= write_size as u64;
            }

            file.flush()?;
            file.sync_all()?;
        }

        // Truncate file to 0 bytes
        file.set_len(0)?;
        file.sync_all()?;
        drop(file);

        // Rename to random obfuscated name before unlink
        let rand_name: u64 = rng.next_u64();
        let obfuscated_path = path.with_file_name(format!(".shredded_{}", rand_name));
        let _ = fs::rename(path, &obfuscated_path);

        // Final removal
        fs::remove_file(if obfuscated_path.exists() { &obfuscated_path } else { path })?;

        Ok(())
    }

    fn delete_file(&self, path: &Path) -> Result<(), StorageError> {
        if !path.exists() {
            return Ok(());
        }
        fs::remove_file(path)?;
        Ok(())
    }

    fn stat(&self, path: &Path) -> Result<StorageMetadata, StorageError> {
        let meta = fs::metadata(path)?;
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let modified_timestamp = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(StorageMetadata {
            name,
            path: path.to_string_lossy().to_string(),
            size: meta.len(),
            is_dir: meta.is_dir(),
            modified_timestamp,
        })
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}
