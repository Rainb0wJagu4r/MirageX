use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::storage::{StorageAdapter, StorageError, StorageMetadata};

#[derive(Clone, Default)]
pub struct MemoryStorageAdapter {
    files: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryStorageAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_file_content(&self, path: &str) -> Option<Vec<u8>> {
        self.files.read().unwrap().get(path).cloned()
    }
}

impl StorageAdapter for MemoryStorageAdapter {
    fn save_stream(&self, path: &Path, reader: &mut dyn Read) -> Result<u64, StorageError> {
        let mut data = Vec::new();
        let bytes = reader.read_to_end(&mut data)?;
        self.files
            .write()
            .unwrap()
            .insert(path.to_string_lossy().to_string(), data);
        Ok(bytes as u64)
    }

    fn open_stream(&self, path: &Path) -> Result<Box<dyn Read + Send>, StorageError> {
        let key = path.to_string_lossy().to_string();
        let lock = self.files.read().unwrap();
        match lock.get(&key) {
            Some(data) => Ok(Box::new(Cursor::new(data.clone()))),
            None => Err(StorageError::NotFound(key)),
        }
    }

    fn shred_file_with_mode(&self, path: &Path, _passes: u8, _mode: crate::storage::ShredMode) -> Result<(), StorageError> {
        let key = path.to_string_lossy().to_string();
        let mut lock = self.files.write().unwrap();
        if let Some(mut data) = lock.remove(&key) {
            data.fill(0);
            Ok(())
        } else {
            Err(StorageError::NotFound(key))
        }
    }

    fn shred_file(&self, path: &Path, passes: u8) -> Result<(), StorageError> {
        self.shred_file_with_mode(path, passes, crate::storage::ShredMode::Hdd)
    }

    fn delete_file(&self, path: &Path) -> Result<(), StorageError> {
        let key = path.to_string_lossy().to_string();
        self.files.write().unwrap().remove(&key);
        Ok(())
    }

    fn stat(&self, path: &Path) -> Result<StorageMetadata, StorageError> {
        let key = path.to_string_lossy().to_string();
        let lock = self.files.read().unwrap();
        match lock.get(&key) {
            Some(data) => Ok(StorageMetadata {
                name: path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                path: key,
                size: data.len() as u64,
                is_dir: false,
                modified_timestamp: 0,
            }),
            None => Err(StorageError::NotFound(key)),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        let key = path.to_string_lossy().to_string();
        self.files.read().unwrap().contains_key(&key)
    }
}
