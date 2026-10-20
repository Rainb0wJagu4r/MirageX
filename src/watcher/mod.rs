use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::keyfile::apply_keyfile_paths;
use crate::crypto::PqcSuite;
use crate::storage::local::LocalStorageAdapter;
use crate::storage::{ShredMode, StorageAdapter};
use crate::wraith::encryptor::{encrypt_stream, EncryptOptions};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherConfig {
    pub watch_dir: String,
    pub output_dir: String,
    pub password: String,
    pub keyfile_paths: Vec<String>,
    pub suite: String,
    pub shred_source: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherStatus {
    pub is_active: bool,
    pub watch_dir: Option<String>,
    pub output_dir: Option<String>,
    pub processed_count: u64,
    pub last_event: Option<String>,
}

struct WatcherHandle {
    stop_signal: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

struct WatcherManager {
    handle: Option<WatcherHandle>,
    status: WatcherStatus,
}

static WATCHER_MANAGER: OnceLock<Arc<Mutex<WatcherManager>>> = OnceLock::new();

fn get_manager() -> &'static Arc<Mutex<WatcherManager>> {
    WATCHER_MANAGER.get_or_init(|| {
        Arc::new(Mutex::new(WatcherManager {
            handle: None,
            status: WatcherStatus {
                is_active: false,
                watch_dir: None,
                output_dir: None,
                processed_count: 0,
                last_event: None,
            },
        }))
    })
}

pub fn start_folder_watcher(mut config: WatcherConfig) -> Result<String, String> {
    let watch_p = PathBuf::from(&config.watch_dir);
    let out_p = PathBuf::from(&config.output_dir);

    if !watch_p.is_dir() {
        return Err(format!("El directorio a vigilar '{}' no existe o no es carpeta", config.watch_dir));
    }
    if !out_p.is_dir() {
        return Err(format!("El directorio de salida '{}' no existe o no es carpeta", config.output_dir));
    }
    if config.password.is_empty() && config.keyfile_paths.is_empty() {
        return Err("Se requiere al menos una contraseña o un keyfile para el auto-cifrado.".into());
    }

    let manager_arc = get_manager();
    let mut manager = manager_arc.lock().map_err(|e| e.to_string())?;

    if let Some(existing) = manager.handle.take() {
        existing.stop_signal.store(true, Ordering::SeqCst);
        if let Some(th) = existing.thread_handle {
            let _ = th.join();
        }
    }

    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_signal.clone();
    let manager_clone = manager_arc.clone();

    // Derive effective password once
    let effective_key = apply_keyfile_paths(config.password.as_bytes(), &config.keyfile_paths)
        .map_err(|e| format!("Error procesando keyfiles: {}", e))?;
    config.password.zeroize();

    let suite = match config.suite.as_str() {
        "1024" => PqcSuite::MlKem1024,
        _ => PqcSuite::MlKem768,
    };
    let shred_source = config.shred_source;

    let thread_handle = thread::spawn(move || {
        let mut file_candidates: HashMap<PathBuf, (u64, Instant)> = HashMap::new();

        while !stop_clone.load(Ordering::Relaxed) {
            if let Ok(entries) = fs::read_dir(&watch_p) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }

                    // Skip hidden files, temp files, and already encrypted .wraith containers
                    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                    if file_name.starts_with('.')
                        || file_name.ends_with(".wraith")
                        || file_name.ends_with(".tmp")
                        || file_name.contains(".tmp.")
                    {
                        continue;
                    }

                    if let Ok(meta) = fs::metadata(&path) {
                        let size = meta.len();
                        let now = Instant::now();

                        // Check if file is stable (not still being written or copied)
                        if let Some((prev_size, first_seen)) = file_candidates.get(&path) {
                            if *prev_size == size && first_seen.elapsed() >= Duration::from_millis(500) {
                                // File is stable! Proceed with auto-encryption
                                let out_file_name = format!("{}.wraith", file_name);
                                let dest_path = out_p.join(&out_file_name);

                                if let Ok(in_file) = File::open(&path) {
                                    let options = EncryptOptions {
                                        suite,
                                        chunk_size: 16 * 1024 * 1024,
                                        original_filename: file_name.to_string(),
                                        ..Default::default()
                                    };

                                    let tmp_dest = dest_path.with_extension(format!("tmp.{}", now.elapsed().as_micros()));
                                    let enc_result = if let Ok(mut tmp_f) = File::create(&tmp_dest) {
                                        let res = encrypt_stream(
                                            in_file,
                                            &mut tmp_f,
                                            &effective_key,
                                            size,
                                            options,
                                            |_| {},
                                        );
                                        if res.is_ok() {
                                            let _ = fs::rename(&tmp_dest, &dest_path);
                                            true
                                        } else {
                                            let _ = fs::remove_file(&tmp_dest);
                                            false
                                        }
                                    } else {
                                        false
                                    };

                                    if enc_result {
                                        if shred_source {
                                            let storage = LocalStorageAdapter::new();
                                            let _ = storage.shred_file_with_mode(&path, 3, ShredMode::Hdd);
                                        }

                                        if let Ok(mut m) = manager_clone.lock() {
                                            m.status.processed_count += 1;
                                            m.status.last_event = Some(format!(
                                                "Cifrado auto: '{}' -> '{}' ({} bytes)",
                                                file_name, out_file_name, size
                                            ));
                                        }
                                    }
                                }

                                file_candidates.remove(&path);
                            } else {
                                file_candidates.insert(path, (size, now));
                            }
                        } else {
                            file_candidates.insert(path, (size, now));
                        }
                    }
                }
            }

            // Cleanup stale candidates that no longer exist
            file_candidates.retain(|p, _| p.exists());

            // Sleep between polling checks (1500 ms)
            for _ in 0..15 {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    });

    manager.handle = Some(WatcherHandle {
        stop_signal,
        thread_handle: Some(thread_handle),
    });

    manager.status.is_active = true;
    manager.status.watch_dir = Some(config.watch_dir.clone());
    manager.status.output_dir = Some(config.output_dir.clone());
    manager.status.last_event = Some(format!("Vigilancia iniciada en '{}'", config.watch_dir));

    Ok(format!("Carpeta vigilada activada exitosamente en '{}'", config.watch_dir))
}

pub fn stop_folder_watcher() -> Result<String, String> {
    let manager_arc = get_manager();
    let mut manager = manager_arc.lock().map_err(|e| e.to_string())?;

    if let Some(existing) = manager.handle.take() {
        existing.stop_signal.store(true, Ordering::SeqCst);
        if let Some(th) = existing.thread_handle {
            let _ = th.join();
        }
    }

    manager.status.is_active = false;
    manager.status.last_event = Some("Vigilancia detenida por el usuario.".into());

    Ok("Carpeta vigilada detenida con éxito.".into())
}

pub fn get_watcher_status() -> WatcherStatus {
    let manager_arc = get_manager();
    if let Ok(manager) = manager_arc.lock() {
        manager.status.clone()
    } else {
        WatcherStatus {
            is_active: false,
            watch_dir: None,
            output_dir: None,
            processed_count: 0,
            last_event: Some("Error accediendo al estado del vigilante".into()),
        }
    }
}
