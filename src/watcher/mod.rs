use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::keyfile::apply_keyfile_paths;
use crate::crypto::PqcSuite;
use crate::storage::local::LocalStorageAdapter;
use crate::storage::{ShredMode, StorageAdapter};
use crate::wraith::encryptor::{encrypt_stream, EncryptOptions};

fn default_suite() -> String {
    "768".to_string()
}
fn default_filter_mode() -> String {
    "all".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherConfig {
    pub watch_dir: String,
    pub output_dir: String,
    pub password: String,
    #[serde(default)]
    pub keyfile_paths: Vec<String>,
    #[serde(default = "default_suite")]
    pub suite: String,
    #[serde(default)]
    pub shred_source: bool,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default = "default_filter_mode")]
    pub filter_mode: String,
    #[serde(default)]
    pub filter_extensions: Vec<String>,
    #[serde(default)]
    pub inactivity_timeout_minutes: u32,
    #[serde(default = "default_true")]
    pub os_notifications: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherAuditEntry {
    pub timestamp: String,
    pub original_file: String,
    pub relative_path: String,
    pub encrypted_file: String,
    pub file_size: u64,
    pub shred_applied: bool,
    pub sha256_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherStatus {
    pub is_active: bool,
    pub watch_dir: Option<String>,
    pub output_dir: Option<String>,
    pub processed_count: u64,
    pub last_event: Option<String>,
    pub audit_log: Vec<WatcherAuditEntry>,
    pub auto_locked: bool,
    pub recursive: bool,
    pub filter_mode: String,
    pub filter_extensions: Vec<String>,
    pub inactivity_timeout_minutes: u32,
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
                audit_log: Vec::new(),
                auto_locked: false,
                recursive: false,
                filter_mode: "all".into(),
                filter_extensions: Vec::new(),
                inactivity_timeout_minutes: 0,
            },
        }))
    })
}

fn notify_desktop(title: &str, message: &str) {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display notification "{}" with title "{}" sound name "default""#,
            message.replace('"', "\\\""),
            title.replace('"', "\\\"")
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output();
    }

    #[cfg(windows)]
    {
        let script = format!(
            r#"[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null; $n = new-object system.windows.forms.notifyicon; $n.icon = [System.Drawing.SystemIcons]::Information; $n.visible = $true; $n.showballoontip(8, '{}', '{}', [system.windows.forms.tooltipicon]::Info)"#,
            title.replace('\'', "''"),
            message.replace('\'', "''")
        );
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
            .output();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args([title, message, "-i", "security-high"])
            .output();
    }
}

fn current_iso_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;
    format!("D+{} {:02}:{:02}:{:02} UTC", days, hours, minutes, seconds)
}

fn compute_file_sha256(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Some(hex::encode(hasher.finalize()))
}

fn should_process_file(file_name: &str, filter_mode: &str, filter_extensions: &[String]) -> bool {
    let lower = file_name.to_lowercase();
    // System junk, dotfiles and existing containers
    if lower.starts_with('.')
        || lower.starts_with("~$")
        || lower.ends_with(".wraith")
        || lower.ends_with(".tmp")
        || lower.contains(".tmp.")
        || lower.ends_with(".crdownload")
        || lower.ends_with(".part")
        || lower == "thumbs.db"
        || lower == ".ds_store"
        || lower == "desktop.ini"
    {
        return false;
    }

    if filter_mode == "whitelist" && !filter_extensions.is_empty() {
        let path = Path::new(file_name);
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            return filter_extensions.iter().any(|allowed| {
                let clean = allowed.trim().trim_start_matches('.').to_lowercase();
                clean == ext_lower
            });
        }
        return false;
    }

    true
}

fn collect_watch_files(dir: &Path, recursive: bool, base_dir: &Path) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

            if path.is_file() {
                let rel_str = match path.strip_prefix(base_dir) {
                    Ok(rel) => rel.to_string_lossy().to_string(),
                    Err(_) => file_name,
                };
                files.push((path, rel_str));
            } else if path.is_dir() && recursive {
                // Avoid recursing into hidden or system folders
                if !file_name.starts_with('.') && file_name != "node_modules" && file_name != ".git" {
                    let mut sub = collect_watch_files(&path, true, base_dir);
                    files.append(&mut sub);
                }
            }
        }
    }
    files
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
    let mut effective_key = apply_keyfile_paths(config.password.as_bytes(), &config.keyfile_paths)
        .map_err(|e| format!("Error procesando keyfiles: {}", e))?;
    config.password.zeroize();

    let suite = match config.suite.as_str() {
        "1024" => PqcSuite::MlKem1024,
        _ => PqcSuite::MlKem768,
    };
    let shred_source = config.shred_source;
    let recursive = config.recursive;
    let filter_mode = config.filter_mode.clone();
    let filter_extensions = config.filter_extensions.clone();
    let inactivity_minutes = config.inactivity_timeout_minutes;
    let os_notifications = config.os_notifications;

    let thread_handle = thread::spawn(move || {
        let mut file_candidates: HashMap<PathBuf, (u64, Instant)> = HashMap::new();
        let mut last_activity = Instant::now();

        while !stop_clone.load(Ordering::Relaxed) {
            // Check inactivity timeout
            if inactivity_minutes > 0
                && last_activity.elapsed() >= Duration::from_secs(inactivity_minutes as u64 * 60)
            {
                effective_key.zeroize();
                if let Ok(mut m) = manager_clone.lock() {
                    m.status.is_active = false;
                    m.status.auto_locked = true;
                    m.status.last_event = Some(format!(
                        "🔒 Vigilancia bloqueada por inactividad ({} min). Claves purgadas de memoria.",
                        inactivity_minutes
                    ));
                }
                if os_notifications {
                    notify_desktop(
                        "MirageX // Vigilancia Auto-Bloqueada",
                        &format!("Sesión cerrada por inactividad tras {} minutos. Claves purgadas de RAM.", inactivity_minutes),
                    );
                }
                break;
            }

            let candidates = collect_watch_files(&watch_p, recursive, &watch_p);

            for (path, rel_path) in candidates {
                let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

                if !should_process_file(&file_name, &filter_mode, &filter_extensions) {
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
                            let target_dest_dir = if recursive {
                                if let Some(parent) = Path::new(&rel_path).parent() {
                                    out_p.join(parent)
                                } else {
                                    out_p.clone()
                                }
                            } else {
                                out_p.clone()
                            };

                            let _ = fs::create_dir_all(&target_dest_dir);
                            let dest_path = target_dest_dir.join(&out_file_name);

                            // Calculate sha256 for audit
                            let sha256_hash = compute_file_sha256(&path).unwrap_or_else(|| "0000".into());

                            if let Ok(in_file) = File::open(&path) {
                                let options = EncryptOptions {
                                    suite,
                                    chunk_size: 16 * 1024 * 1024,
                                    original_filename: file_name.clone(),
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
                                    last_activity = Instant::now();
                                    let mut shredded = false;
                                    if shred_source {
                                        let storage = LocalStorageAdapter::new();
                                        if storage.shred_file_with_mode(&path, 3, ShredMode::Hdd).is_ok() {
                                            shredded = true;
                                        }
                                    }

                                    let audit_entry = WatcherAuditEntry {
                                        timestamp: current_iso_timestamp(),
                                        original_file: file_name.clone(),
                                        relative_path: rel_path.clone(),
                                        encrypted_file: out_file_name.clone(),
                                        file_size: size,
                                        shred_applied: shredded,
                                        sha256_hash,
                                    };

                                    if let Ok(mut m) = manager_clone.lock() {
                                        m.status.processed_count += 1;
                                        m.status.last_event = Some(format!(
                                            "Cifrado auto: '{}' -> '{}' ({} bytes)",
                                            file_name, out_file_name, size
                                        ));
                                        m.status.audit_log.push(audit_entry);
                                        if m.status.audit_log.len() > 1000 {
                                            m.status.audit_log.remove(0);
                                        }
                                    }

                                    if os_notifications {
                                        notify_desktop(
                                            "MirageX // Archivo Cifrado",
                                            &format!("'{}' cifrado con éxito como .wraith ({} KB)", file_name, size / 1024),
                                        );
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

        effective_key.zeroize();
    });

    manager.handle = Some(WatcherHandle {
        stop_signal,
        thread_handle: Some(thread_handle),
    });

    manager.status.is_active = true;
    manager.status.auto_locked = false;
    manager.status.watch_dir = Some(config.watch_dir.clone());
    manager.status.output_dir = Some(config.output_dir.clone());
    manager.status.recursive = config.recursive;
    manager.status.filter_mode = config.filter_mode;
    manager.status.filter_extensions = config.filter_extensions;
    manager.status.inactivity_timeout_minutes = config.inactivity_timeout_minutes;
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
            audit_log: Vec::new(),
            auto_locked: false,
            recursive: false,
            filter_mode: "all".into(),
            filter_extensions: Vec::new(),
            inactivity_timeout_minutes: 0,
        }
    }
}

pub fn export_watcher_audit_log(format: &str) -> Result<String, String> {
    let status = get_watcher_status();
    match format.to_lowercase().as_str() {
        "csv" => {
            let mut out = String::from("Timestamp,Original_File,Relative_Path,Encrypted_File,Size_Bytes,Shred_Applied,SHA256\n");
            for item in &status.audit_log {
                out.push_str(&format!(
                    "\"{}\",\"{}\",\"{}\",\"{}\",{},{},\"{}\"\n",
                    item.timestamp.replace('"', "\"\""),
                    item.original_file.replace('"', "\"\""),
                    item.relative_path.replace('"', "\"\""),
                    item.encrypted_file.replace('"', "\"\""),
                    item.file_size,
                    item.shred_applied,
                    item.sha256_hash
                ));
            }
            Ok(out)
        }
        _ => {
            // Default jsonl
            let mut out = String::new();
            for item in &status.audit_log {
                if let Ok(line) = serde_json::to_string(item) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            Ok(out)
        }
    }
}
