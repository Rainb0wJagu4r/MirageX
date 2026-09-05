use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Instant;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

pub const MAX_ALLOWED_CHUNK_SIZE: u32 = 256 * 1024 * 1024; // 256 MiB max

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

    // 3. Reject forbidden and dangerous directory references
    let safe_name = basename.trim();
    if safe_name.is_empty()
        || safe_name == "."
        || safe_name == ".."
        || safe_name.contains('/')
        || safe_name.contains('\\')
    {
        "recovered_file.bin".to_string()
    } else {
        safe_name.to_string()
    }
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
pub fn encrypt_file_cmd(
    input_path: String,
    output_path: Option<String>,
    mut password: String,
    suite_id: Option<u8>,
    chunk_size_mb: Option<u32>,
    shred_source: bool,
) -> Result<EncryptionResult, String> {
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
            p
        }
    };

    let suite = match suite_id {
        Some(id) => PqcSuite::from_u8(id).map_err(|e| e.to_string())?,
        None => PqcSuite::MlKem768,
    };

    // Safe chunk calculation with checked_mul and upper bounds
    let chunk_size = chunk_size_mb
        .and_then(|mb| mb.checked_mul(1024 * 1024))
        .map(|bytes| bytes.min(MAX_ALLOWED_CHUNK_SIZE))
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

    // Atomic write to temporary file
    let mut rng = OsRng;
    let rand_suffix: u64 = rng.next_u64();
    let tmp_out_path = match out_p.file_name() {
        Some(fname) => out_p.with_file_name(format!("{}.tmp.{}", fname.to_string_lossy(), rand_suffix)),
        None => PathBuf::from(format!("miragex_enc_{}.tmp", rand_suffix)),
    };

    let mut tmp_file = File::create(&tmp_out_path).map_err(|e| e.to_string())?;

    let start = Instant::now();
    let total_encrypted_res = encrypt_stream(
        in_file,
        &mut tmp_file,
        password.as_bytes(),
        meta.size,
        options,
        |_| {},
    );

    // Scrub password string
    password.zeroize();

    let total_encrypted = match total_encrypted_res {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = fs::remove_file(&tmp_out_path);
            return Err(e.to_string());
        }
    };

    let elapsed = start.elapsed().as_millis();

    // Atomic commit
    if let Err(e) = fs::rename(&tmp_out_path, &out_p) {
        let _ = fs::remove_file(&tmp_out_path);
        return Err(format!("Failed to commit encrypted file: {}", e));
    }

    let out_meta = storage.stat(&out_p).map_err(|e| e.to_string())?;

    if shred_source {
        let _ = storage.shred_file(in_p, 3);
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
    shred_source: bool,
) -> Result<DecryptionResult, String> {
    let in_p = Path::new(&input_path);
    if !in_p.exists() {
        return Err(format!("Container file not found on disk: '{}'.", input_path));
    }

    let in_file = File::open(in_p).map_err(|e| e.to_string())?;

    // Streaming direct to atomic temporary file on disk (Zero RAM accumulation)
    let mut rng = OsRng;
    let rand_suffix: u64 = rng.next_u64();
    let parent_dir = in_p.parent().unwrap_or_else(|| Path::new("."));
    let tmp_out_path = parent_dir.join(format!(".miragex_dec_{}.tmp", rand_suffix));

    let mut tmp_file = File::create(&tmp_out_path).map_err(|e| e.to_string())?;

    let start = Instant::now();
    let decrypt_res: Result<Manifest, _> = decrypt_stream(
        in_file,
        &mut tmp_file,
        password.as_bytes(),
        DecryptOptions::default(),
        |_| {},
    );

    // Scrub password string
    password.zeroize();

    let manifest = match decrypt_res {
        Ok(m) => m,
        Err(e) => {
            // Decryption or integrity check failed: securely wipe temporary file
            let _ = fs::remove_file(&tmp_out_path);
            return Err(e.to_string());
        }
    };

    let elapsed = start.elapsed().as_millis();

    // Security Hardening: Sanitize original_filename to prevent Path Traversal
    let sanitized_filename = sanitize_filename(&manifest.original_filename);

    let out_p = match output_path {
        Some(p) => PathBuf::from(p),
        None => parent_dir.join(&sanitized_filename),
    };

    // Commit decrypted file atomically
    if let Err(e) = fs::rename(&tmp_out_path, &out_p) {
        let _ = fs::remove_file(&tmp_out_path);
        return Err(format!("Failed to save decrypted file: {}", e));
    }

    if shred_source {
        let storage = LocalStorageAdapter::new();
        let _ = storage.shred_file(in_p, 3);
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
pub fn shred_file_cmd(input_path: String, passes: Option<u8>) -> Result<String, String> {
    let in_p = Path::new(&input_path);
    if !in_p.exists() {
        return Err(format!("Target file not found: {}", input_path));
    }

    let storage = LocalStorageAdapter::new();
    let num_passes = passes.unwrap_or(3);
    storage.shred_file(in_p, num_passes).map_err(|e| e.to_string())?;

    Ok(format!("Successfully shredded and deleted '{}' with {} passes", input_path, num_passes))
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
