use std::fs::{self, File};
use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use rand::RngCore;

use miragex::watcher::{
    get_watcher_status, start_folder_watcher, stop_folder_watcher, WatcherConfig,
};
use miragex::wraith::decryptor::{decrypt_stream, DecryptOptions};

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_folder_watcher_auto_encryption_and_shred() {
    let _guard = TEST_LOCK.lock().unwrap();
    let temp_base = std::env::temp_dir().join(format!("miragex_watcher_test_{}", std::process::id()));
    let watch_dir = temp_base.join("watched");
    let output_dir = temp_base.join("encrypted_out");

    let _ = fs::remove_dir_all(&temp_base);
    fs::create_dir_all(&watch_dir).expect("Create watch dir");
    fs::create_dir_all(&output_dir).expect("Create output dir");

    let password = "TestWatcherSecurePassword123!".to_string();

    let config = WatcherConfig {
        watch_dir: watch_dir.to_string_lossy().to_string(),
        output_dir: output_dir.to_string_lossy().to_string(),
        password: password.clone(),
        keyfile_paths: vec![],
        suite: "768".to_string(),
        name_fuzzing: false,
        shred_source: true,
        recursive: true,
        filter_mode: "all".to_string(),
        filter_extensions: vec![],
        inactivity_timeout_minutes: 0,
        os_notifications: false,
    };

    let start_res = start_folder_watcher(config);
    assert!(start_res.is_ok(), "Watcher should start successfully");

    let status = get_watcher_status();
    assert!(status.is_active, "Watcher should report active status");

    // Drop a test file into the watched directory
    let test_file = watch_dir.join("confidential_document.txt");
    let test_payload = b"SUPER_SECRET_QUANTUM_SAFE_PAYLOAD_FOR_AUTO_ENCRYPTION_TEST";
    {
        let mut f = File::create(&test_file).expect("Create test file");
        f.write_all(test_payload).expect("Write payload");
        f.flush().expect("Flush payload");
    }

    // Wait for the watcher polling loop (up to 4 seconds)
    let expected_out = output_dir.join("confidential_document.txt.wraith");
    let mut encrypted_found = false;

    for _ in 0..40 {
        thread::sleep(Duration::from_millis(150));
        if expected_out.exists() {
            encrypted_found = true;
            break;
        }
    }

    assert!(encrypted_found, "Watcher should have created the .wraith container");

    // Check that source file was shredded / removed
    assert!(!test_file.exists(), "Source file should have been securely wiped after encryption");

    // Verify decrypted contents of the auto-encrypted file
    let enc_file = File::open(&expected_out).expect("Open encrypted container");
    let mut decrypted_bytes = Vec::new();

    decrypt_stream(
        enc_file,
        &mut decrypted_bytes,
        password.as_bytes(),
        DecryptOptions::default(),
        |_| {},
    ).expect("Decryption of auto-encrypted file should succeed");

    assert_eq!(decrypted_bytes, test_payload, "Decrypted payload must match original");

    // Stop watcher
    let stop_res = stop_folder_watcher();
    assert!(stop_res.is_ok(), "Watcher should stop cleanly");

    let final_status = get_watcher_status();
    assert!(!final_status.is_active, "Watcher should report inactive after stop");
    assert!(final_status.processed_count >= 1, "Processed count should be at least 1");
    assert!(!final_status.audit_log.is_empty(), "Audit log should have recorded processed file");

    let csv_export = miragex::watcher::export_watcher_audit_log("csv").expect("Export CSV");
    assert!(csv_export.contains("confidential_document.txt"), "CSV should contain filename");
    assert!(csv_export.contains("confidential_document.txt.wraith"), "CSV should contain encrypted filename");

    let jsonl_export = miragex::watcher::export_watcher_audit_log("jsonl").expect("Export JSONL");
    assert!(jsonl_export.contains("confidential_document.txt"), "JSONL should contain filename");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_base);
}

#[test]
fn test_folder_watcher_same_folder_no_loop() {
    let _guard = TEST_LOCK.lock().unwrap();
    let temp_base = std::env::temp_dir().join(format!("miragex_watch_same_{}", OsRng.next_u64()));
    let watch_dir = temp_base.join("shared_inbox");
    fs::create_dir_all(&watch_dir).expect("Create shared inbox");

    let password = "loop_prevention_pwd".to_string();

    // Source and destination are the SAME folder
    let config = WatcherConfig {
        watch_dir: watch_dir.to_string_lossy().to_string(),
        output_dir: watch_dir.to_string_lossy().to_string(),
        password: password.clone(),
        keyfile_paths: vec![],
        suite: "768".to_string(),
        name_fuzzing: false,
        shred_source: true,
        recursive: false,
        filter_mode: "all".to_string(),
        filter_extensions: vec![],
        inactivity_timeout_minutes: 0,
        os_notifications: false,
    };

    let start_res = start_folder_watcher(config);
    assert!(start_res.is_ok(), "Watcher should start on same folder");

    let test_file = watch_dir.join("single_doc.pdf");
    fs::write(&test_file, b"data to encrypt").expect("Write test doc");

    let expected_wraith = watch_dir.join("single_doc.pdf.wraith");

    // Wait up to 5 seconds for processing
    let start_time = Instant::now();
    let mut encrypted_found = false;
    while start_time.elapsed() < Duration::from_secs(5) {
        if expected_wraith.exists() && !test_file.exists() {
            encrypted_found = true;
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }

    assert!(encrypted_found, "File should be encrypted in-place and source shredded");

    // Wait an additional 2.5 seconds to ensure NO infinite loop encrypting .wraith into .wraith.wraith
    thread::sleep(Duration::from_millis(2500));

    let rogue_loop_file = watch_dir.join("single_doc.pdf.wraith.wraith");
    assert!(!rogue_loop_file.exists(), "Watcher must NEVER re-encrypt .wraith files in an infinite loop!");

    let status = get_watcher_status();
    assert_eq!(status.processed_count, 1, "Processed count must remain exactly 1 (no loop)");

    let stop_res = stop_folder_watcher();
    assert!(stop_res.is_ok());

    let _ = fs::remove_dir_all(&temp_base);
}

#[test]
fn test_folder_watcher_name_fuzzing_by_default_and_roundtrip() {
    let _guard = TEST_LOCK.lock().unwrap();
    let temp_base = std::env::temp_dir().join(format!("miragex_watch_fuzz_{}", OsRng.next_u64()));
    let watch_dir = temp_base.join("incoming");
    let output_dir = temp_base.join("vault_out");
    fs::create_dir_all(&watch_dir).expect("Create incoming dir");
    fs::create_dir_all(&output_dir).expect("Create vault_out dir");

    let password = "NameFuzzingSecretKey999!".to_string();

    let config = WatcherConfig {
        watch_dir: watch_dir.to_string_lossy().to_string(),
        output_dir: output_dir.to_string_lossy().to_string(),
        password: password.clone(),
        keyfile_paths: vec![],
        suite: "768".to_string(),
        name_fuzzing: true, // Name fuzzing enabled
        shred_source: true,
        recursive: false,
        filter_mode: "all".to_string(),
        filter_extensions: vec![],
        inactivity_timeout_minutes: 0,
        os_notifications: false,
    };

    let start_res = start_folder_watcher(config);
    assert!(start_res.is_ok(), "Watcher with name fuzzing should start");

    let file_name = "classified_intel.docx";
    let test_file = watch_dir.join(file_name);
    let original_bytes = b"TOP_SECRET_DOCX_PAYLOAD_FUZZED_TEST_2026";
    fs::write(&test_file, original_bytes).expect("Write test file");

    let expected_fuzzed_name = miragex::commands::compute_fuzzed_filename(file_name);
    let expected_fuzzed_path = output_dir.join(&expected_fuzzed_name);

    // Wait up to 5 seconds for processing
    let start_time = Instant::now();
    let mut encrypted_found = false;
    while start_time.elapsed() < Duration::from_secs(5) {
        if expected_fuzzed_path.exists() && !test_file.exists() {
            encrypted_found = true;
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }

    assert!(encrypted_found, "File must be fuzzed as [sha256].wraith and source shredded");
    assert!(!output_dir.join(format!("{}.wraith", file_name)).exists(), "Plain filename.wraith must NOT exist on disk");

    // Decrypt the fuzzed .wraith file and verify original filename metadata is recovered
    let mut enc_file = File::open(&expected_fuzzed_path).expect("Open encrypted container");
    let mut decrypted_bytes = Vec::new();
    let dec_res = decrypt_stream(
        &mut enc_file,
        &mut decrypted_bytes,
        password.as_bytes(),
        DecryptOptions::default(),
        |_| {},
    ).expect("Decryption of fuzzed container must succeed");

    assert_eq!(decrypted_bytes, original_bytes, "Decrypted content must match original payload");
    assert_eq!(dec_res.original_filename, file_name, "Header must preserve original filename for restoration");

    let stop_res = stop_folder_watcher();
    assert!(stop_res.is_ok());

    let _ = fs::remove_dir_all(&temp_base);
}
