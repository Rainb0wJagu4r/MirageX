use std::fs::{self, File};
use std::io::Write;
use std::thread;
use std::time::Duration;

use miragex::watcher::{
    get_watcher_status, start_folder_watcher, stop_folder_watcher, WatcherConfig,
};
use miragex::wraith::decryptor::{decrypt_stream, DecryptOptions};

#[test]
fn test_folder_watcher_auto_encryption_and_shred() {
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
