use std::fs;

use miragex::backup::{create_backup_archive, restore_backup_archive};
use miragex::crypto::PqcSuite;

#[test]
fn test_backup_blinded_hash_engine_roundtrip() {
    let temp_base = std::env::temp_dir().join(format!("miragex_backup_test_{}", std::process::id()));
    let source_dir = temp_base.join("source_data");
    let backup_dir = temp_base.join("encrypted_backup_target");
    let restore_dir = temp_base.join("restored_data");

    let _ = fs::remove_dir_all(&temp_base);
    fs::create_dir_all(&source_dir).expect("Create source dir");

    // Create nested directory structure
    let _sub1 = source_dir.join("financials");
    let sub2 = source_dir.join("financials/2026");
    let sub3 = source_dir.join("personal/passwords");
    fs::create_dir_all(&sub2).expect("Create sub2");
    fs::create_dir_all(&sub3).expect("Create sub3");

    let file1 = source_dir.join("readme.md");
    let file2 = sub2.join("q3_balance.csv");
    let file3 = sub3.join("vault_keys.txt");

    fs::write(&file1, b"# Confidential Readme for Backup Engine").expect("Write file1");
    fs::write(&file2, b"account,balance\n1234,999999.50\n5678,450000.00").expect("Write file2");
    fs::write(&file3, b"master_key_alpha_omega_99").expect("Write file3");

    let password = "BackupUltraStrongPassword_2026!".to_string();

    // 1. Create backup archive with blinded IDs
    let backup_res = create_backup_archive(
        &source_dir.to_string_lossy(),
        &backup_dir.to_string_lossy(),
        password.clone(),
        &[],
        PqcSuite::MlKem768,
    ).expect("create_backup_archive should succeed");

    assert!(backup_res.success);
    assert_eq!(backup_res.total_files, 3);
    assert!(backup_res.total_bytes > 0);

    // Verify backup folder contents:
    // MUST contain backup_manifest.wraith
    let manifest_path = backup_dir.join("backup_manifest.wraith");
    assert!(manifest_path.is_file(), "backup_manifest.wraith must exist");

    // Verify that NO plaintext filenames appear in backup_dir
    for entry in fs::read_dir(&backup_dir).expect("Read backup dir").flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            name == "backup_manifest.wraith" || (name.ends_with(".wraith") && name.len() == 64 + 7),
            "Files in backup must have 64-char hex blinded names + .wraith, found: {}",
            name
        );
        assert!(!name.contains("readme"), "Must not leak 'readme'");
        assert!(!name.contains("balance"), "Must not leak 'balance'");
        assert!(!name.contains("vault_keys"), "Must not leak 'vault_keys'");
    }

    // 2. Restore backup archive into restore_dir
    let restore_res = restore_backup_archive(
        &backup_dir.to_string_lossy(),
        &restore_dir.to_string_lossy(),
        password.clone(),
        &[],
    ).expect("restore_backup_archive should succeed");

    assert!(restore_res.success);
    assert_eq!(restore_res.restored_files, 3);

    // Verify restored file contents match originals byte-for-byte
    let res_f1 = restore_dir.join("readme.md");
    let res_f2 = restore_dir.join("financials/2026/q3_balance.csv");
    let res_f3 = restore_dir.join("personal/passwords/vault_keys.txt");

    assert!(res_f1.is_file(), "Restored file 1 must exist at correct path");
    assert!(res_f2.is_file(), "Restored file 2 must exist in nested subfolder");
    assert!(res_f3.is_file(), "Restored file 3 must exist in deep subfolder");

    assert_eq!(fs::read(&res_f1).unwrap(), b"# Confidential Readme for Backup Engine");
    assert_eq!(fs::read(&res_f2).unwrap(), b"account,balance\n1234,999999.50\n5678,450000.00");
    assert_eq!(fs::read(&res_f3).unwrap(), b"master_key_alpha_omega_99");

    // 3. Test wrong password fails to restore
    let wrong_restore_res = restore_backup_archive(
        &backup_dir.to_string_lossy(),
        &restore_dir.to_string_lossy(),
        "WrongPassword123!".to_string(),
        &[],
    );
    assert!(wrong_restore_res.is_err(), "Restoring with wrong password must fail");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_base);
}
