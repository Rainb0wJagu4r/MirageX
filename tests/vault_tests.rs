use std::fs;
use rand::rngs::OsRng;
use rand::RngCore;

use miragex::commands::{decrypt_file_cmd, encrypt_file_cmd};
use miragex::crypto::keyfile::generate_keyfile;

#[test]
fn test_encrypt_decrypt_with_keyfile_only() {
    let tmp_dir = std::env::temp_dir().join(format!("miragex_kf_test_{}", OsRng.next_u64()));
    fs::create_dir_all(&tmp_dir).unwrap();

    let input_path = tmp_dir.join("confidential.txt");
    fs::write(&input_path, b"Zero-Knowledge Payload with Keyfile Only").unwrap();

    let keyfile_path = tmp_dir.join("test.key");
    let keyfile_bytes = generate_keyfile(64, Some(b"entropy123")).unwrap();
    fs::write(&keyfile_path, &*keyfile_bytes).unwrap();

    let enc_res = encrypt_file_cmd(
        input_path.to_string_lossy().to_string(),
        None,
        String::new(), // Empty password
        Some(keyfile_path.to_string_lossy().to_string()),
        Some(1),
        None,
        false,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(enc_res.success);
    let encrypted_path = enc_res.output_path;

    // Decrypt with keyfile only
    let dec_res = decrypt_file_cmd(
        encrypted_path.clone(),
        Some(tmp_dir.join("restored.txt").to_string_lossy().to_string()),
        String::new(), // Empty password
        Some(keyfile_path.to_string_lossy().to_string()),
        false,
        None,
        None,
    )
    .unwrap();

    assert!(dec_res.success);
    let restored = fs::read(dec_res.output_path).unwrap();
    assert_eq!(restored, b"Zero-Knowledge Payload with Keyfile Only");

    // Decrypt without keyfile must fail
    assert!(decrypt_file_cmd(
        encrypted_path.clone(),
        None,
        String::new(),
        None,
        false,
        None,
        None,
    )
    .is_err());

    // Decrypt with wrong keyfile must fail
    let wrong_keyfile = tmp_dir.join("wrong.key");
    fs::write(&wrong_keyfile, generate_keyfile(64, None).unwrap()).unwrap();
    assert!(decrypt_file_cmd(
        encrypted_path,
        None,
        String::new(),
        Some(wrong_keyfile.to_string_lossy().to_string()),
        false,
        None,
        None,
    )
    .is_err());

    let _ = fs::remove_dir_all(tmp_dir);
}

#[test]
fn test_encrypt_decrypt_with_password_and_keyfile_2fa() {
    let tmp_dir = std::env::temp_dir().join(format!("miragex_2fa_test_{}", OsRng.next_u64()));
    fs::create_dir_all(&tmp_dir).unwrap();

    let input_path = tmp_dir.join("sensitive.pdf");
    fs::write(&input_path, b"%PDF-1.7 Ultra Confidential 2FA Test").unwrap();

    let keyfile_path = tmp_dir.join("second_factor.key");
    let keyfile_bytes = generate_keyfile(128, Some(b"entropy456")).unwrap();
    fs::write(&keyfile_path, &*keyfile_bytes).unwrap();

    let password = "correct_horse_battery_staple".to_string();

    let enc_res = encrypt_file_cmd(
        input_path.to_string_lossy().to_string(),
        None,
        password.clone(),
        Some(keyfile_path.to_string_lossy().to_string()),
        Some(2), // ML-KEM-1024
        None,
        false,
        None,
        None,
        None,
    )
    .unwrap();

    let encrypted_path = enc_res.output_path;

    // Decrypt with correct password AND keyfile
    let dec_res = decrypt_file_cmd(
        encrypted_path.clone(),
        Some(tmp_dir.join("restored.pdf").to_string_lossy().to_string()),
        password.clone(),
        Some(keyfile_path.to_string_lossy().to_string()),
        false,
        None,
        None,
    )
    .unwrap();

    assert!(dec_res.success);
    let restored = fs::read(dec_res.output_path).unwrap();
    assert_eq!(restored, b"%PDF-1.7 Ultra Confidential 2FA Test");

    // Right password, missing keyfile -> FAILS
    assert!(decrypt_file_cmd(
        encrypted_path.clone(),
        None,
        password.clone(),
        None,
        false,
        None,
        None,
    )
    .is_err());

    // Wrong password, right keyfile -> FAILS
    assert!(decrypt_file_cmd(
        encrypted_path,
        None,
        "wrong_password".to_string(),
        Some(keyfile_path.to_string_lossy().to_string()),
        false,
        None,
        None,
    )
    .is_err());

    let _ = fs::remove_dir_all(tmp_dir);
}

/// Regression test for tar-slip via symlink entries: a crafted vault must never
/// be able to create a symlink (or write a file) outside the extraction root.
#[test]
fn test_vault_extraction_rejects_symlink_tar_slip() {
    use std::io::Cursor;
    use miragex::vault::{extract_all_vault, open_vault};
    use miragex::wraith::encryptor::{encrypt_stream, EncryptOptions};

    let base = std::env::temp_dir().join(format!("miragex_slip_{}", OsRng.next_u64()));
    let outside = std::env::temp_dir().join(format!("miragex_outside_{}", OsRng.next_u64()));
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&outside).unwrap();

    // Malicious archive: "evil" is a symlink to an outside directory, followed by
    // "evil/pwned.txt", which a naive extractor would write through the symlink.
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_size(0);
        link_header.set_mode(0o777);
        builder.append_link(&mut link_header, "evil", &outside).unwrap();

        let data = b"ESCAPED";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(data.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "evil/pwned.txt", &data[..])
            .unwrap();
        builder.finish().unwrap();
    }

    let vault_path = base.join("malicious.wvault");
    let mut out = fs::File::create(&vault_path).unwrap();
    encrypt_stream(
        Cursor::new(&tar_bytes),
        &mut out,
        b"password123",
        tar_bytes.len() as u64,
        EncryptOptions {
            original_filename: "vault_payload.tar".into(),
            ..Default::default()
        },
        |_| {},
    )
    .unwrap();
    drop(out);

    let session = open_vault(&vault_path, b"password123", &[]).unwrap();
    // The symlink entry must not be exposed to the browser/extractor.
    assert!(session.entries.iter().all(|e| e.path != "evil"));

    let dest = base.join("dest");
    extract_all_vault(&session.session_id, &dest).unwrap();

    assert!(
        !outside.join("pwned.txt").exists(),
        "tar-slip: file was written outside the extraction root"
    );
    // The file is still restored, but as a regular file under the destination.
    assert!(dest.join("evil").is_dir());
    assert_eq!(fs::read(dest.join("evil/pwned.txt")).unwrap(), b"ESCAPED");

    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&outside);
}

/// Vault creation must reject symlinks, both as direct sources and nested inside
/// a selected folder: following them could include files outside the chosen tree
/// (and symlink loops could hang the packer).
#[cfg(unix)]
#[test]
fn test_create_vault_rejects_symlink_sources() {
    use miragex::crypto::PqcSuite;
    use miragex::vault::create_vault;
    use std::os::unix::fs::symlink;

    let base = std::env::temp_dir().join(format!("miragex_symlink_{}", OsRng.next_u64()));
    fs::create_dir_all(&base).unwrap();

    let target = base.join("real.txt");
    fs::write(&target, b"real content").unwrap();
    let vault = base.join("secure.wvault");

    // 1. Symlink used directly as a source.
    let direct = base.join("direct-link.txt");
    symlink(&target, &direct).unwrap();
    let err = create_vault(&vault, &[direct], b"pw", &[], PqcSuite::MlKem768).unwrap_err();
    assert!(err.contains("symbolic link"), "unexpected error: {err}");
    assert!(!vault.exists());

    // 2. Symlink nested inside a selected folder.
    let folder = base.join("folder");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("ok.txt"), b"ok").unwrap();
    symlink(&target, folder.join("nested-link")).unwrap();

    let err = create_vault(&vault, &[folder], b"pw", &[], PqcSuite::MlKem768).unwrap_err();
    assert!(err.contains("symbolic link"), "unexpected error: {err}");
    assert!(!vault.exists());

    let _ = fs::remove_dir_all(&base);
}

/// Default decrypt output must never overwrite an existing file: the filename
/// comes from the container manifest, which an attacker controls.
#[test]
fn test_decrypt_default_output_does_not_overwrite_existing_file() {
    let tmp = std::env::temp_dir().join(format!("miragex_nooverwrite_{}", OsRng.next_u64()));
    fs::create_dir_all(&tmp).unwrap();

    let input = tmp.join("secret.txt");
    fs::write(&input, b"attacker payload").unwrap();

    let enc = encrypt_file_cmd(
        input.to_string_lossy().to_string(),
        None,
        "pw".to_string(),
        None,
        Some(1),
        None,
        false,
        None,
        None,
        None,
    )
    .unwrap();

    // The original plaintext file still exists at the default output name, so
    // decryption must pick a fresh name instead of clobbering it.
    let before = fs::read(&input).unwrap();
    let dec = decrypt_file_cmd(
        enc.output_path.clone(),
        None,
        "pw".to_string(),
        None,
        false,
        None,
        None,
    )
    .unwrap();

    assert_ne!(dec.output_path, input.to_string_lossy());
    assert!(dec.output_path.contains("secret (1).txt"), "got {}", dec.output_path);
    assert_eq!(fs::read(&input).unwrap(), before, "original file was overwritten");
    assert_eq!(fs::read(&dec.output_path).unwrap(), b"attacker payload");

    let _ = fs::remove_dir_all(tmp);
}

/// Default encryption output must not clobber an existing `.wraith` container.
#[test]
fn test_encrypt_default_output_does_not_overwrite_existing_container() {
    let tmp = std::env::temp_dir().join(format!("miragex_enc_nooverwrite_{}", OsRng.next_u64()));
    fs::create_dir_all(&tmp).unwrap();

    let input = tmp.join("doc.txt");
    fs::write(&input, b"same content").unwrap();

    let enc1 = encrypt_file_cmd(
        input.to_string_lossy().to_string(),
        None,
        "pw".to_string(),
        None,
        Some(1),
        None,
        false,
        None,
        None,
        Some(false),
    )
    .unwrap();
    let enc2 = encrypt_file_cmd(
        input.to_string_lossy().to_string(),
        None,
        "pw".to_string(),
        None,
        Some(1),
        None,
        false,
        None,
        None,
        Some(false),
    )
    .unwrap();

    assert_ne!(enc1.output_path, enc2.output_path);
    assert!(enc2.output_path.contains("doc.txt (1).wraith"), "got {}", enc2.output_path);
    assert!(std::path::Path::new(&enc1.output_path).exists());
    assert!(std::path::Path::new(&enc2.output_path).exists());

    let _ = fs::remove_dir_all(tmp);
}

#[test]
fn test_encrypt_name_fuzzing_by_default_and_roundtrip() {
    let tmp = std::env::temp_dir().join(format!("miragex_fuzz_{}", OsRng.next_u64()));
    fs::create_dir_all(&tmp).unwrap();

    let input = tmp.join("confidential_financial_report.xlsx");
    fs::write(&input, b"top secret financial data").unwrap();

    // Encrypt with default (name_fuzzing: None -> true)
    let enc = encrypt_file_cmd(
        input.to_string_lossy().to_string(),
        None,
        "pass123".to_string(),
        None,
        Some(1),
        None,
        false,
        None,
        None,
        None,
    )
    .unwrap();

    assert!(enc.success);
    assert!(enc.name_fuzzed, "name_fuzzed should be true by default");

    let enc_path = std::path::PathBuf::from(&enc.output_path);
    let enc_filename = enc_path.file_name().unwrap().to_string_lossy();

    // Verify filename on disk does NOT contain the original name or extension
    assert!(!enc_filename.contains("confidential"), "Output filename leaked original name!");
    assert!(!enc_filename.contains("xlsx"), "Output filename leaked original extension!");
    assert!(enc_filename.ends_with(".wraith"), "Output filename must have .wraith extension");

    // Decrypt without specifying output path (None) -> restores to parent dir with original name
    fs::remove_file(&input).unwrap();

    let dec = decrypt_file_cmd(
        enc.output_path.clone(),
        None,
        "pass123".to_string(),
        None,
        false,
        None,
        None,
    )
    .unwrap();

    assert!(dec.success);
    assert_eq!(dec.original_filename, "confidential_financial_report.xlsx");

    let restored_file = tmp.join("confidential_financial_report.xlsx");
    assert!(restored_file.exists(), "Original file name must be restored on disk");
    assert_eq!(fs::read(&restored_file).unwrap(), b"top secret financial data");

    let _ = fs::remove_dir_all(tmp);
}

/// Explicit destinations that are symlinks must be refused (Windows `fs::copy`
/// would otherwise follow the link and overwrite its target).
#[cfg(unix)]
#[test]
fn test_decrypt_rejects_symlink_output() {
    use std::os::unix::fs::symlink;

    let tmp = std::env::temp_dir().join(format!("miragex_symlink_out_{}", OsRng.next_u64()));
    fs::create_dir_all(&tmp).unwrap();

    let input = tmp.join("plain.txt");
    fs::write(&input, b"payload").unwrap();
    let enc = encrypt_file_cmd(
        input.to_string_lossy().to_string(),
        None,
        "pw".to_string(),
        None,
        Some(1),
        None,
        false,
        None,
        None,
        None,
    )
    .unwrap();

    let target = tmp.join("target.txt");
    fs::write(&target, b"do not touch").unwrap();
    let link = tmp.join("link.txt");
    symlink(&target, &link).unwrap();

    let err = decrypt_file_cmd(
        enc.output_path,
        Some(link.to_string_lossy().to_string()),
        "pw".to_string(),
        None,
        false,
        None,
        None,
    )
    .unwrap_err();

    assert!(err.contains("symbolic link"), "unexpected error: {err}");
    assert_eq!(fs::read(&target).unwrap(), b"do not touch");

    let _ = fs::remove_dir_all(tmp);
}

/// Vault packing must reject sources above the in-memory ceiling before
/// reading them (sparse file: only metadata is consulted).
#[test]
fn test_create_vault_rejects_sources_over_limit() {
    use miragex::crypto::PqcSuite;
    use miragex::vault::{create_vault, MAX_VAULT_PLAINTEXT_SIZE};

    let tmp = std::env::temp_dir().join(format!("miragex_vault_limit_{}", OsRng.next_u64()));
    fs::create_dir_all(&tmp).unwrap();

    let big = tmp.join("big.bin");
    let f = fs::File::create(&big).unwrap();
    f.set_len(MAX_VAULT_PLAINTEXT_SIZE + 1).unwrap();
    drop(f);

    let vault = tmp.join("big.wvault");
    let err = create_vault(&vault, &[big], b"pw", &[], PqcSuite::MlKem768).unwrap_err();
    assert!(err.contains("in-memory limit"), "unexpected error: {err}");
    assert!(!vault.exists());

    let _ = fs::remove_dir_all(tmp);
}
