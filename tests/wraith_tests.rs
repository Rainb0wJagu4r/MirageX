use std::io::Cursor;
use miragex::crypto::PqcSuite;
use miragex::storage::{local::LocalStorageAdapter, StorageAdapter};
use miragex::wraith::{
    decryptor::{decrypt_stream, DecryptOptions},
    encryptor::{encrypt_stream, EncryptOptions},
    inspect::inspect_container,
};
use rand::rngs::OsRng;
use rand::RngCore;

#[test]
fn test_wraith_v4_768_streaming_roundtrip() {
    let original_payload = b"Quantum-safe classified documents and flight telemetry 2026";
    let password = b"PqcSuperKey768!";

    let options = EncryptOptions {
        suite: PqcSuite::MlKem768,
        chunk_size: 16, // Small chunks to force multiple chunks
        original_filename: "telemetry.dat".into(),
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let mut encrypted_container = Vec::new();
    let bytes_encrypted = encrypt_stream(
        Cursor::new(original_payload),
        &mut encrypted_container,
        password,
        original_payload.len() as u64,
        options,
        |_| {},
    ).expect("Encryption should succeed");

    assert_eq!(bytes_encrypted, original_payload.len() as u64);

    // Inspect container
    let inspection = inspect_container(Cursor::new(&encrypted_container)).expect("Inspection should succeed");
    assert_eq!(inspection.magic, "WRAITH");
    assert_eq!(inspection.version, 4);
    assert_eq!(inspection.suite_id, PqcSuite::MlKem768.as_u8());

    // Decrypt container
    let mut decrypted_payload = Vec::new();
    let decrypt_opts = DecryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let manifest = decrypt_stream(
        Cursor::new(&encrypted_container),
        &mut decrypted_payload,
        password,
        decrypt_opts,
        |_| {},
    ).expect("Decryption should succeed");

    assert_eq!(manifest.original_filename, "telemetry.dat");
    assert_eq!(manifest.original_size, original_payload.len() as u64);
    assert_eq!(original_payload.to_vec(), decrypted_payload);
}

#[test]
fn test_wraith_v4_1024_streaming_roundtrip() {
    let mut large_payload = vec![0u8; 128 * 1024]; // 128 KB
    OsRng.fill_bytes(&mut large_payload);
    let password = b"PqcLevel5MasterPassword!";

    let options = EncryptOptions {
        suite: PqcSuite::MlKem1024,
        chunk_size: 16 * 1024, // 16 KB chunks -> 8 chunks
        original_filename: "archive.tar".into(),
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let mut encrypted_container = Vec::new();
    encrypt_stream(
        Cursor::new(&large_payload),
        &mut encrypted_container,
        password,
        large_payload.len() as u64,
        options,
        |_| {},
    ).expect("Encryption 1024 should succeed");

    let mut decrypted_payload = Vec::new();
    let decrypt_opts = DecryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let manifest = decrypt_stream(
        Cursor::new(&encrypted_container),
        &mut decrypted_payload,
        password,
        decrypt_opts,
        |_| {},
    ).expect("Decryption 1024 should succeed");

    assert_eq!(manifest.original_size, large_payload.len() as u64);
    assert_eq!(large_payload, decrypted_payload);
}

#[test]
fn test_wraith_v4_wrong_password_fails() {
    let payload = b"Sensitive content";
    let password = b"CorrectPassword123";
    let wrong_password = b"IncorrectPassword999";

    let options = EncryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
        ..Default::default()
    };

    let mut container = Vec::new();
    encrypt_stream(
        Cursor::new(payload),
        &mut container,
        password,
        payload.len() as u64,
        options,
        |_| {},
    ).unwrap();

    let mut decrypted = Vec::new();
    let decrypt_opts = DecryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let res = decrypt_stream(
        Cursor::new(&container),
        &mut decrypted,
        wrong_password,
        decrypt_opts,
        |_| {},
    );

    assert!(res.is_err(), "Decryption with wrong password must fail!");
}

#[test]
fn test_wraith_v4_chunk_tamper_fails() {
    let payload = b"Data that must not be tampered with!";
    let password = b"TamperTestPass";

    let options = EncryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
        chunk_size: 8,
        ..Default::default()
    };

    let mut container = Vec::new();
    encrypt_stream(
        Cursor::new(payload),
        &mut container,
        password,
        payload.len() as u64,
        options,
        |_| {},
    ).unwrap();

    // Tamper with a byte inside the encrypted chunks area (after header + envelope)
    let tamper_offset = container.len() - 30;
    container[tamper_offset] ^= 0x55;

    let mut decrypted = Vec::new();
    let decrypt_opts = DecryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let res = decrypt_stream(
        Cursor::new(&container),
        &mut decrypted,
        password,
        decrypt_opts,
        |_| {},
    );

    assert!(res.is_err(), "Decryption of tampered container must fail!");
}

#[test]
fn test_storage_local_shredding() {
    let temp_dir = std::env::temp_dir().join("miragex_test_shred");
    let _ = std::fs::create_dir_all(&temp_dir);
    let test_file = temp_dir.join("test_shred_secret.txt");

    let adapter = LocalStorageAdapter::new();
    let secret_data = b"Wipe me completely with 3 CSPRNG passes!";
    adapter.save_stream(&test_file, &mut Cursor::new(secret_data)).expect("Save should succeed");
    assert!(adapter.exists(&test_file));

    adapter.shred_file(&test_file, 3).expect("Shredding should succeed");
    assert!(!adapter.exists(&test_file), "File must be completely removed after shredding");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_legacy_project_mirage_container() {
    // Simulate legacy Project Mirage v1 C4 container: "MIRAGE\x01\x03" + 16 bytes salt
    let mut legacy_data = Vec::new();
    legacy_data.extend_from_slice(b"MIRAGE\x01\x03");
    legacy_data.extend_from_slice(&[0xaa; 16]); // 16B salt
    legacy_data.extend_from_slice(&[0x00; 100]); // payload

    let inspection = inspect_container(Cursor::new(&legacy_data)).expect("Legacy inspection should succeed");
    assert_eq!(inspection.magic, "MIRAGE");
    assert_eq!(inspection.version, 1);
    assert_eq!(inspection.legacy_project_mirage, true);
    assert_eq!(inspection.is_pqc, false);
    assert!(inspection.suite_name.contains("Mirage-C4"));
}
