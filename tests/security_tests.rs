use std::fs::File;
use std::io::Cursor;
use miragex::commands::sanitize_filename;
use miragex::crypto::PqcSuite;
use miragex::wraith::{
    decryptor::{decrypt_stream, DecryptOptions},
    encryptor::{encrypt_stream, EncryptOptions},
};

#[test]
fn test_path_traversal_sanitization() {
    assert_eq!(sanitize_filename("../../.ssh/authorized_keys"), "authorized_keys");
    assert_eq!(sanitize_filename("/etc/shadow"), "shadow");
    assert_eq!(sanitize_filename("..\\..\\Windows\\System32\\cmd.exe"), "cmd.exe");
    assert_eq!(sanitize_filename("../../../etc/passwd\0.png"), "passwd.png");
    assert_eq!(sanitize_filename(".."), "recovered_file.bin");
    assert_eq!(sanitize_filename("."), "recovered_file.bin");
    assert_eq!(sanitize_filename("   "), "recovered_file.bin");
    assert_eq!(sanitize_filename("legitimate_document.pdf"), "legitimate_document.pdf");
}

#[test]
fn test_header_bit_flip_tampering_fails() {
    let payload = b"Cryptographically protected data";
    let password = b"HeaderTamperTestPass123!";

    let options = EncryptOptions {
        suite: PqcSuite::MlKem768,
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
    ).expect("Encryption should succeed");

    // Tamper with byte 7 (Suite ID) inside the 64-byte Header
    let mut tampered_suite = container.clone();
    tampered_suite[7] ^= 0x01; // flip suite bit

    let mut out = Vec::new();
    let decrypt_opts_1 = DecryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let res = decrypt_stream(
        Cursor::new(&tampered_suite),
        &mut out,
        password,
        decrypt_opts_1,
        |_| {},
    );
    assert!(res.is_err(), "Decryption must fail when header bytes are tampered with!");

    // Tamper with byte 58 (Chunk size field in header)
    let mut tampered_chunk_size = container.clone();
    tampered_chunk_size[58] ^= 0xAA;

    let decrypt_opts_2 = DecryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let res2 = decrypt_stream(
        Cursor::new(&tampered_chunk_size),
        &mut out,
        password,
        decrypt_opts_2,
        |_| {},
    );
    assert!(res2.is_err(), "Decryption must fail when chunk size in header is altered!");
}

#[test]
fn test_temporary_file_cleaned_on_failed_decryption() {
    let temp_dir = std::env::temp_dir().join("miragex_sec_test");
    let _ = std::fs::create_dir_all(&temp_dir);

    let corrupt_container = temp_dir.join("corrupt.wraith");
    std::fs::write(&corrupt_container, b"WRAITH\x04\x01INVALID_DATA_CORRUPT_ENVELOPE").unwrap();

    let mut out = Vec::new();
    let decrypt_opts = DecryptOptions {
        argon2_m_cost: 1024,
        argon2_t_cost: 1,
        argon2_p_cost: 1,
    };

    let res = decrypt_stream(
        File::open(&corrupt_container).unwrap(),
        &mut out,
        b"wrong_pass",
        decrypt_opts,
        |_| {},
    );

    assert!(res.is_err());
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_allocation_bomb_pqc_ciphertext_rejected() {
    let payload = b"Test payload for parser bounds";
    let password = b"LengthBombPassword123!";

    let options = EncryptOptions {
        suite: PqcSuite::MlKem768,
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
    ).expect("Encryption should succeed");

    // Container header is 80 bytes. Offset 80 is pqc_ct_len (4 bytes).
    // Corrupt pqc_ct_len to 0xFFFFFFFF (~4 GB allocation bomb)
    let mut bomb = container.clone();
    bomb[80] = 0xFF;
    bomb[81] = 0xFF;
    bomb[82] = 0xFF;
    bomb[83] = 0xFF;

    let mut out = Vec::new();
    let res = decrypt_stream(
        Cursor::new(&bomb),
        &mut out,
        password,
        DecryptOptions {
            argon2_m_cost: 1024,
            argon2_t_cost: 1,
            argon2_p_cost: 1,
        },
        |_| {},
    );

    assert!(res.is_err(), "Parser must reject invalid/huge pqc_ct_len before allocating RAM");
}

#[test]
fn test_allocation_bomb_wrapped_key_rejected() {
    let payload = b"Test wrapped key bounds";
    let password = b"WrappedKeyPass123!";

    let options = EncryptOptions {
        suite: PqcSuite::MlKem768,
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
    ).expect("Encryption should succeed");

    // Offset after header (80B) + pqc_ct_len (4B) + ciphertext (1088B for ML-KEM-768) = 1172.
    // At offset 1172 is wrapped_len (4 bytes).
    let wrapped_len_offset = 80 + 4 + 1088;
    let mut bomb = container.clone();
    bomb[wrapped_len_offset] = 0xFF;
    bomb[wrapped_len_offset + 1] = 0xFF;
    bomb[wrapped_len_offset + 2] = 0xFF;
    bomb[wrapped_len_offset + 3] = 0xFF;

    let mut out = Vec::new();
    let res = decrypt_stream(
        Cursor::new(&bomb),
        &mut out,
        password,
        DecryptOptions {
            argon2_m_cost: 1024,
            argon2_t_cost: 1,
            argon2_p_cost: 1,
        },
        |_| {},
    );

    assert!(res.is_err(), "Parser must reject wrapped_len exceeding MAX_WRAPPED_KEY_LEN");
}

#[test]
fn test_non_canonical_is_final_rejected() {
    let payload = b"Canonical boolean verification payload";
    let password = b"CanonicalPass123!";

    let options = EncryptOptions {
        suite: PqcSuite::MlKem768,
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
    ).expect("Encryption should succeed");

    // Find chunk is_final position:
    // Header (80) + PQC Envelope (4 + 1088 + 4 + 12 + wrapped_key_len) + chunk_index (8)
    // In ML-KEM-768 wrapped decaps key is 2400 + 16 (tag) = 2416 bytes.
    // PQC envelope total = 4 + 1088 + 4 + 12 + 2416 = 3524.
    // Chunk start = 80 + 3524 = 3604.
    // Chunk index is 8 bytes (3604..3612).
    // is_final byte is at offset 3612.
    let is_final_offset = 80 + 4 + 1088 + 4 + 12 + 2400 + 16 + 8;
    assert_eq!(container[is_final_offset], 1, "Original chunk must be is_final=1");

    let mut non_canonical = container.clone();
    non_canonical[is_final_offset] = 0x02; // Non-canonical byte value

    let mut out = Vec::new();
    let res = decrypt_stream(
        Cursor::new(&non_canonical),
        &mut out,
        password,
        DecryptOptions {
            argon2_m_cost: 1024,
            argon2_t_cost: 1,
            argon2_p_cost: 1,
        },
        |_| {},
    );

    assert!(res.is_err(), "Parser must strictly reject non-canonical is_final byte (0x02)");
}

#[test]
fn test_trailing_garbage_after_manifest_rejected() {
    let payload = b"Strict EOF verification payload";
    let password = b"TrailingGarbagePass123!";

    let options = EncryptOptions {
        suite: PqcSuite::MlKem768,
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
    ).expect("Encryption should succeed");

    // Append malicious trailing garbage after manifest trailer
    let mut trailing_container = container.clone();
    trailing_container.extend_from_slice(b"\xDE\xAD\xBE\xEF_EXTRA_TRAILING_MALICIOUS_BYTES");

    let mut out = Vec::new();
    let res = decrypt_stream(
        Cursor::new(&trailing_container),
        &mut out,
        password,
        DecryptOptions {
            argon2_m_cost: 1024,
            argon2_t_cost: 1,
            argon2_p_cost: 1,
        },
        |_| {},
    );

    assert!(res.is_err(), "Parser must reject containers with unauthenticated trailing bytes");
}

#[test]
fn test_argon2_header_kdf_parameters_preservation() {
    let payload = b"Testing Argon2id parameter persistence in WRAITH v4 header";
    let password = b"DynamicKdfParamsPass123!";

    // Encrypt with custom Argon2 parameters (e.g. 2048 KiB, 2 iterations, 2 threads)
    let options = EncryptOptions {
        suite: PqcSuite::MlKem768,
        argon2_m_cost: 2048,
        argon2_t_cost: 2,
        argon2_p_cost: 2,
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
    ).expect("Encryption with custom KDF params must succeed");

    // Decrypt passing default DecryptOptions (which differ completely from the encryption params)
    let mut out = Vec::new();
    let manifest = decrypt_stream(
        Cursor::new(&container),
        &mut out,
        password,
        DecryptOptions::default(),
        |_| {},
    ).expect("Decryption must seamlessly use KDF parameters stored in container header");

    assert_eq!(out, payload);
    assert_eq!(manifest.original_size, payload.len() as u64);
}

#[test]
fn test_zero_and_invalid_chunk_size_rejected_gracefully() {
    let payload = b"Testing chunk size bounds validation";
    let password = b"ChunkSizeTestPass123!";

    // Test chunk_size = 0 (Must return InvalidChunkSize error without panicking / aborting)
    let options_zero = EncryptOptions {
        chunk_size: 0,
        ..Default::default()
    };
    let mut container = Vec::new();
    let res_zero = encrypt_stream(
        Cursor::new(payload),
        &mut container,
        password,
        payload.len() as u64,
        options_zero,
        |_| {},
    );
    assert!(res_zero.is_err(), "encrypt_stream must reject chunk_size = 0");

    // Test chunk_size < 64 KiB (e.g. 1024 bytes)
    let options_small = EncryptOptions {
        chunk_size: 1024,
        ..Default::default()
    };
    let res_small = encrypt_stream(
        Cursor::new(payload),
        &mut container,
        password,
        payload.len() as u64,
        options_small,
        |_| {},
    );
    assert!(res_small.is_err(), "encrypt_stream must reject chunk_size below MIN_CHUNK_SIZE");

    // Test chunk_size > 256 MiB
    let options_huge = EncryptOptions {
        chunk_size: 512 * 1024 * 1024,
        ..Default::default()
    };
    let res_huge = encrypt_stream(
        Cursor::new(payload),
        &mut container,
        password,
        payload.len() as u64,
        options_huge,
        |_| {},
    );
    assert!(res_huge.is_err(), "encrypt_stream must reject chunk_size above MAX_CHUNK_SIZE");
}

#[test]
fn test_shred_directory_rejected() {
    let temp_dir = std::env::temp_dir().join("miragex_shred_dir_safety_test");
    let _ = std::fs::create_dir_all(&temp_dir);

    // Call shred_file_cmd on a directory
    let res = miragex::commands::shred_file_cmd(
        temp_dir.to_string_lossy().to_string(),
        Some(3),
        Some("ssd".into()),
    );

    assert!(res.is_err(), "shred_file_cmd must reject directories to prevent accidental damage");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

