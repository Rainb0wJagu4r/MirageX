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
