use miragex::crypto::{
    aead::{decrypt_aes_gcm, encrypt_aes_gcm, generate_nonce},
    kdf::{derive_master_keys, derive_password_key, derive_pqc_wrap_key},
    kem::{pqc_decapsulate, pqc_encapsulate},
    PqcSuite,
};
use rand::rngs::OsRng;

#[test]
fn test_kem_768_roundtrip() {
    let mut rng = OsRng;
    let enc_res = pqc_encapsulate(PqcSuite::MlKem768, &mut rng).expect("Encapsulation should succeed");
    assert_eq!(enc_res.ciphertext.len(), PqcSuite::MlKem768.ciphertext_size());

    let recovered_ss = pqc_decapsulate(
        PqcSuite::MlKem768,
        &enc_res.decapsulation_key_bytes,
        &enc_res.ciphertext,
    ).expect("Decapsulation should succeed");

    assert_eq!(*enc_res.shared_secret, *recovered_ss);
}

#[test]
fn test_kem_1024_roundtrip() {
    let mut rng = OsRng;
    let enc_res = pqc_encapsulate(PqcSuite::MlKem1024, &mut rng).expect("Encapsulation should succeed");
    assert_eq!(enc_res.ciphertext.len(), PqcSuite::MlKem1024.ciphertext_size());

    let recovered_ss = pqc_decapsulate(
        PqcSuite::MlKem1024,
        &enc_res.decapsulation_key_bytes,
        &enc_res.ciphertext,
    ).expect("Decapsulation should succeed");

    assert_eq!(*enc_res.shared_secret, *recovered_ss);
}

#[test]
fn test_argon2_and_hkdf_domain_separation() {
    let password = b"UltraSecurePqcPassword2026!";
    let salt = [0x42u8; 32];
    let container_uuid = [0x77u8; 16];
    let pqc_ss = [0x99u8; 32];

    let pwd_key = derive_password_key(password, &salt, 1024, 1, 1).expect("Argon2 should succeed");
    let wrap_key = derive_pqc_wrap_key(&*pwd_key, &salt, &container_uuid).expect("Wrap key should succeed");
    let master_keys = derive_master_keys(&*pwd_key, &pqc_ss, &container_uuid, &salt)
        .expect("HKDF should succeed");

    // Ensure all derived keys are distinct
    assert_ne!(master_keys.dek, master_keys.manifest_key);
    assert_ne!(master_keys.dek, *wrap_key);
    assert_ne!(master_keys.manifest_key, *wrap_key);
}

#[test]
fn test_aead_aes_gcm_tamper_detection() {
    let mut rng = OsRng;
    let key = [0x11u8; 32];
    let nonce = generate_nonce(&mut rng);
    let plaintext = b"Classified quantum payload - top secret";
    let aad = b"ContainerHeaderV4";

    let encrypted = encrypt_aes_gcm(&key, &nonce, plaintext, aad).expect("Encryption should succeed");
    
    // Valid decrypt
    let decrypted = decrypt_aes_gcm(&key, &nonce, &encrypted, aad).expect("Decryption should succeed");
    assert_eq!(plaintext, decrypted.as_slice());

    // Tampered AAD
    let tampered_aad = b"CorruptedHeaderV4";
    assert!(decrypt_aes_gcm(&key, &nonce, &encrypted, tampered_aad).is_err());

    // Tampered Ciphertext
    let mut tampered_ct = encrypted.clone();
    tampered_ct[5] ^= 0xFF;
    assert!(decrypt_aes_gcm(&key, &nonce, &tampered_ct, aad).is_err());
}
