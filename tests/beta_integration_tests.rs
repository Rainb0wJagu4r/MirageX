use std::fs::{self, File};

use miragex::commands::export_context_menu_scripts_cmd;
use miragex::commands::linux_mime::{generate_linux_desktop_file, generate_linux_mime_xml, get_linux_integration_status};
use miragex::commands::preview::inspect_header_for_preview;
use miragex::crypto::PqcSuite;
use miragex::wraith::encryptor::{encrypt_stream, EncryptOptions};

#[test]
fn test_header_preview_inspection() {
    let temp_dir = std::env::temp_dir().join(format!("miragex_preview_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("Create temp dir");

    let container_path = temp_dir.join("sample_data.wraith");
    let test_data = b"DATA_TO_BE_INSPECTED_IN_QUICK_LOOK";

    let mut out_file = File::create(&container_path).expect("Create container file");
    let options = EncryptOptions {
        suite: PqcSuite::MlKem1024,
        chunk_size: 16 * 1024 * 1024,
        original_filename: "sample_data.bin".into(),
        ..Default::default()
    };

    encrypt_stream(
        std::io::Cursor::new(test_data),
        &mut out_file,
        b"PreviewPassword123",
        test_data.len() as u64,
        options,
        |_| {},
    ).expect("Encryption should succeed");

    // Now inspect header preview WITHOUT password
    let preview_info = inspect_header_for_preview(&container_path.to_string_lossy())
        .expect("inspect_header_for_preview should succeed");

    assert!(preview_info.is_valid);
    assert_eq!(preview_info.magic, "WRAITH");
    assert_eq!(preview_info.version, 4);
    assert!(preview_info.suite_name.contains("ML-KEM-1024"));
    assert!(preview_info.summary_text.contains("WRAITH HEADER"));
    assert!(preview_info.argon2_summary.contains("Argon2id"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_linux_mime_and_desktop_generation() {
    let xml = generate_linux_mime_xml();
    assert!(xml.contains("application/x-wraith"));
    assert!(xml.contains("*.wraith"));
    assert!(xml.contains("application-x-wraith"));

    let desktop = generate_linux_desktop_file("/usr/bin/miragex");
    assert!(desktop.contains("Name=MirageX"));
    assert!(desktop.contains("MimeType=application/x-wraith;"));
    assert!(desktop.contains("Actions=Encrypt;Decrypt;Inspect;"));
    assert!(desktop.contains("--gui-encrypt"));
    assert!(desktop.contains("--gui-decrypt"));
    assert!(desktop.contains("--gui-inspect"));

    let status = get_linux_integration_status();
    assert!(!status.mime_xml_path.is_empty());
    assert!(!status.desktop_file_path.is_empty());
}

#[test]
fn test_export_context_menu_scripts() {
    let scripts = export_context_menu_scripts_cmd();
    assert!(scripts.windows_bat.contains("MirageX.Encrypt"));
    assert!(scripts.windows_bat.contains("nobug.ico"));
    assert!(scripts.windows_bat.contains("Descifrar"));
    assert!(scripts.windows_bat.contains("Inspeccionar"));

    assert!(scripts.windows_reg.contains("MirageX.Encrypt"));
    assert!(scripts.windows_reg.contains(".wraith"));

    assert!(scripts.linux_sh.contains("application/x-wraith"));
    assert!(scripts.linux_sh.contains("update-mime-database"));
}
