use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxIntegrationStatus {
    pub is_installed: bool,
    pub mime_xml_path: String,
    pub desktop_file_path: String,
    pub icon_path: String,
    pub details: String,
}

pub fn generate_linux_mime_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
    <mime-type type="application/x-wraith">
        <comment>Contenedor Cifrado Post-Cuántico WRAITH</comment>
        <comment xml:lang="en">WRAITH Post-Quantum Encrypted Container</comment>
        <glob pattern="*.wraith"/>
        <glob pattern="*.WRAITH"/>
        <icon name="application-x-wraith"/>
        <generic-icon name="package-x-generic"/>
    </mime-type>
</mime-info>"#
}

pub fn generate_linux_desktop_file(exe_path: &str) -> String {
    format!(
        r#"[Desktop Entry]
Version=1.0
Type=Application
Name=MirageX
GenericName=Post-Quantum Encryption Engine
Comment=Cifrador Post-Cuántico WRAITH (NIST FIPS 203 ML-KEM + AES-256-GCM)
Exec="{}" %F
Icon=miragex
Terminal=false
Categories=Utility;Security;Cryptography;Archiving;
MimeType=application/x-wraith;
Actions=Encrypt;Decrypt;Inspect;

[Desktop Action Encrypt]
Name=Cifrar con MirageX (Post-Quantum)
Name[en]=Encrypt with MirageX (Post-Quantum)
Exec="{}" --gui-encrypt %F
Icon=miragex

[Desktop Action Decrypt]
Name=Descifrar con MirageX (Post-Quantum)
Name[en]=Decrypt with MirageX (Post-Quantum)
Exec="{}" --gui-decrypt %F
Icon=application-x-wraith

[Desktop Action Inspect]
Name=Inspeccionar Cabecera WRAITH
Name[en]=Inspect WRAITH Header
Exec="{}" --gui-inspect %F
Icon=miragex
"#,
        exe_path, exe_path, exe_path, exe_path
    )
}

pub fn setup_linux_desktop_integration() -> Result<String, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "No se pudo resolver la variable HOME en el sistema.".to_string())?;

    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "miragex".to_string());

    let share_dir = home.join(".local/share");
    let mime_dir = share_dir.join("mime/packages");
    let apps_dir = share_dir.join("applications");
    let icons_dir = share_dir.join("icons/hicolor/128x128/mimetypes");
    let apps_icon_dir = share_dir.join("icons/hicolor/128x128/apps");

    fs::create_dir_all(&mime_dir).map_err(|e| format!("Error creando mime dir: {}", e))?;
    fs::create_dir_all(&apps_dir).map_err(|e| format!("Error creando applications dir: {}", e))?;
    fs::create_dir_all(&icons_dir).map_err(|e| format!("Error creando icons mimetypes dir: {}", e))?;
    fs::create_dir_all(&apps_icon_dir).map_err(|e| format!("Error creando icons apps dir: {}", e))?;

    // 1. Write MIME XML
    let xml_path = mime_dir.join("miragex-wraith.xml");
    fs::write(&xml_path, generate_linux_mime_xml())
        .map_err(|e| format!("Error escribiendo XML de MIME: {}", e))?;

    // 2. Write .desktop file
    let desktop_path = apps_dir.join("miragex.desktop");
    fs::write(&desktop_path, generate_linux_desktop_file(&exe_path))
        .map_err(|e| format!("Error escribiendo .desktop: {}", e))?;

    // 3. Write icon assets if available
    const NOBUG_PNG: &[u8] = include_bytes!("../../icons/nobug.png");
    let _ = fs::write(icons_dir.join("application-x-wraith.png"), NOBUG_PNG);
    let _ = fs::write(apps_icon_dir.join("miragex.png"), NOBUG_PNG);

    // 4. Update desktop & mime database if tools exist
    let _ = std::process::Command::new("update-mime-database")
        .arg(share_dir.join("mime"))
        .output();

    let _ = std::process::Command::new("update-desktop-database")
        .arg(&apps_dir)
        .output();

    Ok(format!(
        "Integración en Linux completada: MIME type 'application/x-wraith' y acceso 'miragex.desktop' registrados en '{}'.",
        share_dir.display()
    ))
}

pub fn get_linux_integration_status() -> LinuxIntegrationStatus {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let share_dir = home.join(".local/share");
    let xml_path = share_dir.join("mime/packages/miragex-wraith.xml");
    let desktop_path = share_dir.join("applications/miragex.desktop");
    let icon_path = share_dir.join("icons/hicolor/128x128/mimetypes/application-x-wraith.png");

    let is_installed = xml_path.exists() && desktop_path.exists();

    LinuxIntegrationStatus {
        is_installed,
        mime_xml_path: xml_path.to_string_lossy().to_string(),
        desktop_file_path: desktop_path.to_string_lossy().to_string(),
        icon_path: icon_path.to_string_lossy().to_string(),
        details: if is_installed {
            "Tipo MIME e integración de escritorio activa en ~/.local/share/".into()
        } else {
            "No instalado aún en el perfil de usuario local.".into()
        },
    }
}
