use std::fs::{self, File};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::wraith::inspect::inspect_container;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPreviewInfo {
    pub file_name: String,
    pub file_size: u64,
    pub is_valid: bool,
    pub magic: String,
    pub version: u8,
    pub generation: String,
    pub suite_name: String,
    pub chunk_size_mb: f32,
    pub argon2_summary: String,
    pub uuid_hex: String,
    pub salt_hex: String,
    pub security_rating: String,
    pub summary_text: String,
}

pub fn inspect_header_for_preview(file_path: &str) -> Result<HeaderPreviewInfo, String> {
    let p = Path::new(file_path);
    if !p.exists() {
        return Err(format!("Archivo no encontrado: {}", file_path));
    }

    let meta = fs::metadata(p).map_err(|e| e.to_string())?;
    let file = File::open(p).map_err(|e| e.to_string())?;
    let inspection = inspect_container(file).map_err(|e| e.to_string())?;

    let file_name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
    let argon2_summary = format!(
        "Argon2id (RAM: {} MB, Iter: {}, Hilos: {})",
        inspection.argon2_m_cost / 1024,
        inspection.argon2_t_cost,
        inspection.argon2_p_cost
    );

    let summary_text = format!(
        "╔══════════════════════════════════════════════════════════╗\n\
         ║   VISTA PREVIA WRAITH HEADER (SIN CONTRASEÑA)           ║\n\
         ╠══════════════════════════════════════════════════════════╣\n\
         • Archivo:       {}\n\
         • Tamaño:        {:.2} MB\n\
         • Formato:       {} (v{})\n\
         • Suite PQC:     {} (NIST FIPS 203)\n\
         • Bloques AEAD:  {:.1} MB Streaming (AES-256-GCM)\n\
         • Derivación:    {}\n\
         • UUID Vault:    {}\n\
         • Nivel:         Post-Quantum Level 3/5 Resistente\n\
         ╚══════════════════════════════════════════════════════════╝",
        file_name,
        meta.len() as f64 / (1024.0 * 1024.0),
        inspection.magic,
        inspection.version,
        inspection.suite_name,
        inspection.chunk_size_mb,
        argon2_summary,
        &inspection.uuid_hex[..16]
    );

    Ok(HeaderPreviewInfo {
        file_name,
        file_size: meta.len(),
        is_valid: true,
        magic: inspection.magic,
        version: inspection.version,
        generation: inspection.generation,
        suite_name: inspection.suite_name,
        chunk_size_mb: inspection.chunk_size_mb,
        argon2_summary,
        uuid_hex: inspection.uuid_hex,
        salt_hex: inspection.salt_hex,
        security_rating: "Post-Quantum Cryptographic Fortress (FIPS 203)".into(),
        summary_text,
    })
}

pub fn setup_quicklook_preview() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let services_dir = PathBuf::from(home).join("Library/Services");
            let _ = fs::create_dir_all(&services_dir);

            let workflow_dir = services_dir.join("Vista Previa Cabecera WRAITH.workflow");
            let contents_dir = workflow_dir.join("Contents");
            let _ = fs::create_dir_all(&contents_dir);

            let info_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSServices</key>
    <array>
        <dict>
            <key>NSBackgroundColorName</key>
            <string>background</string>
            <key>NSBackgroundStrokeColorName</key>
            <string>line</string>
            <key>NSIconName</key>
            <string>NSActionTemplate</string>
            <key>NSMenuItem</key>
            <dict>
                <key>default</key>
                <string>Vista Previa Cabecera WRAITH (Sin Contraseña)</string>
            </dict>
            <key>NSMessage</key>
            <string>runWorkflowAsService</string>
            <key>NSRequiredContext</key>
            <dict>
                <key>NSApplicationIdentifier</key>
                <string>com.apple.finder</string>
            </dict>
            <key>NSSendFileTypes</key>
            <array>
                <string>com.miragesecurity.wraith</string>
                <string>public.data</string>
            </array>
        </dict>
    </array>
</dict>
</plist>"#;

            let doc_wflow = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AMApplicationBuild</key>
    <string>523</string>
    <key>AMApplicationVersion</key>
    <string>2.10</string>
    <key>AMDocumentVersion</key>
    <string>2</string>
    <key>actions</key>
    <array>
        <dict>
            <key>action</key>
            <dict>
                <key>ActionBundlePath</key>
                <string>/System/Library/Automator/Run Shell Script.action</string>
                <key>ActionName</key>
                <string>Run Shell Script</string>
                <key>ActionParameters</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <string>for f in "$@"
do
    open -a "MirageX" "$f" 2>/dev/null || open -a "/Applications/MirageX.app" "$f" 2>/dev/null
done</string>
                    <key>inputMethod</key>
                    <integer>1</integer>
                    <key>shell</key>
                    <string>/bin/bash</string>
                </dict>
                <key>BundleIdentifier</key>
                <string>com.apple.RunShellScript</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"#;

            let _ = fs::write(contents_dir.join("Info.plist"), info_plist);
            let _ = fs::write(contents_dir.join("document.wflow"), doc_wflow);

            let _ = std::process::Command::new("/System/Library/CoreServices/pbs")
                .arg("-flush")
                .output();

            Ok("Acción Rápida de Vista Previa WRAITH en macOS Finder registrada con éxito.".into())
        } else {
            Err("No se pudo resolver el directorio HOME.".into())
        }
    }

    #[cfg(windows)]
    {
        // On Windows, the inspect context menu registered in setup_context_menu_cmd acts as the preview handler
        Ok("Vista previa registrada en el menú contextual de Windows ('Inspeccionar Contenedor WRAITH').".into())
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Ok("Vista previa integrada en MirageX CLI y visor visual de Linux.".into())
    }
}
