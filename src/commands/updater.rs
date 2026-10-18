use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangelogEntry {
    pub version: String,
    pub title: String,
    pub date: String,
    pub is_current: bool,
    pub highlights: Vec<String>,
    pub security_notes: Vec<String>,
    pub raw_markdown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub has_update: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_date: Option<String>,
    pub release_notes: String,
    pub changelog_history: Vec<ChangelogEntry>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProgress {
    pub chunk: usize,
    pub total: Option<u64>,
    pub downloaded_bytes: u64,
    pub percent: Option<u8>,
}

/// Devuelve el historial oficial de versiones y novedades (Changelog) de MirageX.
pub fn get_changelog_entries() -> Vec<ChangelogEntry> {
    vec![
        ChangelogEntry {
            version: "v4.0.2".to_string(),
            title: "Velvet HUD, In-App Auto-Updates, Bóvedas In-Memory & Centro de Orientación".to_string(),
            date: "18 de Octubre, 2026".to_string(),
            is_current: true,
            highlights: vec![
                "💡 Centro de Orientación Criptográfica interactivo con casos de uso prácticos (WhatsApp, Nube, Borrado).".to_string(),
                "🎨 Nueva paleta de diseño 'Velvet' (#313866, #50409A, #FF7BBF) conservando el morado neón (#b026ff) de MirageX.".to_string(),
                "📦 Sistema de Bóvedas Cifradas In-Memory (.wvault) multi-carpeta sin necesidad de instalar drivers en el kernel.".to_string(),
                "🔑 Generador de Keyfiles estándar VeraCrypt/Arcanum con radar de entropía física del cursor.".to_string(),
                "📲 Compartir contraseñas mediante Código QR local efímero de autodestrucción (Zero-Network).".to_string(),
                "🔄 Actualizador In-App multiplataforma (Windows, macOS, Linux) con visor de Changelog integrado.".to_string(),
            ],
            security_notes: vec![
                "Mezcla criptográfica de Keyfiles bit a bit idéntica a VeraCrypt con tabla CRC-32 IEEE 802.3 (polinomio 0xEDB88320).".to_string(),
                "Aislamiento de bóvedas contra ataques Tar-Slip y sanitización de Path Traversal.".to_string(),
                "Auto-cierre y purgado de memoria seguro en el visualizador QR.".to_string(),
            ],
            raw_markdown: "### MirageX v4.0.1\n- Centro de Orientación Criptográfica y Casos de Uso.\n- Bóvedas multi-archivo in-memory (.wvault).\n- Generador de Keyfiles VeraCrypt/Arcanum con radar de entropía.\n- Paleta Velvet con acentos neón.\n- Actualizador In-App transparente.".to_string(),
        },
        ChangelogEntry {
            version: "v4.0.0".to_string(),
            title: "Revolución Post-Cuántica (PQC) & Contenedores WRAITH v4".to_string(),
            date: "13 de Septiembre, 2026".to_string(),
            is_current: false,
            highlights: vec![
                "🛡️ Implementación de ML-KEM-768 y ML-KEM-1024 basados en el estándar oficial NIST FIPS 203 (Agosto 2024).".to_string(),
                "⚡ Cifrado Simétrico Autenticado AES-256-GCM AEAD procesado en chunks streaming de alta velocidad.".to_string(),
                "🔒 Función de derivación de claves Argon2id con 64 MB de memoria RAM contra ataques GPU y ASIC.".to_string(),
                "🌪️ Triturador forense de archivos con modos dedicados para SSD/NVMe (desgaste) y HDD magnéticos (DoD 5220.22-M).".to_string(),
            ],
            security_notes: vec![
                "Protección total contra 'Store Now, Decrypt Later' ante futuras computadoras cuánticas.".to_string(),
                "Detección instantánea de manipulación a nivel de bit con autenticación GCM Tag de 128 bits.".to_string(),
            ],
            raw_markdown: "### MirageX v4.0.0\n- Criptografía Post-Cuántica ML-KEM (Kyber) NIST FIPS 203.\n- Cifrado AEAD AES-256-GCM.\n- KDF Argon2id con resistencia a aceleración por hardware.\n- Triturador forense seguro.".to_string(),
        },
        ChangelogEntry {
            version: "v3.5.0".to_string(),
            title: "Integración de Sistema Operativo & Compatibilidad Universal".to_string(),
            date: "28 de Agosto, 2026".to_string(),
            is_current: false,
            highlights: vec![
                "🖱️ Menú contextual integrado en Windows Explorer (Acción rápida de cifrar/descifrar sin abrir cmd).".to_string(),
                "🍏 Acciones Rápidas y Servicios de Finder en macOS para archivos .wraith.".to_string(),
                "📂 Soporte para arrastrar y soltar (Drag & Drop) nativo sobre la ventana.".to_string(),
                "🔄 Herramienta de inspección forense y compatibilidad con versiones legacy .mirg v2.".to_string(),
            ],
            security_notes: vec![
                "Hardening del kernel con RLIMIT_CORE para impedir que se escriban volcados de memoria con claves.".to_string(),
            ],
            raw_markdown: "### MirageX v3.5.0\n- Menú contextual en Windows y macOS.\n- Drag & Drop nativo.\n- Compatibilidad retroactiva.".to_string(),
        },
    ]
}

#[tauri::command]
pub fn get_changelog_history_cmd() -> Vec<ChangelogEntry> {
    get_changelog_entries()
}

#[tauri::command]
pub async fn check_app_update_cmd(app: AppHandle) -> Result<UpdateCheckResult, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let history = get_changelog_entries();

    match app.updater() {
        Ok(updater) => {
            match updater.check().await {
                Ok(Some(update)) => {
                    Ok(UpdateCheckResult {
                        has_update: true,
                        current_version,
                        latest_version: update.version.clone(),
                        release_date: update.date.map(|d| d.to_string()),
                        release_notes: update.body.unwrap_or_else(|| "Nuevas mejoras de seguridad y correcciones incluidas en esta versión.".to_string()),
                        changelog_history: history,
                        error: None,
                    })
                }
                Ok(None) => {
                    Ok(UpdateCheckResult {
                        has_update: false,
                        current_version: current_version.clone(),
                        latest_version: current_version,
                        release_date: None,
                        release_notes: String::new(),
                        changelog_history: history,
                        error: None,
                    })
                }
                Err(_e) => {
                    // Fallback transparente: si el servidor no responde o estamos offline,
                    // comprobamos si ya estamos en la versión más reciente del changelog
                    let is_latest = history.first().map(|h| h.version == format!("v{}", current_version)).unwrap_or(true);
                    let user_error = if is_latest {
                        None
                    } else {
                        Some("No se pudo conectar al servidor de actualizaciones. Revisa tu conexión a Internet o visita GitHub Releases.".to_string())
                    };

                    Ok(UpdateCheckResult {
                        has_update: false,
                        current_version: current_version.clone(),
                        latest_version: current_version,
                        release_date: None,
                        release_notes: String::new(),
                        changelog_history: history,
                        error: user_error,
                    })
                }
            }
        }
        Err(_e) => {
            Ok(UpdateCheckResult {
                has_update: false,
                current_version: current_version.clone(),
                latest_version: current_version,
                release_date: None,
                release_notes: String::new(),
                changelog_history: history,
                error: None,
            })
        }
    }
}

#[tauri::command]
pub async fn install_app_update_cmd(app: AppHandle) -> Result<String, String> {
    let updater = app.updater().map_err(|e| format!("Error en updater: {}", e))?;
    let update_opt = updater.check().await.map_err(|e| format!("Error al verificar actualización: {}", e))?;

    if let Some(update) = update_opt {
        let app_handle = app.clone();
        let mut downloaded: u64 = 0;

        update.download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let percent = total.map(|t| {
                    if t > 0 {
                        ((downloaded as f64 / t as f64) * 100.0).min(100.0) as u8
                    } else {
                        0
                    }
                });

                let _ = app_handle.emit("update-download-progress", UpdateProgress {
                    chunk,
                    total,
                    downloaded_bytes: downloaded,
                    percent,
                });
            },
            || {},
        ).await.map_err(|e| format!("Fallo durante la descarga/instalación: {}", e))?;

        let _ = app.emit("update-download-finished", ());
        Ok("Actualización descargada e instalada con éxito. Reinicia la aplicación para aplicar los cambios.".to_string())
    } else {
        Err("No hay ninguna actualización pendiente para instalar.".to_string())
    }
}

#[tauri::command]
pub fn restart_app_cmd(app: AppHandle) {
    app.restart();
}
