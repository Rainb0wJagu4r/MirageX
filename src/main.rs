#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use miragex::cli::run_cli;
use tauri::{Emitter, Manager};

/// Best-effort hardening: prevent the OS from writing core dumps that could
/// capture sensitive key material after a crash (AUDIT.md L1).
/// No-op on platforms where the kernel lacks RLIMIT_CORE (e.g. Windows).
#[cfg(unix)]
fn disable_core_dumps() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {}

#[cfg(windows)]
fn register_windows_file_association() {
    if let Ok(exe_path) = std::env::current_exe() {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let exe_str = exe_path.to_string_lossy().to_string();
        let icon_path = miragex::commands::ensure_windows_nobug_icon();
        let icon_str = icon_path.to_string_lossy().to_string();

        let run_reg = |args: &[&str]| {
            let _ = std::process::Command::new("reg")
                .args(args)
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        };

        run_reg(&["add", "HKCU\\Software\\Classes\\.wraith", "/ve", "/d", "MirageX.wraith", "/f"]);
        run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith", "/ve", "/d", "WRAITH Encrypted Container", "/f"]);
        run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\DefaultIcon", "/ve", "/d", &format!("\"{}\",0", icon_str), "/f"]);
        run_reg(&["add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\open\\command", "/ve", "/d", &format!("\"{}\" --gui-decrypt \"%1\"", exe_str), "/f"]);

        let _ = std::process::Command::new("ie4uinit.exe")
            .arg("-show")
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

#[cfg(not(windows))]
fn register_windows_file_association() {}

fn main() {
    disable_core_dumps();

    // Run registry and integration setup asynchronously in background (0ms startup latency)
    std::thread::spawn(|| {
        register_windows_file_association();
        let _ = miragex::commands::setup_context_menu_cmd();
    });

    // Check if running from CLI
    if run_cli() {
        return;
    }

    // Otherwise launch native Tauri GUI with Single Instance support
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }

            if argv.len() > 1 {
                let mut target_path = None;
                let mut action = None;

                for (i, arg) in argv.iter().enumerate().skip(1) {
                    if arg == "--gui-encrypt" && i + 1 < argv.len() {
                        target_path = Some(argv[i + 1].clone());
                        action = Some("encrypt".to_string());
                        break;
                    } else if arg == "--gui-decrypt" && i + 1 < argv.len() {
                        target_path = Some(argv[i + 1].clone());
                        action = Some("decrypt".to_string());
                        break;
                    } else if arg == "--gui-inspect" && i + 1 < argv.len() {
                        target_path = Some(argv[i + 1].clone());
                        action = Some("inspect".to_string());
                        break;
                    } else if !arg.starts_with('-') && std::path::Path::new(arg).exists() {
                        target_path = Some(arg.clone());
                        if arg.to_lowercase().ends_with(".wraith") {
                            action = Some("decrypt".to_string());
                        } else {
                            action = Some("encrypt".to_string());
                        }
                        break;
                    }
                }

                if let Some(path) = target_path {
                    let name = std::path::Path::new(&path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.clone());
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    let payload = miragex::commands::InitialFilePayload {
                        path,
                        name,
                        size,
                        action,
                    };
                    let _ = app.emit("open-file-payload", payload);
                }
            }
        }))
        .invoke_handler(tauri::generate_handler![
            miragex::commands::encrypt_file_cmd,
            miragex::commands::decrypt_file_cmd,
            miragex::commands::inspect_container_cmd,
            miragex::commands::shred_file_cmd,
            miragex::commands::run_benchmark_cmd,
            miragex::commands::generate_pqc_key_cmd,
            miragex::commands::select_file_dialog,
            miragex::commands::select_wraith_dialog,
            miragex::commands::get_initial_file_cmd,
            miragex::commands::setup_context_menu_cmd,
            miragex::commands::select_keyfile_dialog,
            miragex::commands::generate_keyfile_cmd,
            miragex::commands::select_vault_sources_dialog,
            miragex::commands::select_vault_source_folder_dialog,
            miragex::commands::select_vault_dialog,
            miragex::commands::create_vault_cmd,
            miragex::commands::open_vault_cmd,
            miragex::commands::list_vault_entries_cmd,
            miragex::commands::extract_vault_entry_cmd,
            miragex::commands::extract_all_vault_cmd,
            miragex::commands::close_vault_cmd,
            miragex::commands::updater::check_app_update_cmd,
            miragex::commands::updater::install_app_update_cmd,
            miragex::commands::updater::restart_app_cmd,
            miragex::commands::updater::get_changelog_history_cmd,
            miragex::commands::open_external_url_cmd,
            miragex::commands::start_folder_watcher_cmd,
            miragex::commands::stop_folder_watcher_cmd,
            miragex::commands::get_watcher_status_cmd,
            miragex::commands::export_watcher_audit_log_cmd,
            miragex::commands::create_backup_archive_cmd,
            miragex::commands::restore_backup_archive_cmd,
            miragex::commands::inspect_header_for_preview_cmd,
            miragex::commands::setup_quicklook_preview_cmd,
            miragex::commands::setup_linux_desktop_integration_cmd,
            miragex::commands::get_linux_integration_status_cmd,
            miragex::commands::remove_context_menu_cmd,
            miragex::commands::export_context_menu_scripts_cmd,
            miragex::commands::select_folder_dialog,
        ])
        .build(tauri::generate_context!())
        .expect("Error while running MirageX Tauri desktop application")
        .run(|app_handle, event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = event {
                for url in urls {
                    if let Ok(file_path) = url.to_file_path() {
                        let path_str = file_path.to_string_lossy().to_string();
                        let name = file_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| path_str.clone());
                        let size = std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
                        let action = if path_str.to_lowercase().ends_with(".wraith") {
                            Some("decrypt".to_string())
                        } else {
                            Some("encrypt".to_string())
                        };
                        let payload = miragex::commands::InitialFilePayload {
                            path: path_str,
                            name,
                            size,
                            action,
                        };
                        let _ = app_handle.emit("open-file-payload", payload);
                    }
                }
            }
        });
}
