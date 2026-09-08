#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use miragex::cli::run_cli;

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
        let exe_str = exe_path.to_string_lossy().to_string();
        let _ = std::process::Command::new("reg")
            .args(&[
                "add", "HKCU\\Software\\Classes\\.wraith",
                "/ve", "/d", "MirageX.wraith", "/f"
            ])
            .output();
        let _ = std::process::Command::new("reg")
            .args(&[
                "add", "HKCU\\Software\\Classes\\MirageX.wraith",
                "/ve", "/d", "WRAITH Encrypted Container", "/f"
            ])
            .output();
        let _ = std::process::Command::new("reg")
            .args(&[
                "add", "HKCU\\Software\\Classes\\MirageX.wraith\\DefaultIcon",
                "/ve", "/d", &format!("\"{}\",0", exe_str), "/f"
            ])
            .output();
        let _ = std::process::Command::new("reg")
            .args(&[
                "add", "HKCU\\Software\\Classes\\MirageX.wraith\\shell\\open\\command",
                "/ve", "/d", &format!("\"{}\" \"%1\"", exe_str), "/f"
            ])
            .output();
    }
}

#[cfg(not(windows))]
fn register_windows_file_association() {}

fn main() {
    disable_core_dumps();
    register_windows_file_association();

    // Check if running from CLI
    if run_cli() {
        return;
    }

    // Otherwise launch native Tauri GUI
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            miragex::commands::encrypt_file_cmd,
            miragex::commands::decrypt_file_cmd,
            miragex::commands::inspect_container_cmd,
            miragex::commands::shred_file_cmd,
            miragex::commands::run_benchmark_cmd,
            miragex::commands::generate_pqc_key_cmd,
            miragex::commands::select_file_dialog,
            miragex::commands::select_wraith_dialog,
        ])
        .run(tauri::generate_context!())
        .expect("Error while running MirageX Tauri desktop application");
}
