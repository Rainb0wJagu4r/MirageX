#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use miragex::cli::run_cli;

fn main() {
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
