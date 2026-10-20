use std::env;
use std::io::{self, BufRead};
use std::process;
use zeroize::Zeroize;

use crate::commands::{
    decrypt_file_cmd, encrypt_file_cmd, inspect_container_cmd, run_benchmark_cmd, shred_file_cmd,
};

pub fn run_cli() -> bool {
    let mut args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        // No arguments -> launch GUI
        return false;
    }

    match args[1].as_str() {
        "gui" => false,
        "help" | "-h" | "--help" => {
            print_help();
            process::exit(0);
        }
        "encrypt" => {
            handle_encrypt(&mut args[2..]);
            true
        }
        "decrypt" => {
            handle_decrypt(&mut args[2..]);
            true
        }
        "inspect" => {
            handle_inspect(&args[2..]);
            true
        }
        "shred" => {
            handle_shred(&args[2..]);
            true
        }
        "keyfile" => {
            handle_keyfile(&args[2..]);
            true
        }
        "bench" => {
            handle_bench();
            true
        }
        "--gui-encrypt" if args.len() > 2 => {
            crate::commands::set_initial_file(&args[2], Some("encrypt"));
            false
        }
        "--gui-decrypt" if args.len() > 2 => {
            crate::commands::set_initial_file(&args[2], Some("decrypt"));
            false
        }
        arg if !arg.starts_with('-') || std::path::Path::new(arg).exists() => {
            crate::commands::set_initial_file(arg, None);
            false
        }
        _ => {
            eprintln!("Unknown command: '{}'. Run 'miragex --help' for usage.", args[1]);
            process::exit(1);
        }
    }
}

fn print_help() {
    println!(r#"
╔═══════════════════════════════════════════════════════════════════╗
║   MIRAGEX v4.0.2 — Post-Quantum Decoupled Encryption Engine     ║
║   Container Format: WRAITH v4 (NIST FIPS 203 ML-KEM + AES-GCM)   ║
╚═══════════════════════════════════════════════════════════════════╝

USAGE:
    miragex                               Launch Desktop GUI
    miragex encrypt <file> [options]
    miragex decrypt <file.wraith> [options]
    miragex keyfile generate <output> [--size <bytes>]
    miragex inspect <file.wraith>
    miragex shred <file> [--passes <N>] [--mode <hdd|ssd>]
    miragex bench

OPTIONS:
    -p, --password <PASS>      Password (visible in process list; prefer interactive prompt)
    --password-stdin           Read password securely from standard input
    -k, --keyfile <PATH>       VeraCrypt/Arcanum compatible Keyfile for 2FA or keyfile-only auth
    -o, --output <PATH>        Custom output destination path
    --pqc <768|1024>           PQC Suite (default: 768)
    --chunk-size <MB>          Streaming chunk size in MB (default: 16)
    --shred                    Securely wipe source file after operation
    --mode <hdd|ssd>           Shredding mode (default: hdd; ssd includes wear-leveling mitigation)
    --passes <N>               Overwrite passes (default: 3)
    -h, --help                 Show this help screen
"#);
}

fn get_password(args: &mut [String], from_stdin: bool, keyfile_present: bool) -> String {
    if from_stdin {
        let mut line = String::new();
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let _ = handle.read_line(&mut line);
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
        line.zeroize();
        return trimmed;
    }

    let mut i = 0;
    while i < args.len() {
        if args[i] == "-p" || args[i] == "--password" {
            if i + 1 < args.len() {
                eprintln!("⚠️ Warning: Passing passwords via CLI argument is visible in system process lists (ps). Use interactive prompt or --password-stdin instead.");
                let pass = args[i + 1].clone();
                args[i + 1].zeroize(); // Scrub original argument memory
                return pass;
            }
        }
        i += 1;
    }

    let prompt_msg = if keyfile_present {
        "🔑 Enter master password (press Enter for keyfile-only): "
    } else {
        "🔑 Enter master password: "
    };

    // Prompt interactively with hidden terminal input
    match rpassword::prompt_password(prompt_msg) {
        Ok(pass) => pass,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            process::exit(1);
        }
    }
}

fn handle_keyfile(args: &[String]) {
    if args.is_empty() || args[0] != "generate" {
        eprintln!("Usage: miragex keyfile generate <output_file> [--size <bytes>]");
        process::exit(1);
    }

    let dest = if args.len() > 1 && !args[1].starts_with('-') {
        args[1].clone()
    } else {
        "miragex.key".to_string()
    };

    let mut size = 64;
    let mut i = 1;
    while i < args.len() {
        if (args[i] == "-s" || args[i] == "--size") && i + 1 < args.len() {
            if let Ok(s) = args[i + 1].parse() {
                size = s;
            }
            i += 1;
        }
        i += 1;
    }

    match crate::crypto::keyfile::generate_keyfile(size, None) {
        Ok(bytes) => {
            // Keyfiles are authentication factors: restrict to the owner (0600).
            #[cfg(unix)]
            let write_res = {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&dest)
                    .and_then(|mut f| f.write_all(&bytes))
            };
            #[cfg(not(unix))]
            let write_res = std::fs::write(&dest, &bytes);

            if let Err(e) = write_res {
                eprintln!("Failed to save keyfile: {}", e);
                process::exit(1);
            }
            println!("🎲 Keyfile generated successfully: '{}' ({} bytes)", dest, size);
        }
        Err(e) => {
            eprintln!("Keyfile generation failed: {}", e);
            process::exit(1);
        }
    }
}

fn handle_encrypt(args: &mut [String]) {
    if args.is_empty() {
        eprintln!("Error: Input file required for encryption.");
        process::exit(1);
    }

    let input_path = args[0].clone();
    let mut output_path = None;
    let mut keyfile_path = None;
    let mut suite_id = Some(1u8); // Default 768
    let mut chunk_size_mb = Some(16u32);
    let mut shred = false;
    let mut shred_mode = None;
    let mut shred_passes = None;
    let mut from_stdin = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--password-stdin" => from_stdin = true,
            "-k" | "--keyfile" => {
                if i + 1 < args.len() {
                    keyfile_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--pqc" => {
                if i + 1 < args.len() {
                    let val = args[i + 1].as_str();
                    suite_id = match val {
                        "1024" => Some(2),
                        _ => Some(1),
                    };
                    i += 1;
                }
            }
            "--chunk-size" => {
                if i + 1 < args.len() {
                    chunk_size_mb = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            "--shred" => shred = true,
            "--mode" | "--shred-mode" => {
                if i + 1 < args.len() {
                    shred_mode = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--passes" | "--shred-passes" => {
                if i + 1 < args.len() {
                    shred_passes = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let keyfile_present = keyfile_path.is_some();
    let password = get_password(args, from_stdin, keyfile_present);
    if password.is_empty() && !keyfile_present {
        eprintln!("Error: Password or keyfile is required.");
        process::exit(1);
    }

    let name_fuzzing = if args.contains(&"--no-fuzz".to_string()) || args.contains(&"--no-name-fuzzing".to_string()) {
        Some(false)
    } else {
        Some(true)
    };

    println!("🔒 Encrypting '{}' using MirageX (WRAITH v4)...", input_path);
    match encrypt_file_cmd(input_path, output_path, password, keyfile_path, suite_id, chunk_size_mb, shred, shred_mode, shred_passes, name_fuzzing) {
        Ok(res) => {
            println!("✅ Encryption successful!");
            println!("   Output:         {}", res.output_path);
            if res.name_fuzzed {
                println!("   Name Fuzzing:   ACTIVE ([sha256].wraith)");
            }
            println!("   Suite:          {}", res.suite_name);
            println!("   Original Size:  {} bytes", res.original_size);
            println!("   Encrypted Size: {} bytes", res.encrypted_size);
            println!("   Chunks:         {}", res.chunks_count);
            println!("   Time:           {} ms", res.elapsed_ms);
        }
        Err(e) => {
            eprintln!("❌ Encryption failed: {}", e);
            process::exit(1);
        }
    }
}

fn handle_decrypt(args: &mut [String]) {
    if args.is_empty() {
        eprintln!("Error: Container file required for decryption.");
        process::exit(1);
    }

    let input_path = args[0].clone();
    let mut output_path = None;
    let mut keyfile_path = None;
    let mut shred = false;
    let mut shred_mode = None;
    let mut shred_passes = None;
    let mut from_stdin = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--password-stdin" => from_stdin = true,
            "-k" | "--keyfile" => {
                if i + 1 < args.len() {
                    keyfile_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--shred" => shred = true,
            "--mode" | "--shred-mode" => {
                if i + 1 < args.len() {
                    shred_mode = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--passes" | "--shred-passes" => {
                if i + 1 < args.len() {
                    shred_passes = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let keyfile_present = keyfile_path.is_some();
    let password = get_password(args, from_stdin, keyfile_present);
    if password.is_empty() && !keyfile_present {
        eprintln!("Error: Password or keyfile is required.");
        process::exit(1);
    }

    println!("🔓 Decrypting and verifying WRAITH container '{}'...", input_path);
    match decrypt_file_cmd(input_path, output_path, password, keyfile_path, shred, shred_mode, shred_passes) {
        Ok(res) => {
            println!("✅ Decryption & Authenticity Verified!");
            println!("   Restored File: {}", res.output_path);
            println!("   Original Name: {}", res.original_filename);
            println!("   Size:          {} bytes", res.restored_size);
            println!("   SHA-256 Hash:  {}", res.sha256_hex);
            println!("   Time:          {} ms", res.elapsed_ms);
        }
        Err(e) => {
            eprintln!("❌ Decryption failed: {}", e);
            process::exit(1);
        }
    }
}

fn handle_inspect(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: File path required for inspection.");
        process::exit(1);
    }

    match inspect_container_cmd(args[0].clone()) {
        Ok(info) => {
            println!("🔍 WRAITH Container Inspection:");
            println!("   Magic / Version:  {} v{}", info.magic, info.version);
            println!("   Algorithm Suite:  {}", info.suite_name);
            println!("   Container UUID:   {}", info.uuid_hex);
            println!("   KDF Salt:         {}", info.salt_hex);
            println!("   Chunk Size:       {} MB ({} bytes)", info.chunk_size_mb, info.chunk_size_bytes);
            println!("   PQC Ciphertext:   {} bytes", info.pqc_ciphertext_size);
        }
        Err(e) => {
            eprintln!("❌ Inspection failed: {}", e);
            process::exit(1);
        }
    }
}

fn handle_shred(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: File path required for shredding.");
        process::exit(1);
    }

    let input_path = args[0].clone();
    let mut passes = 3u8;
    let mut mode = None;

    let mut i = 1;
    while i < args.len() {
        if (args[i] == "--passes" || args[i] == "--shred-passes") && i + 1 < args.len() {
            passes = args[i + 1].parse().unwrap_or(3);
            i += 1;
        } else if (args[i] == "--mode" || args[i] == "--shred-mode") && i + 1 < args.len() {
            mode = Some(args[i + 1].clone());
            i += 1;
        }
        i += 1;
    }

    match shred_file_cmd(input_path, Some(passes), mode) {
        Ok(msg) => println!("🌪️ {}", msg),
        Err(e) => {
            eprintln!("❌ Shredding failed: {}", e);
            process::exit(1);
        }
    }
}

fn handle_bench() {
    println!("⚡ Running MirageX Algorithm Benchmark...");
    match run_benchmark_cmd() {
        Ok(bench) => {
            println!("══════════════════════════════════════════════════════");
            println!("  MirageX Standard (768):     {:.2} ops/sec", bench.miragex_768_encap_ops_sec);
            println!("  MirageX Ultra (1024):       {:.2} ops/sec", bench.miragex_1024_encap_ops_sec);
            println!("  Argon2id (64MB / 3 iter):   {} ms", bench.argon2id_time_ms);
            println!("  AES-256-GCM Hardware Speed: {:.2} MB/s", bench.aes_256_gcm_throughput_mb_s);
            println!("══════════════════════════════════════════════════════");
        }
        Err(e) => eprintln!("❌ Benchmark error: {}", e),
    }
}
