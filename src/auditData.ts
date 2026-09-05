export type Severity = "media" | "baja" | "info" | "fortaleza";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  cvss: number;
  file: string;
  lines: string;
  category: string;
  summary: string;
  technical: string;
  impact: string;
  proof: string;
  fix: string;
  fixLang: string;
  effort: string;
  status: string;
}

export const findings: Finding[] = [
  {
    id: "MX-01",
    title: "chunk_size = 0 provoca división por cero / panic (DoS)",
    severity: "media",
    cvss: 5.3,
    file: "src/commands/mod.rs",
    lines: "≈ L168–172",
    category: "Validación de entrada · Disponibilidad",
    summary:
      "El cálculo de chunk_size aplica checked_mul y cota máxima (256 MiB) pero no cota mínima. Si chunk_size_mb = 0 (CLI --chunk-size 0 o IPC directo), el cifrador recibe chunk_size = 0.",
    technical:
      "Con chunk_size = 0: (1) chunks_count = (size + 0 - 1) / 0 → división por cero → panic (en release panic = abort → crash del proceso). (2) En encrypt_stream, vec![0u8; 0] + bucle de lectura degenerado puede entrar en comportamiento indefinido / loop con probe de 1 byte. La GUI no es explotable (select fijo), pero el CLI y cualquier invocador Tauri IPC sí pueden dispararlo.",
    impact:
      "Denegación de servicio local: caída del binario durante encrypt. No hay RCE (Rust + panic=abort + overflow-checks), pero rompe flujos batch/headless y viola robustez CLI.",
    proof: `// src/commands/mod.rs — vulnerable\nlet chunk_size = chunk_size_mb\n  .and_then(|mb| mb.checked_mul(1024 * 1024))\n  .map(|bytes| bytes.min(MAX_ALLOWED_CHUNK_SIZE))\n  .unwrap_or(DEFAULT_CHUNK_SIZE);\n//  chunk_size_mb = Some(0) → Some(0) → 0  ❌ sin mínimo\n//  ...\nlet chunks_count = (meta.size + (chunk_size as u64) - 1)\n  / (chunk_size as u64); // ÷0 → panic/abort`,
    fix: `pub const MIN_ALLOWED_CHUNK_SIZE: u32 = 64 * 1024; // 64 KiB\n\nlet chunk_size = chunk_size_mb\n  .and_then(|mb| mb.checked_mul(1024 * 1024))\n  .map(|b| b.clamp(MIN_ALLOWED_CHUNK_SIZE, MAX_ALLOWED_CHUNK_SIZE))\n  .unwrap_or(DEFAULT_CHUNK_SIZE);\n\n// + defensa en profundidad en EncryptOptions::default()\n// debug_assert!(chunk_size >= MIN_ALLOWED_CHUNK_SIZE);`,
    fixLang: "rust",
    effort: "15 min · P0",
    status: "Abierto — parche trivial",
  },
  {
    id: "MX-02",
    title: "Archivos temporales con modo 0644 exponen plaintext/ciphertext",
    severity: "media",
    cvss: 5.5,
    file: "src/commands/mod.rs · src/storage/local.rs",
    lines: "File::create tmp",
    category: "Storage · Permisos Unix",
    summary:
      "El descifrado escribe plaintext a .miragex_dec_<rand>.tmp y el cifrado a <out>.tmp.<rand> con File::create (umask por defecto, típicamente 0644). En sistemas multi-usuario, otro UID puede leer el plaintext mientras existe la ventana temporal.",
    technical:
      "File::create no fija modo restrictivo. En Linux/macOS el tmp hereda umask (022 → 644, legible por grupo/otros). El sufijo OsRng u64 evita predicción del nombre, pero no el acceso por readdir o inotify. Además commit_file_atomic con fallback copy+delete duplica la ventana de exposición en EXDEV. save_stream en local.rs tiene el mismo patrón.",
    impact:
      "Lectura de plaintext por usuarios locales concurrentes durante decrypt de archivos sensibles. Severidad media porque requiere acceso local + timing, pero el fix es de 5 líneas.",
    proof: `// decrypt_file_cmd\nlet tmp_out_path = parent_dir\n  .join(format!(".miragex_dec_{}.tmp", rand_suffix));\nlet mut tmp_file = File::create(&tmp_out_path)?;\n//  → modo 0644 según umask ❌\n//  plaintext escrito aquí antes del commit atómico`,
    fix: `#[cfg(unix)]\nuse std::os::unix::fs::OpenOptionsExt;\n\nlet mut tmp_file = std::fs::OpenOptions::new()\n  .write(true).create_new(true).truncate(true)\n  .mode(0o600) // rw------- OK\n  .open(&tmp_out_path)?;\n\n// Windows: aplicar ACL equivalente (std os windows)\n// o documentar limitacion. Aplicar tambien en\n// local.rs save_stream y encrypt tmp.`,
    fixLang: "rust",
    effort: "30 min · P0",
    status: "Abierto — recomendado",
  },
  {
    id: "MX-03",
    title: "Sin política mínima de contraseña (solo non-empty)",
    severity: "media",
    cvss: 5.9,
    file: "src/cli.rs · ui/app.js · src/commands/mod.rs",
    lines: "get_password / btn-start-encrypt",
    category: "KDF · Factor humano",
    summary:
      "Tanto CLI (password.is_empty()) como GUI (if (!password)) aceptan contraseñas de 1 carácter. Argon2id-64MB ralentiza, pero no salva 'a' o '1234' frente a diccionario offline: el atacante tiene salt + envelope y puede probar millones de candidatos en GPU.",
    technical:
      "El medidor de entropía en app.js (evaluatePasswordEntropy) es solo informativo, no bloquea. No hay zxcvbn, lista de denegados, ni mínimo de longitud/entropía. Dado que el contenedor es offline-crackeable por diseño (password-based), la contraseña es el eslabón más débil de toda la cadena PQC.",
    impact:
      "El eslabón PQC (ML-KEM-1024 Nivel 5) queda reducido a la entropía del password. Un usuario con 'password123' anula los 256 bits teóricos del DEK.",
    proof: `// cli.rs\nlet password = get_password(args, from_stdin);\nif password.is_empty() { exit(1) }\n// "a" → Argon2id(64MB,3,4) → HKDF → DEK ✅ aceptado ❌\n\n// app.js — solo warn, no enforce\nif (!password) { showToast('Introduce...'); return; }`,
    fix: `// Rust: mínimo duro + recomendación\nif password.len() < 12 {\n  return Err("Contraseña mínima 12 caracteres.".into());\n}\n// + advertir si entropía estimada < 60 bits\n\n// JS: bloquear botón si bits < 50\n// const { bits } = evaluatePasswordEntropy(pwd);\n// btn.disabled = bits < 50;\n// + integrar zxcvbn o lista top-10k denegada.`,
    fixLang: "rust",
    effort: "1–2 h · P0",
    status: "Abierto — alto valor",
  },
  {
    id: "MX-04",
    title: "Superficie de dependencias: getrandom js + rand 0.8 + sin cargo-audit en CI",
    severity: "media",
    cvss: 4.8,
    file: "Cargo.toml · .github/workflows/",
    lines: "dependencies",
    category: "Supply chain",
    summary:
      "getrandom 0.2 con feature js (para WASM) es innecesaria en binario desktop y amplía superficie. rand 0.8.5 va una major por detrás (0.9). No hay workflow de cargo audit/deny/outdated ni cargo test en CI: solo existe release.yml.",
    technical:
      "El resto del árbol es ejemplar: cero dependencias NPM, sin plugins Tauri fs/http/shell, pure Rust crypto (ml-kem, aes-gcm, argon2, hkdf, sha2). Pero sin auditoría automatizada de advisories (RUSTSEC), una CVE futura en ml-kem/aes-gcm pasaría desapercibida hasta el release.",
    impact:
      "Riesgo futuro, no presente: hoy no hay CVE conocida en las versiones fijadas (ver tabla supply-chain). El riesgo es de proceso.",
    proof: `[dependencies]\nrand = "0.8.5"            # 0.9 disponible\n getrandom = { version="0.2.15", features=["js"] } # js innecesario\n\n# .github/workflows/ → solo release.yml\n# falta: ci.yml (test + clippy + fmt + audit)`,
    fix: `getrandom = { version = "0.2.15" } # quitar "js"\nrand = "0.9" # migrar (cambios menores OsRng)\n\n# .github/workflows/ci.yml\n# - cargo test --all\n# - cargo clippy -- -D warnings\n# - cargo fmt --check\n# - cargo audit && cargo deny check`,
    fixLang: "toml",
    effort: "2 h · P1",
    status: "Abierto — proceso",
  },
  {
    id: "MX-05",
    title: "Decapsulation key descifrada en Vec<u8> sin zeroize",
    severity: "baja",
    cvss: 3.3,
    file: "src/wraith/decryptor.rs",
    lines: "≈ L70–90",
    category: "Higiene de memoria",
    summary:
      "El proyecto usa Zeroizing/MasterKeys de forma ejemplar, pero hay una excepción: decaps_key_bytes (2400/3168 B, secreto PQC de largo plazo del contenedor) vive en Vec<u8> plano y no se borra tras decapsular.",
    technical:
      "decrypt_aes_gcm devuelve Vec<u8>; el llamador lo pasa a pqc_decapsulate y luego lo deja caer sin zeroize. El allocador puede retener las páginas y el secreto puede aparecer en core dumps / swap / volcados forenses. Mismo caso menor para pqc_ct (no secreto, pero conviene uniformidad) y plaintext_chunk sí se borra correctamente (bien).",
    impact:
      "Exposición forense post-mortem del secreto PQC en RAM/swap. Requiere acceso a memoria del proceso o dump; severidad baja.",
    proof: `let decaps_key_bytes = decrypt_aes_gcm(...)?; // Vec<u8> plano\nlet pqc_shared_secret =\n  pqc_decapsulate(header.suite, &decaps_key_bytes, &pqc_ct)?;\n// decaps_key_bytes cae sin zeroize ❌\n// (plaintext_chunk más abajo SÍ hace .zeroize() ✅)`,
    fix: `use zeroize::{Zeroizing, Zeroize};\nlet mut decaps_key_bytes =\n  Zeroizing::new(decrypt_aes_gcm(...)?);\nlet pqc_shared_secret = pqc_decapsulate(\n  header.suite, &decaps_key_bytes, &pqc_ct)?;\n// drop → zeroize automático ✅\n// Alternativa: decaps_key_bytes.zeroize();`,
    fixLang: "rust",
    effort: "10 min · P1",
    status: "Abierto — quick win",
  },
  {
    id: "MX-06",
    title: "Manifest usa solo UUID como AAD (header completo sería ideal)",
    severity: "baja",
    cvss: 2.9,
    file: "src/wraith/manifest.rs",
    lines: "encrypt/decrypt",
    category: "AEAD · Defensa en profundidad",
    summary:
      "La wrap-key ata correctamente los 64 B del header como AAD (excelente). El manifest, en cambio, solo ata container_uuid (16 B). Funcionalmente seguro (UUID aleatorio de 128 bits), pero ata menos contexto del necesario.",
    technical:
      "Un atacante no puede transplantar manifests entre contenedores salvo colisión UUID (2⁻⁶⁴, inviable) y además necesitaría manifest_key (derivada de password+PQC). El hallazgo es de robustez conceptual: atar header_bytes completo haría el binding explícito y futuro-proof ante cambios de formato.",
    impact:
      "Sin impacto explotable hoy. Endurecimiento recomendado para WRAITH v4.1.",
    proof: `// manifest.rs — actual\nencrypt_aes_gcm(manifest_key, &nonce, &json, container_uuid)\n// vs wrap-key — ideal:\n// encrypt_aes_gcm(wrap_key, &nonce, &dk, &header_bytes)`,
    fix: `// Pasar header_bytes al manifest:\npub fn encrypt(&self, key: &[u8;32], header: &[u8;64], ...) {\n  let mut aad = Vec::with_capacity(80);\n  aad.extend_from_slice(header);      // versión+suite+salt+uuid+...\n  aad.extend_from_slice(container_uuid);\n  encrypt_aes_gcm(key, &nonce, &json, &aad)\n}\n// ⚠️ cambio de formato → bump a v4.1 o flag.`,
    fixLang: "rust",
    effort: "1 h · P2 (rompe formato)",
    status: "Diferible a v4.1",
  },
  {
    id: "MX-07",
    title: "Nonces aleatorios por chunk (birthday bound teórico)",
    severity: "baja",
    cvss: 2.3,
    file: "src/wraith/encryptor.rs · src/crypto/aead.rs",
    lines: "generate_nonce por chunk",
    category: "AEAD · Diseño nonce",
    summary:
      "Cada chunk usa nonce aleatorio de 96 bits vía OsRng. Es correcto y estándar, pero con 2³² chunks (~68 mil millones de chunks de 16 MiB = 1 exabyte) la probabilidad de colisión llega al ~39%. Un esquema derivado determinista eliminaría el riesgo por construcción.",
    technical:
      "En la práctica es inalcanzable (nadie cifra 1 EB en un contenedor), y el AAD por chunk (index+isFinal+len) mitiga reordenamiento aunque hubiese colisión parcial. Aun así, NIST SP 800-38D desaconseja nonces aleatorios para volúmenes masivos; la mejor práctica es nonce = HKDF(DEK, 'chunk-nonce' || index) o contador de 96 bits con prefijo aleatorio.",
    impact:
      "Teórico. Sin escenario realista de explotación. Recomendación de diseño a largo plazo.",
    proof: `let chunk_nonce = generate_nonce(&mut rng); // 96b random\nlet ct = encrypt_aes_gcm(&dek, &chunk_nonce, &buf[..n], &aad)?;\n// colisión → reutilización de (key,nonce) → pérdida de\n// confidencialidad de ambos chunks (XOR de keystreams)`,
    fix: `// Opción A: contador con base aleatoria (recomendada)\n// file_nonce_base[4B random] || chunk_index[8B BE]\n// → unicidad garantizada hasta 2⁶⁴ chunks.\n// Opción B: SIV / deterministic: HKDF(dek, index).\n// ⚠️ cambio de formato → planificar v5 o flag.`,
    fixLang: "rust",
    effort: "3–4 h · P2",
    status: "Aceptar riesgo o plan v5",
  },
  {
    id: "MX-08",
    title: "Inconsistencia de flags CLI: --passes vs --shred-passes",
    severity: "baja",
    cvss: 2.0,
    file: "src/cli.rs",
    lines: "handle_encrypt/decrypt vs handle_shred vs help",
    category: "UX · CLI",
    summary:
      "La ayuda documenta miragex shred <f> [--passes N] [--mode …] y encrypt/decrypt con --shred/--mode/--passes, pero handle_encrypt/handle_decrypt solo aceptan --shred-mode/--shred-passes, mientras handle_shred solo acepta --passes/--mode. Los flags documentados se ignoran silenciosamente (_ => {}).",
    technical:
      "Consecuencia: miragex encrypt f --shred --passes 7 hace shred con 3 pasadas por defecto (el 7 se ignora). No es vulnerabilidad de seguridad directa, pero viola el principio de no-sorpresa en una herramienta de borrado seguro, donde el usuario cree haber pedido 7 pasadas.",
    impact:
      "Confusión operativa en borrado seguro. Severidad baja, pero toca la promesa de seguridad del shredder.",
    proof: `// help:  --passes <N>   --mode <hdd|ssd>\n// encrypt/decrypt esperan: --shred-passes / --shred-mode\n"--shred-passes" => { shred_passes = ... }\n_ => {} // --passes cae aquí y se ignora ❌\n// shred espera: --passes / --mode (al revés)`,
    fix: `// Aceptar ambos alias en los tres handlers:\n"--shred-passes" | "--passes" => { ... }\n"--shred-mode" | "--mode" => { ... }\n// + test CLI: assert que --passes 7 → passes==7\n// + unificar help.`,
    fixLang: "rust",
    effort: "30 min · P1",
    status: "Abierto",
  },
  {
    id: "MX-09",
    title: "Parámetros Argon2 no versionados en el header",
    severity: "baja",
    cvss: 2.1,
    file: "src/wraith/header.rs · src/wraith/decryptor.rs",
    lines: "WraithHeader 64B",
    category: "Agilidad cripto · Formato",
    summary:
      "El header de 64 B no almacena m_cost/t_cost/p_cost ni versión de KDF. El descifrador usa siempre DEFAULT (64 MiB/3/4). Hoy es coherente (el cifrador también usa default), pero impide endurecer la KDF en el futuro sin romper todos los contenedores existentes.",
    technical:
      "El campo flags (u32) está reservado y en cero: es el lugar natural para versionar KDF. Sin agilidad, un futuro aumento (p.ej. 256 MiB ante GPUs más rápidas) requeriría heurística de detección o migración manual. OWASP actualiza sus mínimos periódicamente; el formato debería anticiparlo.",
    impact:
      "Deuda técnica de formato. Sin impacto de seguridad hoy; bloquea endurecimiento futuro.",
    proof: `pub struct WraithHeader {\n  version: u8, suite: PqcSuite,\n  salt: [u8;32], uuid: [u8;16],\n  chunk_size: u32, flags: u32, // =0, sin KDF id\n}\n// decrypt: DecryptOptions::default() siempre`,
    fix: `// Reservar flags: bits 0-7 = kdf_id (0=Argon2id-64/3/4)\n// bits 8-31 reservados. En decrypt:\n// match kdf_id { 0 => default, _ => UnsupportedKdf }\n// Documentar matriz de compatibilidad en SPEC.md.`,
    fixLang: "rust",
    effort: "2 h · P2",
    status: "Roadmap v4.1",
  },
  {
    id: "MX-10",
    title: "Password en argv (-p), heap JS y String Rust sin mlock",
    severity: "baja",
    cvss: 3.7,
    file: "src/cli.rs · ui/app.js · src/commands/mod.rs",
    lines: "get_password / IPC",
    category: "Gestión de secretos",
    summary:
      "Tres vectores menores de exposición del password: (1) -p/--password visible en ps/top e historial shell (documentado, pero permitido); (2) input JS + IPC JSON dejan copias inmutables en heap del renderer que no se pueden zeroizar y no se limpian tras operar; (3) String Rust se zeroiza al final (bien), pero sin mlock puede paginarse a swap.",
    technical:
      "El código hace lo razonable: advierte en help, ofrece --password-stdin y prompt oculto con rpassword, y zeroiza args[i+1] y password:String tras usar. Pero argv original del SO, JSON IPC y heap V8 quedan fuera de control. Es el estado del arte para apps Tauri/CLI sin keyring del SO; el hallazgo documenta el límite y propone mitigaciones.",
    impact:
      "Exposición local/forense del password. Requiere acceso a la máquina o a dumps. Común a 1Password/age/VeraCrypt en modo password; no es defecto grave.",
    proof: `// argv visible: ps aux | grep miragex\nmiragex encrypt doc.pdf -p 'S3cr3t!' # ❌ en ps\n\n// app.js: password vive en DOM + JSON IPC\npassword: password, // → Tauri IPC → Rust String\n// input.value nunca se limpia tras éxito`,
    fix: `// 1. Tras éxito: input.value=''; password=null;\n// 2. CLI: warning si detecta -p + sugerir --password-stdin\n// 3. Considerar keyring del SO (keyring-rs) para sesiones\n// 4. Opcional: mlock/VirtualLock para MasterKeys\n//    (crate memsec) + --no-swap-hint en docs.`,
    fixLang: "js",
    effort: "1 h · P1",
    status: "Mitigación parcial",
  },
  {
    id: "MX-11",
    title: "Sin CI de tests/clippy/fmt ni fuzzing; falta SECURITY.md",
    severity: "info",
    cvss: 0.0,
    file: ".github/ · tests/ · (raíz)",
    lines: "—",
    category: "Proceso · Testing",
    summary:
      "La suite de tests es buena (roundtrip 768/1024, tampering, allocation-bombs, canonical-bool, EOF estricto, path-traversal), pero no corre en CI: solo existe release.yml. Sin clippy -D warnings, fmt --check, audit ni fuzzing del parser binario.",
    technical:
      "El parser binario (header+envelope+chunks+trailer) es la superficie ideal para cargo-fuzz / cargo-afl: ya tiene cotas estrictas que el fuzzer validaría. También faltan: SECURITY.md (canal de reporte, PGP, SLA), SPEC.md del formato WRAITH v4 (layout byte-exacto para interoperabilidad), y badge de cobertura.",
    impact:
      "Proceso, no vulnerabilidad. Mejora continua.",
    proof: `# tests/ — 620 líneas, 10+ tests ✅\n# .github/workflows/ — solo release.yml ❌\n# raíz — sin SECURITY.md / SPEC-WRAITH-v4.md ❌`,
    fix: `# ci.yml: test (linux/mac/win) + clippy + fmt + audit\n# fuzz/: cargo-fuzz target decrypt_stream con\n# diccionario {WRAITH, WRAITHMF, MIRG, MIRAGE}\n# SECURITY.md: security@…, PGP, threat model, SLA 90d.`,
    fixLang: "bash",
    effort: "1 día · P1/P2",
    status: "Backlog sano",
  },
  {
    id: "MX-12",
    title: "Detalles menores: versiones y chunk_size sin validar en decrypt",
    severity: "info",
    cvss: 0.0,
    file: "Cargo.toml · tauri.conf.json · decryptor.rs",
    lines: "—",
    category: "Higiene",
    summary:
      "Tres nits: (1) versión 4.0.1 (Cargo) vs 4.0.0 (tauri.conf + banner CLI) — desincronía; (2) header.chunk_size se autentica vía wrap-AAD pero nunca se valida funcionalmente en decrypt (payload_len solo se cota a 256 MiB); (3) errores distinguen wrap/chunk/hash (oráculo menor, irrelevante offline).",
    technical:
      "Ninguno es explotable: (1) cosmético; (2) la autenticidad del header ya impide manipulación silenciosa, la validación sería defensa en profundidad (rechazar chunks > header.chunk_size salvo el final); (3) como el atacante offline puede distinguir igualmente re-derivando, unificar mensajes solo endurece UX, no seguridad.",
    impact: "Nulo. Pulido.",
    proof: `Cargo.toml: 4.0.1 ≠ tauri.conf: 4.0.0 ≠ banner: v4.0.0\n// decryptor: header.chunk_size leído, jamás comparado\nif payload_len > MAX_CHUNK_PAYLOAD_LEN { reject }\n// falta: if !is_final && payload_len != header.chunk_size`,
    fix: `// 1. Single source: version en Cargo.toml →\n//    tauri.conf via tauri-build + env! en banner.\n// 2. En decrypt: validar chunk regular == header.chunk_size.\n// 3. Opcional: mensaje uniforme "auth failed".`,
    fixLang: "rust",
    effort: "45 min · P2",
    status: "Nits",
  },
];

export const strengths = [
  {
    title: "Arquitectura híbrida PQC correcta",
    desc: "ML-KEM (FIPS 203) + Argon2id + HKDF-SHA512 con domain separation + AES-256-GCM. El DEK combina password_key || pqc_ss: rompe HNDL sin confiar solo en PQC ni solo en password.",
    icon: "atom",
  },
  {
    title: "AAD secuencial anti-reordenamiento",
    desc: "UUID || index || isFinal || len por chunk + header completo como AAD de la wrap-key. Reordenar, truncar o flipear bits falla en autenticación. Lookahead EOF evita TOCTOU.",
    icon: "link",
  },
  {
    title: "Parser endurecido ejemplar",
    desc: "Cotas estrictas (pqc_ct exacto, wrapped ≤8 KiB, chunk ≤256 MiB, manifest ≤64 KiB), bool canónico, EOF estricto, hash constant-time. Tests de allocation-bomb incluidos.",
    icon: "shield",
  },
  {
    title: "Higiene de memoria seria",
    desc: "Zeroizing/ZeroizeOnDrop en password_key, wrap_key, MasterKeys, shared_secret; plaintext_chunk.zeroize(); scrub de argv y password:String. Raro ver esto tan consistente.",
    icon: "eraser",
  },
  {
    title: "Path traversal neutralizado + tests",
    desc: "sanitize_filename (controles, backslash, basename, ., ..) con 8 casos de test incluyendo ..\\..\\Windows y null-byte. Commit atómico tmp+rename con fallback EXDEV.",
    icon: "folder",
  },
  {
    title: "Tauri mínimo privilegio + frontend XSS-safe",
    desc: "CSP restrictiva, sin plugins fs/http/shell, ACL explícita por comando, cero NPM deps, y app.js sin un solo innerHTML (todo textContent/createElement).",
    icon: "monitor",
  },
  {
    title: "Shredder honesto (best-effort)",
    desc: "Distingue HDD (DoD multi-pass) vs SSD (anti-dedup + ofuscación de metadatos) y documenta límites FTL/wear-leveling en vez de prometer borrado imposible.",
    icon: "flame",
  },
  {
    title: "Release hardening + big-endian determinista",
    desc: "panic=abort, overflow-checks, LTO, strip, opt-3; layout big-endian cross-platform; streaming <25 MB para ficheros >100 GB.",
    icon: "cpu",
  },
];

export const scores = [
  { label: "Criptografía aplicada", score: 9.2, max: 10, note: "FIPS 203 + Argon2id + HKDF + GCM correctos" },
  { label: "Parser / formato WRAITH", score: 9.0, max: 10, note: "Cotas, canónico, EOF, tests anti-bomba" },
  { label: "Gestión de claves y memoria", score: 8.4, max: 10, note: "Zeroize consistente; falta MX-05 + mlock" },
  { label: "Storage atómico / shred", score: 8.0, max: 10, note: "Atómico + honesto; falta 0600 (MX-02)" },
  { label: "GUI Tauri / IPC / XSS", score: 8.8, max: 10, note: "CSP + ACL + cero innerHTML" },
  { label: "CLI / UX segura", score: 7.2, max: 10, note: "MX-01, MX-08, MX-03 lastran" },
  { label: "Supply chain / deps", score: 7.6, max: 10, note: "Cero NPM; falta audit CI (MX-04)" },
  { label: "Tests / CI / docs", score: 7.8, max: 10, note: "Buena suite; sin CI ni fuzz (MX-11)" },
];

export const attackMatrix = [
  { attack: "Bit-flip en header (suite, chunk_size)", result: "Bloqueado", detail: "Wrap-AAD sobre 64 B → ManifestAuthFailed. Test incluido." },
  { attack: "Reordenar / duplicar chunks", result: "Bloqueado", detail: "AAD con index+isFinal+len + check secuencial." },
  { attack: "Truncar último chunk / quitar trailer", result: "Bloqueado", detail: "Lookahead EOF + manifest total_chunks + EOF estricto." },
  { attack: "Password incorrecto", result: "Bloqueado", detail: "Wrap auth falla antes de tocar chunks; mensaje genérico." },
  { attack: "Allocation bomb (pqc_ct = 0xFFFFFFFF)", result: "Bloqueado", detail: "Igualdad estricta con tamaño NIST; test incluido." },
  { attack: "wrapped_len gigante", result: "Bloqueado", detail: "Cota 8 KiB; test incluido." },
  { attack: "is_final = 0x02 (no canónico)", result: "Bloqueado", detail: "Match 0/1 estricto; test incluido." },
  { attack: "Basura tras manifest (smuggling)", result: "Bloqueado", detail: "Lectura de 1 byte extra → InvalidContainer; test incluido." },
  { attack: "Path traversal en manifest (../../.ssh)", result: "Bloqueado", detail: "sanitize_filename + 8 tests." },
  { attack: "Chunk con tag GCM corrupto", result: "Bloqueado", detail: "ChunkTampered{index}; plaintext no se escribe." },
  { attack: "Hash SHA-256 no coincide", result: "Bloqueado", detail: "Comparación constant-time + size check." },
  { attack: "Harvest-Now-Decrypt-Later cuántico", result: "Mitigado", detail: "ML-KEM-768/1024: sin PQC-ss no hay DEK aunque caiga AES." },
  { attack: "Diccionario offline con pass débil", result: "Riesgo residual", detail: "MX-03: Argon2id ayuda pero '1234' cae. Política necesaria." },
  { attack: "Lector local de /tmp durante decrypt", result: "Riesgo residual", detail: "MX-02: tmp 0644. Parche 0600 pendiente." },
];

export const deps = [
  { name: "ml-kem", ver: "0.2", role: "PQC KEM (FIPS 203)", risk: "Bajo", note: "Implementación RustCrypto; auditar advisories RUSTSEC." },
  { name: "aes-gcm", ver: "0.10.3", role: "AEAD streaming + wrap + manifest", risk: "Bajo", note: "Con instrucciones AES HW; nonces aleatorios (MX-07)." },
  { name: "argon2", ver: "0.5.3", role: "KDF password (id, 64MiB/3/4)", risk: "Bajo", note: "Parámetros OWASP-conformes. Sin features std extras." },
  { name: "hkdf / sha2", ver: "0.12.4 / 0.10.8", role: "HKDF-SHA512 + SHA-256 manifiesto", risk: "Bajo", note: "Domain separation con labels v4." },
  { name: "rand / getrandom", ver: "0.8.5 / 0.2.15", role: "OsRng sales, UUID, nonces", risk: "Medio", note: "MX-04: quitar feature js; migrar rand 0.9." },
  { name: "zeroize / subtle", ver: "1.8.1 / 2.6.1", role: "Borrado memoria + ct-eq", risk: "Bajo", note: "Uso ejemplar; ampliar a MX-05." },
  { name: "tauri (+build)", ver: "2.0.0", role: "GUI desktop + IPC", risk: "Bajo", note: "Sin plugins fs/http/shell. CSP + ACL mínimas." },
  { name: "rfd / rpassword", ver: "0.15 / 7.3", role: "Diálogos nativos + prompt oculto", risk: "Bajo", note: "Evitan webview file-input; bien." },
  { name: "serde / serde_json / hex", ver: "1.0 / 1.0 / 0.4.3", role: "Manifiesto JSON + hex inspección", risk: "Bajo", note: "Manifest cifrado; JSON solo tras auth." },
  { name: "NPM / frontend", ver: "0 deps", role: "ui/ vanilla JS+CSS", risk: "Mínimo", note: "Sin bundler ni supply-chain JS. Excelente." },
];

export const roadmap = [
  {
    phase: "P0 · 7 días",
    color: "#ef4444",
    items: [
      "MX-01: clamp mínimo 64 KiB en chunk_size + test ÷0.",
      "MX-02: OpenOptions mode 0600 en los 3 tmp + test de permisos.",
      "MX-03: mínimo 12 caracteres + bloqueo <50 bits en GUI + docs.",
      "MX-05: Zeroizing en decaps_key_bytes (10 min).",
    ],
  },
  {
    phase: "P1 · 30 días",
    color: "#fbbf24",
    items: [
      "MX-04: quitar getrandom/js, rand 0.9, ci.yml (test/clippy/fmt/audit/deny).",
      "MX-08: alias --passes/--shred-passes + unificar help + tests CLI.",
      "MX-10: limpiar inputs tras operar, warning -p, evaluar keyring-rs.",
      "MX-11: SECURITY.md + SPEC-WRAITH-v4.md + badges.",
    ],
  },
  {
    phase: "P2 · v4.1 / v5",
    color: "#22d3ee",
    items: [
      "MX-06: AAD de manifest = header+UUID (bump formato).",
      "MX-07: nonces contador/HKDF (bump formato o flag).",
      "MX-09: kdf_id en flags + matriz compatibilidad.",
      "Fuzzing continuo (cargo-fuzz) + cobertura + 2ª revisión externa.",
    ],
  },
];
