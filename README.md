<div align="center">

<img src="assets/logo.png" alt="MirageX Ghost Logo" width="220" />

# MirageX
### Next-Generation Post-Quantum Cryptographic Engine & WRAITH v4 Container Format

[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST SP 800-22](https://img.shields.io/badge/NIST%20SP%20800--22-PASS-brightgreen.svg)](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results)
[![Security Audit v3](https://img.shields.io/badge/Audit%20Report-v3%20(100%25%20Remediated)-brightgreen.svg)](SECURITY_AUDIT_REPORT_V3.md)
[![Tauri 2.0](https://img.shields.io/badge/Tauri-v2.0-blue.svg)](https://tauri.app/)
[![License](https://img.shields.io/badge/License-Apache%202.0%20%2F%20MIT-blue.svg)](LICENSE)

<br/>

[📖 Overview](#-overview) •
[⚡ Key Features](#-key-architecture--features) •
[💡 Guide & Cases](#-centro-de-orientación-criptográfica) •
[📦 Installation](#-installation--build) •
[💻 Usage](#-usage) •
[🛡️ Security Audit v3](SECURITY_AUDIT_REPORT_V3.md) •
[📜 Threat Model](THREAT_MODEL.md) •
[📦 Releases](https://github.com/Rainb0wJagu4r/MirageX/releases)

</div>

---

## 📖 Overview

**MirageX** is a quantum-resistant, decoupled file encryption engine and binary container architecture (**WRAITH v4**). Written in pure native **Rust** with a native **Tauri 2.0** desktop interface (zero local HTTP servers, 100% direct native IPC, zero-knowledge, zero-network).

> [!WARNING]
> **Project Origin & Active Development Status**
> - 🇲🇽 **Born in Mexico:** This project is proud to be created in Mexico by Rainb0wJagu4r.
> - **In Active Development:** Software is under active research and continuous implementation.
> - **NIST FIPS 203 Cryptographic Library Notice:** Post-quantum encapsulation is powered by the RustCrypto `ml-kem` implementation (FIPS 203 standard, published August 2024). While mathematically compliant with NIST specifications, it has not undergone formal CMVP hardware module certification; community code reviews and third-party penetration tests are actively encouraged.
> - **NIST SP 800-22 Statistical Audit:** The entropy and pseudorandomness of **MirageX Ultra (ML-KEM-1024 / Level 5 PQC)** WRAITH v4 envelopes have been audited across random binary, structured text, and all-zeroes payloads. All tests passed with zero correlation: [PROJECT-MIRAGE-NIST-Analyze-results](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results).
> - **Open to Audits:** We welcome open cryptographic audits and code reviews to help us continue learning, developing, and contributing to post-quantum cybersecurity.

---

## ⚡ Key Architecture & Features

- **Post-Quantum Cryptography (PQC)**:
  - Official **NIST FIPS 203** standards: **ML-KEM-768** (Security Level 3) and **ML-KEM-1024** (Security Level 5).
  - Hybrid quantum envelope architecture: `Argon2id (Dynamic Header Parameters) + ML-KEM Key Encapsulation -> HKDF-SHA512 -> AES-256-GCM DEK`.
  - Protects files against *Harvest Now, Decrypt Later* (HNDL) adversarial threats.

- **Decoupled Storage Architecture**:
  - The cryptographic engine is completely isolated from the storage medium.
  - Encrypted `.wraith` files can reside in local NVMe/SSD/HDD, external USB drives, air-gapped cold storage, NAS (SMB/NFS), or cloud storage without third parties knowing keys or plaintext metadata.

- **Deterministic & Cross-Platform WRAITH v4 Format**:
  - Strict big-endian 80-byte header with embedded KDF parameter versioning (`m_cost`, `t_cost`, `p_cost`).
  - NIST SP 800-38D deterministic 96-bit chunk nonces (`4-byte session salt || 8-byte chunk index`) guaranteeing zero nonce collision under identical DEK.
  - Streaming authenticated chunking (16 MiB default) with constant memory footprint (<25 MB RAM for >100 GB files).
  - Sequential AAD binding: `UUID || ChunkIndex || IsFinal || PayloadLen` prevents chunk reordering, truncation, or bit-flip tampering.

- **VeraCrypt / Arcanum Compatible Keyfiles**:
  - Two-factor (password + keyfile) or keyfile-only authentication using the same 64/128-byte CRC-32 IEEE 802.3 pool derivation as VeraCrypt and Arcanum, verified byte-for-byte against the official C implementation.
  - Built-in CSPRNG keyfile generator (`OsRng` + mouse-entropy folding radar) with 64, 256, and 1024-byte presets.

- **Portable Encrypted Vaults (`.wvault`)**:
  - Driver-free multi-file containers that pack files and whole directory trees into a WRAITH v4 envelope, protected by password and/or keyfile.
  - Built-in portable in-memory file explorer to browse the vault tree, search, extract individual entries or everything, and lock the vault with in-memory zeroization.

- **🔄 Multiplatform In-App Auto-Updates & Built-in Changelog**:
  - Native in-app updater supporting Windows, macOS, and Linux powered by `tauri-plugin-updater` with Ed25519 digital signature verification.
  - Real-time download progress bar, one-click restart, and a built-in interactive Changelog history viewer.

- **📲 Zero-Network Ephemeral QR Password Share**:
  - Share generated passwords locally via on-screen QR codes rendered 100% in client-side canvas with auto-destruct countdown timer.

---

## 💡 Centro de Orientación Criptográfica ("¿Por dónde empiezo?")

La aplicación incluye una sección dedicada para usuarios que no saben por dónde comenzar:
- **Caso A (Enviar archivos por WhatsApp / Drive / Nube)**: Cifrado individual a contenedor `.wraith` ultra-rápido.
- **Caso B (Múltiples carpetas y proyectos juntos)**: Bóveda `.wvault` con explorador integrado sin requerir drivers en el kernel.
- **Caso C (Autenticación física de doble factor 2FA)**: Uso de Keyfiles estándar VeraCrypt/Arcanum guardados en una memoria USB.
- **Caso D (Venta de PC / Borrado definitivo)**: Triturador seguro con mitigación wear-leveling (SSD/NVMe) o pasadas DoD (HDD).

---

## 🚀 Hardware Benchmarks (Apple Silicon M-Series / Release Mode)

```text
══════════════════════════════════════════════════════
  MirageX Standard (768):     9,760.9 ops/sec
  MirageX Ultra (1024):       7,728.9 ops/sec
  Argon2id (64MB / 3 iter):   80 ms
  AES-256-GCM Hardware Speed: 210.7+ MB/s
══════════════════════════════════════════════════════
```

---

## 📦 Installation & Build

**Prerequisites:** [Rust 1.80+](https://rustup.rs/) on macOS, Linux, or Windows 10/11.

```bash
git clone https://github.com/Rainb0wJagu4r/MirageX.git
cd MirageX
cargo build --release
```

---

## 💻 Usage

### 1. Launch Desktop GUI (Velvet Neon Cyber HUD)

```bash
cargo run --release
```

### 2. Command Line Interface (CLI)

#### Encrypt a file (MirageX Ultra / Level 5 PQC):
```bash
./target/release/miragex encrypt document.pdf --pqc 1024
# Prompts for master password securely with hidden terminal input
```

#### Decrypt & verify cryptographic authenticity:
```bash
./target/release/miragex decrypt document.pdf.wraith
```

#### Inspect container metadata (MirageX v4 & Legacy Project Mirage v1/v2):
```bash
./target/release/miragex inspect document.pdf.wraith
```

#### Securely wipe a sensitive file (CSPRNG Multi-Pass, Best-Effort on SSD/NVMe):
```bash
./target/release/miragex shred sensitive_file.txt --passes 3 --mode ssd
```

#### Generate a VeraCrypt / Arcanum-compatible keyfile:
```bash
./target/release/miragex keyfile generate second_factor.key --size 64
```

#### Encrypt with password + keyfile (2FA) or keyfile only:
```bash
./target/release/miragex encrypt document.pdf -k second_factor.key
# Press Enter at the password prompt to use keyfile-only authentication
```

#### Decrypt with the same keyfile:
```bash
./target/release/miragex decrypt document.pdf.wraith -k second_factor.key
```

#### Run hardware benchmark:
```bash
./target/release/miragex bench
```

---

## ⚛️ NIST SP 800-22 Empirical Entropy & Statistical Randomness Audit

The `.wraith` v4 containers produced by **MirageX Ultra (ML-KEM-1024 / NIST Level 5)** were audited using the **NIST SP 800-22** statistical test suite across diverse payload profiles (random binary, structured repeated text, and all-zeroes `\x00` payloads). Full reports and CLI reproduction tools are hosted at [PROJECT-MIRAGE-NIST-Analyze-results](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results).

| NIST SP 800-22 Statistical Test | Random Binary Payload | Structured Text Payload | All-Zeroes `\x00` Payload | Statistical Status ($\alpha=0.01$) |
| :--- | :---: | :---: | :---: | :---: |
| **Bit Balance (Proportion of 1s)** | 50.00% ones | 49.98% ones | 50.01% ones | **Optimal ($0.5$)** |
| **Serial Autocorrelation (Lag 1)** | `+0.000062` | `-0.000132` | `+0.000164` | **Zero Correlation** |
| **Frequency (Monobit) Test** | `0.71236` | `0.20062` | `0.64910` | **PASS** |
| **Frequency Test within a Block ($M=128$)** | `0.06584` | `0.47384` | `0.82379` | **PASS** |
| **Runs Test** | `0.79946` | `0.58692` | `0.50191` | **PASS** |
| **Longest Run of Ones in a Block** | `0.29160` | `0.47189` | `0.17197` | **PASS** |
| **Discrete Fourier Transform (Spectral)** | `0.30926` | `0.66735` | `0.81112` | **PASS** |
| **Cumulative Sums (Cusum Forward)** | `0.75004` | `0.07870` | `0.87089` | **PASS** |
| **Cumulative Sums (Cusum Backward)** | `0.93817` | `0.38733` | `0.46799` | **PASS** |
| **Approximate Entropy ($m=3$)** | `0.99139` | `0.42544` | `0.82460` | **PASS** |
| **Serial Test ($m=3$)** | `0.93628, 0.73516` | `0.46603, 0.43912` | `0.73596, 0.51164` | **PASS** |
| **Non-overlapping Template Matching** | `0.84219` | `0.23030` | `0.99140` | **PASS** |
| **OVERALL VERDICT** | **NIST STS PASS** | **NIST STS PASS** | **NIST STS PASS** | **CRYPTOGRAPHIC RANDOM (PASS)** |

---

## ⚠️ Known Limitations

- **Vault size limit:** `.wvault` archives are packed and decrypted in memory and are capped at **2 GiB of plaintext** (plus TAR overhead); larger vaults are rejected with a clear error. Regular `.wraith` file containers keep using streaming with constant memory.
- **No silent overwrites:** when no explicit destination is chosen, existing files are never overwritten (a `name (1).ext` suffix is used), and symlink destinations are refused.
- **Keyfile compatibility is not container compatibility:** keyfile derivation matches VeraCrypt/Arcanum, but MirageX does **not** mount or open VeraCrypt `.tc` / `.hc` / `.vc` volumes. Vaults use the MirageX `.wvault` format.
- **Symlinks are rejected:** vault creation refuses symlinks and special files because following them could include data outside the selected tree or loop indefinitely. Add the real paths instead.
- **Vault UI is desktop-only:** creating, browsing and extracting vaults is currently available in the Tauri GUI; the CLI covers keyfiles and `.wraith` file containers.

---

## 📄 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

---

<div align="center">

Made with love ❤️ by [Rainb0wJagu4r](https://github.com/Rainb0wJagu4r) from Mexico 🇲🇽

</div>
