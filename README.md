# MirageX // Post-Quantum Cryptographic Engine & WRAITH v4

[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Tauri 2.0](https://img.shields.io/badge/Tauri-v2.0-blue.svg)](https://tauri.app/)
[![Zero Dependencies](https://img.shields.io/badge/Supply%20Chain-Zero%20NPM%20Deps-brightgreen.svg)]()

**MirageX** is a next-generation, quantum-resistant, decoupled file encryption engine and container format (**WRAITH v4**). Written in pure native **Rust** with a native **Tauri 2.0** desktop interface (zero local web servers, 100% direct IPC).

---

## Key Features

1. **Post-Quantum Cryptography (PQC)**:
   - Official **NIST FIPS 203** standards: **ML-KEM-768** (Security Level 3) and **ML-KEM-1024** (Security Level 5).
   - Hybrid envelope architecture: `Argon2id + ML-KEM Key Encapsulation -> HKDF-SHA512 -> AES-256-GCM DEK`.
   - Protects data against *Harvest Now, Decrypt Later* (HNDL) threats.
2. **Decoupled Storage Architecture**:
   - Cryptographic engine is completely isolated from the storage medium.
   - Files `.wraith` can reside in Local SSD/HDD, USB drives, NAS (SMB/NFS), or Zero-Knowledge cloud without the storage knowing keys or metadata.
3. **Deterministic & Cross-Platform WRAITH v4 Format**:
   - Strict big-endian layout across **macOS, Windows, and Linux**.
   - Streaming authenticated chunking (16 MiB chunks by default) with constant memory footprint (<25 MB RAM for >100 GB files).
   - Sequential AAD binding: `UUID || ChunkIndex || IsFinal || PayloadLen` prevents chunk reordering, truncation, or bit-flip tampering.
4. **Dual Mode Interface**:
   - **Native Desktop GUI**: Tauri 2.0 with Electric Purple Cyber HUD, Drag & Drop, native macOS/Windows file dialogs (`rfd`), and real-time streaming telemetry.
   - **High-Throughput CLI**: Automated headless batch encryption, decryption, inspection, and multi-pass CSPRNG shredding.
5. **Backwards Compatible Inspector**:
   - Instantly inspects `.wraith` containers and detects whether they belong to the **MirageX v4 (PQC)** generation or legacy **Project Mirage v1 (Mirage-C4 / AES-GCM)** containers.

---

## Hardware Benchmarks (Apple Silicon M-Series / Release Mode)

```text
══════════════════════════════════════════════════════
  MirageX Standard (768):     9,760.9 ops/sec
  MirageX Ultra (1024):       7,728.9 ops/sec
  Argon2id (64MB / 3 iter):   80 ms
  AES-256-GCM Hardware Speed: 210.7+ MB/s
══════════════════════════════════════════════════════
```

---

## Installation & Build

### Prerequisites
- [Rust 1.80+](https://rustup.rs/)
- macOS, Linux, or Windows 10/11

### Build Release Binary
```bash
git clone https://github.com/Rainb0wJagu4r/MirageX.git
cd MirageX
cargo build --release
```

---

## Usage

### 1. Launch Desktop GUI
```bash
cargo run --release
```

### 2. Command Line Interface (CLI)

#### Encrypt a file (MirageX Ultra / Level 5 PQC):
```bash
./target/release/miragex encrypt document.pdf -p 'MasterPassword2026!' --pqc 1024
# Outputs: document.pdf.wraith
```

#### Decrypt & verify cryptographic authenticity:
```bash
./target/release/miragex decrypt document.pdf.wraith -p 'MasterPassword2026!'
```

#### Inspect container metadata without password:
```bash
./target/release/miragex inspect document.pdf.wraith
```

#### Securely shred a sensitive file (CSPRNG Multi-Pass):
```bash
./target/release/miragex shred sensitive_file.txt --passes 3
```

#### Run hardware benchmark:
```bash
./target/release/miragex bench
```

---

## Security Model

- **Memory Protection**: Sensitive key materials and intermediate secrets implement `Zeroize` and are cleared from memory upon drop.
- **Envelope Hierarchy**: Password derivation and quantum encapsulation are separated using HKDF domain-separated subkeys (`miragex-v4-pqc-wrap-key`, `miragex-v4-aes256-gcm-dek`, `miragex-v4-manifest-key`, `miragex-v4-header-auth-key`).
- **Integrity**: Full SHA-256 manifest hash verification + GCM authentication tags per chunk.

---

## License
Apache 2.0 / MIT.
