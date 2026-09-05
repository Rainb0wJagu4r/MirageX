<div align="center">

<img src="assets/logo.png" alt="MirageX Ghost Logo" width="220" />

# MirageX
### Next-Generation Post-Quantum Cryptographic Engine & WRAITH v4 Container Format

[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST SP 800-22](https://img.shields.io/badge/NIST%20SP%20800--22-PASS-brightgreen.svg)](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results)
[![Tauri 2.0](https://img.shields.io/badge/Tauri-v2.0-blue.svg)](https://tauri.app/)
[![Zero Dependencies](https://img.shields.io/badge/Supply%20Chain-Zero%20NPM%20Deps-brightgreen.svg)]()

<br/>

**MirageX** is a quantum-resistant, decoupled file encryption engine and binary container architecture (**WRAITH v4**). Written in pure native **Rust** with a native **Tauri 2.0** cyber HUD desktop interface (zero local HTTP servers, 100% direct native IPC).

<br/>

> [!WARNING]
> **Project Origin & Active Development Status**
> - 🇲🇽 **Born in Mexico:** This project is proud to be born in Mexico.
> - **In Active Development:** Software is under active research and implementation.
> - **NIST SP 800-22 Statistical Audit:** The entropy and pseudorandomness of **MirageX Ultra (ML-KEM-1024 / Level 5 PQC)** WRAITH v4 envelopes have been audited across random binary, structured text, and all-zeroes payloads. All tests passed with zero correlation: [PROJECT-MIRAGE-NIST-Analyze-results](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results).
> - **Open to Audits:** We welcome open cryptographic audits and code reviews to help us continue learning, developing, and contributing to post-quantum cybersecurity.

<br/>

---

## ⚡ Key Architecture & Features

<p align="center">

**Post-Quantum Cryptography (PQC)**<br/>
Official **NIST FIPS 203** standards: **ML-KEM-768** (Security Level 3) and **ML-KEM-1024** (Security Level 5).<br/>
Hybrid quantum envelope architecture: `Argon2id + ML-KEM Key Encapsulation -> HKDF-SHA512 -> AES-256-GCM DEK`.<br/>
Protects data against *Harvest Now, Decrypt Later* (HNDL) adversarial threats.

<br/>

**Decoupled Storage Architecture**<br/>
The cryptographic engine is completely isolated from the storage medium.<br/>
Files `.wraith` can reside in Local NVMe/SSD/HDD, external USB drives, air-gapped cold storage, NAS (SMB/NFS), or Zero-Knowledge cloud without the host knowing keys or plaintext metadata.

<br/>

**Deterministic & Cross-Platform WRAITH v4 Format**<br/>
Strict big-endian layout across **macOS, Windows, and Linux**.<br/>
Streaming authenticated chunking (16 MiB default) with constant memory footprint (<25 MB RAM for >100 GB files).<br/>
Sequential AAD binding: `UUID || ChunkIndex || IsFinal || PayloadLen` prevents chunk reordering, truncation, or bit-flip tampering.

<br/>

**Dual Mode Interface**<br/>
**Native Desktop GUI**: Tauri 2.0 with Electric Purple Cyber HUD, Drag & Drop, native file dialogs (`rfd`), and real-time streaming telemetry.<br/>
**High-Throughput CLI**: Automated headless batch encryption, decryption, inspection, and multi-pass CSPRNG shredding.

<br/>

**Backwards Compatible Container Inspector**<br/>
Instantly inspects `.wraith` containers and identifies whether they belong to the **MirageX v4 (PQC)** generation or legacy **Project Mirage v1 / v2 (Mirage-C4 / AES-GCM)** containers.

</p>

---

## 🚀 Hardware Benchmarks (Apple Silicon M-Series / Release Mode)

</div>

```text
══════════════════════════════════════════════════════
  MirageX Standard (768):     9,760.9 ops/sec
  MirageX Ultra (1024):       7,728.9 ops/sec
  Argon2id (64MB / 3 iter):   80 ms
  AES-256-GCM Hardware Speed: 210.7+ MB/s
══════════════════════════════════════════════════════
```

<div align="center">

---

## 📦 Installation & Build

<p align="center">
<strong>Prerequisites:</strong> <a href="https://rustup.rs/">Rust 1.80+</a> on macOS, Linux, or Windows 10/11.
</p>

</div>

```bash
git clone https://github.com/Rainb0wJagu4r/MirageX.git
cd MirageX
cargo build --release
```

<div align="center">

---

## 💻 Usage

### 1. Launch Desktop GUI (Electric Purple Cyber HUD)

</div>

```bash
cargo run --release
```

<div align="center">

### 2. Command Line Interface (CLI)

</div>

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
./target/release/miragex shred sensitive_file.txt --passes 3
```

#### Run hardware benchmark:
```bash
./target/release/miragex bench
```

<div align="center">

---

## ⚛️ NIST SP 800-22 Empirical Entropy & Statistical Randomness Audit

<p align="center">
The <code>.wraith</code> v4 containers produced by <strong>MirageX Ultra (ML-KEM-1024 / NIST Level 5)</strong> were audited using the <strong>NIST SP 800-22</strong> statistical test suite across diverse payload profiles (random binary, structured repeated text, and all-zeroes <code>\x00</code> payloads).<br/>
Full reports and CLI reproduction tools are hosted at <a href="https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results">PROJECT-MIRAGE-NIST-Analyze-results</a>.
</p>

</div>

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

<div align="center">

---

## 📄 License

Apache 2.0 / MIT.

---

**MirageX // Quantum-Resistant Decoupled Storage**  
*Born in Mexico 🇲🇽*

</div>
