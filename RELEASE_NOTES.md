<div align="center">

<img src="https://raw.githubusercontent.com/Rainb0wJagu4r/MirageX/main/assets/logo.png" alt="MirageX Logo" width="220" />

# MirageX v4.0.1 — Post-Quantum Cryptographic Release
### Official Multi-Platform Binaries & Security Hardened Release

[![Release Version](https://img.shields.io/badge/Release-v4.0.1-brightgreen.svg)](https://github.com/Rainb0wJagu4r/MirageX/releases/tag/v4.0.1)
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST SP 800-22](https://img.shields.io/badge/NIST%20SP%20800--22%20Stats-PASS-brightgreen.svg)](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results)
[![Security Hardened](https://img.shields.io/badge/Internal%20Audit-0%20Open%20Issues-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0%20%2F%20MIT-blue.svg)]()

<br/>

<p align="center">
<strong>MirageX v4.0.1</strong> es el motor criptográfico desacoplado y formato de contenedor binario (<strong>WRAITH v4</strong>), diseñado para mitigar riesgos de computación cuántica (<em>NIST FIPS 203 ML-KEM</em>), evaluado estadísticamente con la suite de aleatoriedad <strong>NIST SP 800-22</strong> y endurecido tras dos rondas de revisión y pruebas de seguridad interna.
</p>

<br/>

---

## 📦 Archivos de Descarga y Checksums SHA-256

</div>

| Plataforma | Archivo / Instalador | Formato | Tamaño | Checksum SHA-256 |
| :--- | :--- | :---: | :---: | :--- |
| 🍎 **macOS (Apple Silicon)** | `MirageX_4.0.0_aarch64.dmg` | Instalador DMG con GUI | `3.3 MB` | `60e24c6bfc8e6855b210138f8f560f43ebe8b538977ddf1d2dfcb21d8c2bb3c1` |
| 🍎 **macOS (Bundle)** | `MirageX.app` | App Bundle Nativo | `7.0 MB` | *(Contenido firmado en bundle)* |
| 🍎 **macOS (CLI)** | `miragex_macos_cli` | Binario CLI Nativo | `7.0 MB` | `a9d49580e5f63c23f484bf27830d6495098c41198baddd463bc055ddbc8c7084` |
| 🪟 **Windows (x64)** | `miragex.exe` | Ejecutable Portable Nativo | `5.0 MB` | `c46e20d7c889a6f18d53d2a9bc8a9d734d65e267927a850a8cf4b0efe8bd0cb2` |

<div align="center">

---

## 🚀 Novedades y Características en v4.0.1

<p align="center">

**1. Criptografía Post-Cuántica (PQC)**<br/>
Implementación estricta de **NIST FIPS 203**: **ML-KEM-768** (Nivel 3) y **ML-KEM-1024** (Nivel 5).<br/>
Envelope híbrido: `Argon2id + ML-KEM Key Encapsulation -> HKDF-SHA512 -> AES-256-GCM DEK`.<br/>
Mitigación arquitectónica frente a riesgos de interceptación *Harvest Now, Decrypt Later* (HNDL).

<br/>

**2. Sistema Dual de Borrado Seguro (SSD & HDD)**<br/>
⚡ **Modo SSD / NVMe:** Secuencia de mitigación de *Wear-Leveling* (CSPRNG de alta entropía anti-deduplicación FTL + Truncamiento a 0 bytes + 3 pasadas de ofuscación de metadatos MFT/Inode).<br/>
💾 **Modo HDD:** Sobrescritura magnética física clásica multi-paso (DoD 5220.22-M con CSPRNG + 0x55 + 0xAA + Ceros).<br/>
Disponible tanto en la herramienta independiente de triturado como durante el cifrado/descifrado de archivos.

<br/>

**3. Parser Binario WRAITH Blindado contra Ataques Hostiles**<br/>
Validación estricta de longitudes y mitigación de *Allocation / Length Bombs* (`pqc_ct_len`, `MAX_WRAPPED_KEY_LEN`, `MAX_CHUNK_PAYLOAD_LEN`, `MAX_MANIFEST_LEN`).<br/>
Comprobación canónica obligatoria de flags (`is_final`), detección de bytes de basura anexados (*trailing garbage*) y verificación cruzada de conteo de chunks.

<br/>

**4. Streaming a Disco con Consumo Constante de RAM**<br/>
Descifrado directo bloque a bloque hacia archivos temporales atómicos con reemplazo seguro (`commit_file_atomic` con fallback `EXDEV`), permitiendo procesar archivos de cientos de gigabytes consumiendo menos de 25 MB de RAM.

<br/>

**5. Higiene de Memoria y CLI Segura**<br/>
Soporte de contraseña interactiva oculta en terminal (`rpassword`) y lectura desde tuberías (`--password-stdin`).<br/>
Sobrescritura física de claves intermedias y credenciales en memoria física mediante `zeroize::Zeroizing`.

</p>

---

## 💻 Guía Rápida de Uso

### 1. Iniciar Interfaz Gráfica (Desktop GUI)

</div>

```bash
# macOS
open MirageX.app
# o mediante el instalador DMG

# Windows
.\miragex.exe
```

<div align="center">

### 2. Uso por Línea de Comandos (CLI)

</div>

```bash
# Cifrar archivo con PQC Nivel 5 (ML-KEM-1024) y borrado seguro del original (SSD):
./miragex encrypt documento.pdf --pqc 1024 --shred --shred-mode ssd

# Descifrar y verificar autenticidad criptográfica:
./miragex decrypt documento.pdf.wraith

# Inspección estructural de cabecera WRAITH sin requerir contraseña:
./miragex inspect documento.pdf.wraith

# Borrado seguro independiente (Modo HDD DoD 5220.22-M):
./miragex shred archivo_sensible.txt --mode hdd --passes 7
```

<div align="center">

---

## 📊 Evaluación Estadística de Aleatoriedad (NIST SP 800-22)

<p align="center">
Los datos cifrados en contenedores <code>.wraith</code> v4 generados por <strong>MirageX Ultra (ML-KEM-1024 / Nivel 5)</strong> superaron con éxito la batería de pruebas estadísticas de aleatoriedad <strong>NIST SP 800-22</strong> con distribución uniforme de bits y cero sesgos detectables.
</p>

---

**MirageX Development Team**  
*Born in Mexico 🇲🇽 // Production-Ready Post-Quantum Security*

</div>
