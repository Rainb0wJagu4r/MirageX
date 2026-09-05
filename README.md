<div align="center">

<img src="assets/logo.png" alt="MirageX Logo" width="220" />

# MirageX v4.0.1 — Informe Completo de Auditoría y Hardening de Seguridad
### Post-Quantum Cryptographic Engine & WRAITH v4 Binary Container

[![Audit Status](https://img.shields.io/badge/Audit%20Status-100%25%20Remediated-brightgreen.svg)]()
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST SP 800-22](https://img.shields.io/badge/NIST%20SP%20800--22-PASS-brightgreen.svg)](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results)
[![Automated Tests](https://img.shields.io/badge/Tests-18%2F18%20Passing-brightgreen.svg)]()

<br/>

<p align="center">
Este documento detalla exhaustivamente todos los hallazgos de seguridad identificados durante las diversas fases de auditoría técnica sobre <strong>MirageX</strong> y la especificación del formato binario <strong>WRAITH v4</strong>, así como las soluciones criptográficas y de ingeniería implementadas para su <strong>remediación total (100% Corregido)</strong>.
</p>

<br/>

---

## 📊 Resumen Ejecutivo de Estado de Hallazgos

| ID | Hallazgo de Seguridad | Severidad | CVSS | Estado | Solución Técnica en v4.0.1 |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **MX-01** | División por cero / DoS si `chunk_size = 0` | Media | 5.3 | 🟢 **100% Corregido** | Cota mínima `MIN_ALLOWED_CHUNK_SIZE = 64 KiB` y `clamp()` estricto. |
| **MX-02** | Archivos temporales con modo 0644 | Media | 5.5 | 🟢 **100% Corregido** | Modo restrictivo `0o600` en Unix y atómico con fallback `EXDEV`. |
| **MX-03** | Política de contraseñas y entropía | Media | 5.9 | 🟢 **100% Corregido** | Lectura oculta con `rpassword`, tubería `--password-stdin` y validación. |
| **MX-04** | Supply chain y CI/CD de tests | Media | 4.8 | 🟢 **100% Corregido** | Dependencias limpias, `cargo test` continuo en matriz multiplataforma. |
| **MX-05** | Parámetros KDF Argon2id no guardados en contenedor | Media | 5.0 | 🟢 **100% Corregido** | Cabecera WRAITH de 80B serializa `m_cost`, `t_cost`, `p_cost` con límites seguros. |
| **MX-06** | Nonces de AES-GCM aleatorios vs. Deterministas | Baja | 2.3 | 🟢 **100% Corregido** | Esquema **NIST SP 800-38D**: `4B session salt + 8B chunk_index` (0 colisiones). |
| **MX-07** | Capabilities de Tauri con `core:default` | Baja | 2.8 | 🟢 **100% Corregido** | Menor privilegio: restringido a `core:event`, `core:window`, `core:app`. |
| **MX-08** | Inconsistencia de flags CLI de shredder | Baja | 2.0 | 🟢 **100% Corregido** | Unificación de flags `--passes / --shred-passes` y `--mode / --shred-mode`. |
| **MX-09** | Transparencia de implementación `ml-kem` (FIPS 203) | Info | 0.0 | 🟢 **Documentado** | Divulgación formal en docs y README sobre estado pre-1.0 y CMVP. |
| **MX-10** | Limitación de borrado en SSD con FTL/Wear-Leveling | Info | 0.0 | 🟢 **Documentado** | Etiquetado transparente "best-effort" en GUI/CLI y algoritmo de mitigación. |

<br/>

---

## 🔬 Detalle Técnico de las Correcciones Implementadas

<p align="center">

### 1. Versionado y Persistencia de Parámetros KDF Argon2id (MX-05)
La cabecera de WRAITH v4 fue ampliada a **80 bytes** (alineación exacta a bloques de 16 bytes).<br/>
Se serializan explícitamente:
- `argon2_m_cost` (4 bytes, memoria en KiB)
- `argon2_t_cost` (4 bytes, iteraciones)
- `argon2_p_cost` (4 bytes, paralelismo/hilos)

Al descifrar, el motor lee estos valores directamente de la cabecera del archivo y aplica verificaciones de rango (`8 KiB` a `2 GiB`, `1` a `1000` iteraciones, `1` a `64` hilos), eliminando cualquier dependencia de constantes hardcodeadas y previniendo ataques de agotamiento de memoria.

<br/>

### 2. Nonces Deterministas según NIST SP 800-38D (MX-06)
Para eliminar el riesgo teórico del *birthday paradox* en archivos masivos bajo la misma DEK:<br/>
Se genera un prefijo aleatorio CSPRNG de 4 bytes por contenedor y se combina con el índice secuencial `chunk_index` (8 bytes en Big-Endian):
`nonce = [Prefix (4B)] || [ChunkIndex (8B)]`
Garantiza invarianza estricta de nonce y **cero reutilización de nonces**.

<br/>

### 3. Principio de Menor Privilegio en Tauri 2.0 (MX-07)
Se eliminó la concesión de permisos globales `core:default`.<br/>
La aplicación restringe el IPC estrictamente a:
- `core:event:default` (telemetría de progreso en tiempo real)
- `core:window:default` (gestión de ventana HUD)
- `core:app:default` (información del bundle)
- Todos los comandos nativos de MirageX auditados.

<br/>

### 4. Sistema Dual de Borrado Seguro (SSD vs HDD) (MX-10)
- **Modo SSD / NVMe:** Mitigación de controladores FTL mediante escritura de alta entropía anti-deduplicación + truncamiento a 0 + 3 pasadas de sobrescritura de metadatos (Inode/MFT).
- **Modo HDD:** Sobrescritura magnética clásica de grado DoD 5220.22-M (CSPRNG + 0x55 + 0xAA + 0x00).

</p>

---

## 🧪 Matriz de Verificación y Pruebas Automatizadas (18/18 PASS)

</div>

```text
running 4 tests (crypto_tests)
test test_aead_aes_gcm_tamper_detection ... ok
test test_kem_768_roundtrip ... ok
test test_argon2_and_hkdf_domain_separation ... ok
test test_kem_1024_roundtrip ... ok

running 8 tests (security_tests)
test test_path_traversal_sanitization ... ok
test test_temporary_file_cleaned_on_failed_decryption ... ok
test test_allocation_bomb_pqc_ciphertext_rejected ... ok
test test_allocation_bomb_wrapped_key_rejected ... ok
test test_header_bit_flip_tampering_fails ... ok
test test_non_canonical_is_final_rejected ... ok
test test_trailing_garbage_after_manifest_rejected ... ok
test test_argon2_header_kdf_parameters_preservation ... ok

running 6 tests (wraith_tests)
test test_inspect_legacy_project_mirage_mirg_v2 ... ok
test test_wraith_v4_chunk_tamper_fails ... ok
test test_wraith_v4_768_streaming_roundtrip ... ok
test test_storage_local_shredding_hdd_and_ssd ... ok
test test_wraith_v4_1024_streaming_roundtrip ... ok
test test_wraith_v4_wrong_password_fails ... ok

test result: ok. 18 passed; 0 failed; 0 ignored; finished in 0.69s
```

<div align="center">

---

**MirageX Security & Hardening Team**  
*Born in Mexico 🇲🇽 // Production-Ready Post-Quantum Security*

</div>
