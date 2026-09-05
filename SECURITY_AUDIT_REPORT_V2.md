<div align="center">

<img src="assets/logo.png" alt="MirageX Logo" width="220" />

# MirageX (WRAITH v4) — Informe Completo de Auditoría y Hardening de Seguridad
### Post-Quantum Cryptographic Engine & WRAITH v4 Binary Container

[![Audit Status](https://img.shields.io/badge/Audit%20Status-100%25%20Remediated-brightgreen.svg)]()
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST SP 800-22](https://img.shields.io/badge/NIST%20SP%20800--22-PASS-brightgreen.svg)](https://github.com/Rainb0wJagu4r/PROJECT-MIRAGE-NIST-Analyze-results)
[![Automated Tests](https://img.shields.io/badge/Tests-20%2F20%20Passing-brightgreen.svg)]()

<br/>

<p align="center">
Este documento detalla exhaustivamente todos los hallazgos de seguridad identificados durante las diversas fases de auditoría técnica (incluyendo la auditoría estática del 5 de septiembre de 2026) sobre <strong>MirageX</strong> y la especificación del formato binario <strong>WRAITH v4</strong>, así como las soluciones criptográficas y de ingeniería implementadas para su <strong>remediación total (100% Corregido)</strong>.
</p>

<br/>

---

## 📊 Resumen Ejecutivo de Estado de Hallazgos

| ID | Hallazgo de Seguridad | Severidad | CVSS | Estado | Solución Técnica en v4.0.1 |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **MX-01** | Panic / DoS con `chunk_size = 0` | Alta | 7.5 | 🟢 **100% Corregido** | Cotas estrictas `MIN_CHUNK_SIZE = 64 KiB`, `MAX_CHUNK_SIZE = 256 MiB` y error formal `InvalidChunkSize`. |
| **MX-02** | Archivos temporales con modo 0644 | Media | 5.5 | 🟢 **100% Corregido** | Modo restrictivo `0o600` en Unix y sustitución atómica con fallback seguro `EXDEV`. |
| **MX-03** | Borrado no seguro de temporal en fallo de descifrado | Media | 5.5 | 🟢 **100% Corregido** | Sustituido `fs::remove_file` por triturado seguro (`shred_file_with_mode`) en todas las ramas de error. |
| **MX-04** | Política de contraseñas y exposición en terminal | Media | 5.9 | 🟢 **100% Corregido** | Entrada oculta con `rpassword`, tubería `--password-stdin` y zeroización de memoria en buffers/strings. |
| **MX-05** | Supply chain, dependencias y testing continuo | Media | 4.8 | 🟢 **100% Corregido** | Dependencias depuradas, cero CVEs conocidas y suite de 20 tests continuos. |
| **MX-06** | Parámetros KDF Argon2id no guardados en contenedor | Media | 5.0 | 🟢 **100% Corregido** | Cabecera WRAITH de 80B serializa `m_cost`, `t_cost`, `p_cost` con límites seguros (8 KiB a 2 GiB). |
| **MX-07** | Nonces de AES-GCM aleatorios vs. Deterministas | Baja | 2.3 | 🟢 **100% Corregido** | Esquema **NIST SP 800-38D**: `4B session salt + 8B chunk_index` (0 colisiones garantizadas). |
| **MX-08** | Capabilities de Tauri con `core:default` | Baja | 2.8 | 🟢 **100% Corregido** | Menor privilegio: restringido estrictamente a `core:event`, `core:window`, `core:app`. |
| **MX-09** | Inconsistencia de flags CLI de shredder | Baja | 2.0 | 🟢 **100% Corregido** | Unificación de flags `--passes / --shred-passes` y `--mode / --shred-mode`. |
| **MX-10** | Verificación de alcance en comando shred | Baja | 2.5 | 🟢 **100% Corregido** | Validación backend `in_p.is_file()` para impedir destrucción accidental de directorios/dispositivos. |
| **MX-11** | Transparencia de biblioteca FIPS 203 ML-KEM | Info | 0.0 | 🟢 **Documentado** | Divulgación en `README.md`, notas de lanzamiento y `THREAT_MODEL.md`. |
| **MX-12** | Trade-off de liberación de texto plano en streaming | Info | 0.0 | 🟢 **Documentado** | Documentado en `THREAT_MODEL.md` (modelo idéntico a `age`/`gpg`, protegido por temporales atómicos). |
| **MX-13** | Ajuste y honestidad en afirmaciones de lanzamiento (Ronda 2) | Media | 4.0 | 🟢 **100% Corregido** | Términos absolutos moderados en `RELEASE_NOTES.md`, aclarando evaluación estadística NIST SP 800-22 vs certificación. |
| **MX-14** | Fijación exacta de dependencia PQC `ml-kem = "=0.2.3"` (Ronda 2) | Baja | 2.0 | 🟢 **100% Corregido** | Dependencia fijada a versión exacta para evitar cambios silenciosos upstream. |
| **MX-15** | Hardening de CI/CD y anclaje por commit SHA (Ronda 2) | Baja | 2.5 | 🟢 **100% Corregido** | Acciones de GitHub ancladas a commit SHA inmutable + ejecución de tests en release. |
| **MX-16** | Limpieza de constantes muertas en backend (Ronda 2) | Info | 0.0 | 🟢 **100% Corregido** | Eliminado `MAX_ALLOWED_CHUNK_SIZE` redundante, unificando en `wraith::MAX_CHUNK_SIZE`. |

<br/>

---

## 🔬 Detalle Técnico de las Correcciones Implementadas

<p align="center">

### 1. Blindaje contra Panic / DoS en Chunk Size (MX-01)
En `src/wraith/mod.rs` y `src/wraith/encryptor.rs`, se definieron cotas mínimas y máximas:<br/>
- `MIN_CHUNK_SIZE = 64 * 1024` (64 KiB)
- `MAX_CHUNK_SIZE = 256 * 1024 * 1024` (256 MiB)
Si el invocador pasa `chunk_size = 0` o un valor fuera de rango, el motor retorna de inmediato el error formal `WraithError::InvalidChunkSize` sin entrar en pánico ni abortar el proceso.

<br/>

### 2. Destrucción Segura de Archivos Temporales en Fallos de Integridad (MX-02 & MX-03)
En `src/commands/mod.rs` y `src/storage/local.rs`:<br/>
- Todos los archivos temporales se crean con permisos Unix exclusivos `0o600` (`rw-------`).
- Si `decrypt_stream` o la validación del hash SHA-256 / trailer falla, el archivo temporal que contenía texto plano parcial es **triturado de inmediato mediante sobrescritura física multi-paso** (`shred_file_with_mode`) antes de retornar el error al usuario.

<br/>

### 3. Versionado y Persistencia de Parámetros KDF Argon2id (MX-06)
La cabecera de WRAITH v4 fue ampliada a **80 bytes** (alineación exacta a bloques de 16 bytes).<br/>
Se serializan explícitamente:
- `argon2_m_cost` (4 bytes, memoria en KiB)
- `argon2_t_cost` (4 bytes, iteraciones)
- `argon2_p_cost` (4 bytes, paralelismo/hilos)

Al descifrar, el motor lee estos valores directamente de la cabecera del archivo y aplica verificaciones de rango (`8 KiB` a `2 GiB`, `1` a `1000` iteraciones, `1` a `64` hilos), eliminando cualquier dependencia de constantes hardcodeadas.

<br/>

### 4. Nonces Deterministas según NIST SP 800-38D (MX-07)
Para eliminar el riesgo teórico del *birthday paradox* en archivos masivos bajo la misma DEK:<br/>
Se genera un prefijo aleatorio CSPRNG de 4 bytes por contenedor y se combina con el índice secuencial `chunk_index` (8 bytes en Big-Endian):
`nonce = [Prefix (4B)] || [ChunkIndex (8B)]`
Garantiza invarianza estricta de nonce y **cero reutilización de nonces**.

<br/>

### 5. Principio de Menor Privilegio en Tauri 2.0 (MX-08)
Se eliminó la concesión de permisos globales `core:default`.<br/>
La aplicación restringe el IPC estrictamente a `core:event:default`, `core:window:default`, `core:app:default` y los comandos nativos de MirageX auditados.

<br/>

### 6. Sistema Dual de Borrado Seguro (SSD vs HDD) y Verificación de Backend (MX-10)
- **Modo SSD / NVMe:** Mitigación de controladores FTL mediante escritura de alta entropía anti-deduplicación + truncamiento a 0 + 3 pasadas de sobrescritura de metadatos (Inode/MFT).
- **Modo HDD:** Sobrescritura magnética clásica de grado DoD 5220.22-M (CSPRNG + 0x55 + 0xAA + 0x00).
- **Seguridad Backend:** Validación obligatoria `in_p.is_file()` para impedir el borrado accidental de directorios o puntos de montaje.

</p>

---

## 🧪 Matriz de Verificación y Pruebas Automatizadas (20/20 PASS)

</div>

```text
running 4 tests (crypto_tests)
test test_aead_aes_gcm_tamper_detection ... ok
test test_kem_768_roundtrip ... ok
test test_argon2_and_hkdf_domain_separation ... ok
test test_kem_1024_roundtrip ... ok

running 10 tests (security_tests)
test test_zero_and_invalid_chunk_size_rejected_gracefully ... ok
test test_shred_directory_rejected ... ok
test test_path_traversal_sanitization ... ok
test test_temporary_file_cleaned_on_failed_decryption ... ok
test test_allocation_bomb_wrapped_key_rejected ... ok
test test_allocation_bomb_pqc_ciphertext_rejected ... ok
test test_header_bit_flip_tampering_fails ... ok
test test_non_canonical_is_final_rejected ... ok
test test_trailing_garbage_after_manifest_rejected ... ok
test test_argon2_header_kdf_parameters_preservation ... ok

running 6 tests (wraith_tests)
test test_inspect_legacy_project_mirage_mirg_v2 ... ok
test test_storage_local_shredding_hdd_and_ssd ... ok
test test_wraith_v4_chunk_tamper_fails ... ok
test test_wraith_v4_768_streaming_roundtrip ... ok
test test_wraith_v4_1024_streaming_roundtrip ... ok
test test_wraith_v4_wrong_password_fails ... ok

test result: ok. 20 passed; 0 failed; 0 ignored; finished in 0.74s
```

<div align="center">

---

**MirageX Security & Hardening Team**  
*Born in Mexico 🇲🇽 // Production-Ready Post-Quantum Security*

</div>
