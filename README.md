<div align="center">

<img src="assets/logo.png" alt="MirageX Logo" width="200" />

# MirageX // Security Hardening & Parser Verification Report (Phase 2)
### Branch: `security-hardening-v2`

[![Security Status](https://img.shields.io/badge/Security-Audited%20%26%20Hardened%20v2-brightgreen.svg)]()
[![Automated Tests](https://img.shields.io/badge/Security%20Tests-17%2F17%20PASSED-brightgreen.svg)]()
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)

<br/>

<p align="center">
Este documento detalla exclusivamente el informe de la segunda auditoría técnica realizada sobre el <strong>parser binario de WRAITH v4</strong> y la interfaz CLI en <strong>MirageX</strong>, abordando el tratamiento de archivos <code>.wraith</code> hostiles, mitigaciones contra <em>length bombs</em>, verificación canónica estricta y protección de credenciales en memoria y terminal.
</p>

<br/>

---

## 📊 Matriz de Nuevas Vulnerabilidades Identificadas & Remediadas

</div>

| Nivel de Severidad | Vulnerabilidad Encontrada | Vector de Amenaza / Impacto | Estado | Archivos Modificados |
| :--- | :--- | :--- | :---: | :--- |
| 🔴 **ALTA (CRÍTICO)** | **Allocation / Length Bombs en Parser Binario** | Contenedor `.wraith` malicioso con campos `u32` en `0xFFFFFFFF` fuerza reservas de ~4 GB de RAM antes de validar (DoS por agotamiento). | **CORREGIDO** | `src/wraith/decryptor.rs`<br>`src/crypto/mod.rs` |
| 🔴 **ALTA (OPERATIVO)** | **Exposición de Contraseña en `argv` y Memoria CLI** | Uso de `-p <pass>` visible en `ps aux`/historial shell y persistencia sin `zeroize` en el buffer `args`. | **CORREGIDO** | `src/cli.rs`<br>`Cargo.toml` |
| 🟠 **MEDIA** | **Aceptación de Valores No Canónicos en `is_final`** | Bytes no canónicos (`0x02`, `0xFF`) se trataban silenciosamente como `false` en vez de rechazar el contenedor. | **CORREGIDO** | `src/wraith/decryptor.rs` |
| 🟠 **MEDIA** | **Ausencia de Verificación EOF tras el Manifiesto** | Inyección de bytes de basura no autenticados (*trailing garbage*) anexados al final del archivo `.wraith`. | **CORREGIDO** | `src/wraith/decryptor.rs` |
| 🟠 **MEDIA** | **Falta de Validación de `manifest.total_chunks`** | Discrepancia entre el conteo de chunks procesados y el total declarado en el manifiesto. | **CORREGIDO** | `src/wraith/decryptor.rs` |
| 🟡 **MEDIA-BAJA** | **TOCTOU en `encrypt_stream` con Archivos Concurrentes** | Determinación de `is_final` basada en `stat()` previo podía truncar archivos en escritura concurrente. | **CORREGIDO** | `src/wraith/encryptor.rs` |
| 🟢 **BAJA (ROBUSTEZ)** | **Fallback Atómico ante `EXDEV` (Cross-Device)** | Fallo al mover archivos entre diferentes particiones o unidades de disco en `fs::rename`. | **CORREGIDO** | `src/commands/mod.rs` |

<div align="center">

---

## 🔍 Análisis Detallado de Hallazgos y Soluciones Técnicas

</div>

### 🔴 1. Protección contra Allocation / Length Bombs en el Parser Binario
<p align="center"><strong>Archivo:</strong> <code>src/wraith/decryptor.rs</code></p>

- **Problema:** El parser binario leía longitudes `u32` crudas del stream (`pqc_ct_len`, `wrapped_len`, `payload_len`, `manifest_len`) y las pasaba directamente a `vec![0u8; len]`. Un archivo de pocos bytes con `0xFFFFFFFF` provocaba pánico por falta de memoria RAM (*Out of Memory*).
- **Remediación:**
  1. `pqc_ct_len` se valida estrictamente contra `header.suite.ciphertext_size()` (1088 bytes para ML-KEM-768 y 1568 bytes para ML-KEM-1024, según NIST FIPS 203).
  2. Se establecieron topes duros innegociables antes de cualquier reserva de memoria:
     - `MAX_WRAPPED_KEY_LEN = 8 KiB`
     - `MAX_CHUNK_PAYLOAD_LEN = 256 MiB`
     - `MAX_MANIFEST_LEN = 64 KiB`
  3. Si cualquier longitud leída excede estos límites, el parser aborta de inmediato con `WraithError::InvalidContainer` sin asignar un solo byte de memoria innecesaria.

---

### 🔴 2. Entrada Segura de Contraseña en CLI y Limpieza de Memoria
<p align="center"><strong>Archivos:</strong> <code>src/cli.rs</code>, <code>Cargo.toml</code></p>

- **Problema:** La CLI obligaba a pasar `-p <password>`, exponiendo la clave en el historial de comandos de shell (`~/.zsh_history`) y en la tabla de procesos del sistema (`ps aux`). Adicionalmente, el vector `args` retenía la copia en memoria.
- **Remediación:**
  1. Se integró el crate `rpassword` para solicitar la contraseña de forma interactiva y oculta en la terminal si no se especifica `-p`.
  2. Se añadió soporte para `--password-stdin` permitiendo pipelines seguros sin tocar argumentos de línea de comandos.
  3. Si se utiliza `-p`, la memoria original dentro del vector `args` y la variable local se sobrescriben inmediatamente con ceros (`zeroize()`).

---

### 🟠 3. Verificación Canónica Estricta del Byte `is_final`
<p align="center"><strong>Archivo:</strong> <code>src/wraith/decryptor.rs</code></p>

- **Problema:** El byte `is_final` se evaluaba como `final_buf[0] == 1`, permitiendo que bytes no canónicos como `0x02` o `0xFF` fueran interpretados silenciosamente como `false`.
- **Remediación:** Se implementó verificación exhaustiva canónica:
```rust
let is_final = match final_buf[0] {
    0 => false,
    1 => true,
    _ => return Err(WraithError::InvalidContainer),
};
```

---

### 🟠 4. Detección y Rechazo de Basura Final (*Trailing Garbage*)
<p align="center"><strong>Archivo:</strong> <code>src/wraith/decryptor.rs</code></p>

- **Problema:** Tras descifrar el manifiesto, el stream no comprobaba si había bytes adicionales inyectados al final del archivo contenedor.
- **Remediación:** Se añadió verificación de EOF estricta tras la lectura del trailer:
```rust
let mut extra = [0u8; 1];
if reader.read(&mut extra)? != 0 {
    return Err(WraithError::InvalidContainer);
}
```

---

### 🟠 5. Validación Cruzada de Conteo de Chunks (`manifest.total_chunks`)
<p align="center"><strong>Archivo:</strong> <code>src/wraith/decryptor.rs</code></p>

- **Problema:** El campo `manifest.total_chunks` no se cotejaba con el contador real de chunks descifrados `expected_chunk_index`.
- **Remediación:** Se incorporó la validación obligatoria:
```rust
if manifest.total_chunks != expected_chunk_index {
    return Err(WraithError::IntegrityHashMismatch);
}
```

---

### 🟡 6. Eliminación de Condición de Carrera (TOCTOU) en Cifrado de Streaming
<p align="center"><strong>Archivo:</strong> <code>src/wraith/encryptor.rs</code></p>

- **Problema:** `is_final` dependía del tamaño de archivo obtenido por `stat()` previo al cifrado. Si el archivo crecía concurrentemente durante la lectura, podía truncarse silenciosamente.
- **Remediación:** Se implementó un sondeo de byte adelantado (*lookahead byte probe*) que detecta el verdadero EOF al momento exacto de la lectura física del stream, independientemente del tamaño reportado previamente por el sistema de archivos.

---

### 🟢 7. Compatibilidad Atómica Cross-Device (`EXDEV`)
<p align="center"><strong>Archivo:</strong> <code>src/commands/mod.rs</code></p>

- **Problema:** `fs::rename` fallaba si el archivo de destino residía en una partición, disco externo o montaje SMB distinto al directorio temporal.
- **Remediación:** Se creó `commit_file_atomic()` que intenta `fs::rename` atómico y, ante error de enlace entre dispositivos (`EXDEV`), ejecuta fallback automático mediante `fs::copy()` seguido de borrado seguro del archivo temporal.

---

<div align="center">

## 🧪 Pruebas de Seguridad y Verificación Automatizada

<p align="center">
Se añadieron 4 nuevos tests específicos en <code>tests/security_tests.rs</code> (alcanzando 17 tests unitarios y de seguridad totales):
</p>

</div>

```bash
cargo test
```

```text
running 4 tests (crypto)
test crypto::aead_aes_gcm_tamper_detection      ... ok
test crypto::kem_768_roundtrip                   ... ok
test crypto::argon2_and_hkdf_domain_separation  ... ok
test crypto::kem_1024_roundtrip                  ... ok

running 7 tests (security)
test security::path_traversal_sanitization               ... ok
test security::temporary_file_cleaned_on_failed_decrypt  ... ok
test security::header_bit_flip_tampering_fails           ... ok
test security::allocation_bomb_pqc_ciphertext_rejected   ... ok
test security::allocation_bomb_wrapped_key_rejected      ... ok
test security::non_canonical_is_final_rejected           ... ok
test security::trailing_garbage_after_manifest_rejected  ... ok

running 6 tests (wraith & legacy)
test wraith::inspect_legacy_project_mirage_mirg_v2 ... ok
test wraith::wraith_v4_chunk_tamper_fails          ... ok
test wraith::wraith_v4_768_streaming_roundtrip     ... ok
test wraith::storage_local_shredding               ... ok
test wraith::wraith_v4_1024_streaming_roundtrip    ... ok
test wraith::wraith_v4_wrong_password_fails        ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

<div align="center">

---

**MirageX Hardened Release — Phase 2**  
*Audited & Certified Robust against Hostile Binary Containers*

</div>
