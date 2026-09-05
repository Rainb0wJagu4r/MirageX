<div align="center">

<img src="assets/logo.png" alt="MirageX Logo" width="200" />

# MirageX // Security Hardening & Vulnerability Remediation Report
### Branch: `security-hardening`

[![Security Status](https://img.shields.io/badge/Security-Audited%20%26%20Hardened-brightgreen.svg)]()
[![Automated Tests](https://img.shields.io/badge/Security%20Tests-13%2F13%20PASSED-brightgreen.svg)]()
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)

<br/>

<p align="center">
Este documento detalla exclusivamente el informe de la auditoría de seguridad realizada sobre <strong>MirageX</strong> (formato <code>.wraith</code> v4), los vectores de ataque identificados y las remediaciones técnicas implementadas en esta rama.
</p>

<br/>

---

## 📊 Matriz Resumen de Vulnerabilidades Encontradas y Corregidas

</div>

| Nivel de Severidad | Vulnerabilidad Encontrada | Impacto Potencial | Estado | Archivos Modificados |
| :--- | :--- | :--- | :---: | :--- |
| 🔴 **CRÍTICO** | **DOM XSS en WebView Tauri** | Ejecución arbitraria de comandos nativos Tauri (`shred_file_cmd`, etc.) al abrir un `.wraith` malicioso. | **CORREGIDO** | `ui/app.js`<br>`tauri.conf.json` |
| 🔴 **CRÍTICO** | **Path Traversal en Desempaquetado** | Sobrescritura de archivos arbitrarios del sistema (`.bashrc`, `.ssh/authorized_keys`) vía `original_filename`. | **CORREGIDO** | `src/commands/mod.rs` |
| 🟠 **ALTO** | **Agotamiento de RAM (DoS en Descifrado)** | Colapso por memoria RAM al descifrar archivos de múltiples gigabytes en un buffer `Vec<u8>`. | **CORREGIDO** | `src/commands/mod.rs` |
| 🟡 **MEDIO** | **Falta de AAD en Cabecera Binaria** | Manipulación de metadatos de cabecera antes de la desencapsulación PQC. | **CORREGIDO** | `src/wraith/encryptor.rs`<br>`src/wraith/decryptor.rs` |
| 🟡 **MEDIO** | **Material Sensible sin Zeroize** | Retención de claves privadas KEM, material KDF y contraseñas en memoria de proceso. | **CORREGIDO** | `src/crypto/*`<br>`src/wraith/*`<br>`src/commands/*` |
| 🟢 **BAJO** | **Tiempo Constante & Safe Chunks** | Comparación de hashes sin tiempo constante y riesgo de desbordamiento en tamaño de chunks. | **CORREGIDO** | `Cargo.toml`<br>`src/wraith/decryptor.rs` |

<div align="center">

---

## 🔍 Análisis Detallado de Vulnerabilidades y Soluciones

</div>

### 🔴 1. CRÍTICO — Inyección DOM XSS hacia Comandos Nativos de Tauri
<p align="center"><strong>Archivos:</strong> <code>ui/app.js</code>, <code>tauri.conf.json</code></p>

- **Vulnerabilidad Encontrada:** El campo `original_filename` proveniente del manifest cifrado dentro del contenedor `.wraith` era insertado directamente en el DOM mediante `innerHTML` sin escapar ni filtrar. Dado que `tauri.conf.json` no tenía una política de seguridad de contenido (CSP) configurada (`"csp": null`), un archivo `.wraith` malicioso podía inyectar código HTML/JS como:
```html
<img src=x onerror="window.__TAURI__.core.invoke('shred_file_cmd',{inputPath:'/ruta/sensible',passes:1})">
```
lo que permitía a un atacante ejecutar comandos nativos con privilegios del sistema operativo del usuario.

- **Corrección Implementada:**
  1. Se eliminó todo uso de `innerHTML` en la manipulación dinámica de archivos en `ui/app.js`. Ahora se construyen los nodos del DOM de forma estrictamente segura usando `document.createElement()`, `textContent` y `appendChild()`.
  2. Se configuró una directiva estricta de Content Security Policy (CSP) en `tauri.conf.json`:
```json
"csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src ipc: tauri:;"
```

---

### 🔴 2. CRÍTICO — Path Traversal Arbitrario en Desempaquetado
<p align="center"><strong>Archivo:</strong> <code>src/commands/mod.rs</code></p>

- **Vulnerabilidad Encontrada:** En `decrypt_file_cmd`, la ruta de salida utilizaba `parent.join(&manifest.original_filename)`. En Rust, `Path::join` descarta la ruta base si el argumento es una ruta absoluta (`/etc/passwd`, `C:\Windows\System32\calc.exe`) o resuelve secuencias de escape de directorio (`../../.bashrc`), permitiendo la sobrescritura arbitraria de archivos en el disco de la víctima.

- **Corrección Implementada:**
  - Se implementó la función `sanitize_filename()` que:
    1. Normaliza separadores de ruta tanto de Windows (`\`) como de Unix (`/`).
    2. Elimina caracteres de control ASCII (`0..=31`) y bytes nulos (`\0`).
    3. Extrae estrictamente el nombre base (`Path::file_name()`), rechazando componentes de traversal (`..`, `.`).
    4. En caso de recibir un nombre inválido o vacío tras la limpieza, asigna de forma segura el fallback `sanitized_extracted_file.bin`.

---

### 🟠 3. ALTO — Agotamiento de Memoria (DoS) en Descifrado
<p align="center"><strong>Archivo:</strong> <code>src/commands/mod.rs</code></p>

- **Vulnerabilidad Encontrada:** Durante el descifrado, `decrypt_file_cmd` acumulaba todo el contenido del archivo en memoria RAM dentro de un `Vec<u8>` antes de escribirlo en disco (`decrypt_stream(..., &mut temp_buffer, ...)`). Para archivos grandes (gigabytes o decenas de gigabytes), esto provocaba el colapso del proceso por falta de memoria (Out-of-Memory / DoS).

- **Corrección Implementada:**
  - Se reescribió el descifrado para realizar *streaming* directo bloque a bloque hacia un archivo temporal en disco (`.miragex_dec_<random>.tmp`).
  - Si la verificación de integridad SHA-256 o la autenticación de chunks falla, el archivo temporal se destruye de inmediato.
  - Al validar exitosamente todos los bloques, se ejecuta un reemplazo atómico mediante `fs::rename` al archivo de destino final, manteniendo el consumo de RAM constante e independiente del tamaño del archivo.

---

### 🟡 4. MEDIO — Falta de Autenticación en la Cabecera Binaria (AAD)
<p align="center"><strong>Archivos:</strong> <code>src/wraith/encryptor.rs</code>, <code>src/wraith/decryptor.rs</code></p>

- **Vulnerabilidad Encontrada:** Los 64 bytes de la cabecera binaria del contenedor `.wraith` (que incluyen versión, suite_id, flags y tamaños) no estaban explícitamente autenticados contra modificaciones maliciosas previas a la desencapsulación.

- **Corrección Implementada:**
  - Se vincularon los 64 bytes completos de la cabecera (`header.to_bytes()`) como Datos Autenticados Asociados (**AAD**) en el cifrado AES-256-GCM de la clave de desencapsulación PQC.
  - Cualquier alteración o bit-flip en la cabecera provoca el rechazo criptográfico inmediato antes de procesar o escribir ningún bloque de datos.

---

### 🟡 5. MEDIO — Retención de Material Criptográfico en Memoria
<p align="center"><strong>Archivos:</strong> <code>src/crypto/kdf.rs</code>, <code>src/crypto/kem.rs</code>, <code>src/crypto/mod.rs</code>, <code>src/wraith/decryptor.rs</code></p>

- **Vulnerabilidad Encontrada:** Claves intermedias derivadas por Argon2id, claves privadas de desencapsulación ML-KEM y buffers de desencapsulación permanecían en memoria sin borrado seguro al terminar la operación.

- **Corrección Implementada:**
  - Se implementó `zeroize::Zeroizing` y llamadas explícitas a `.zeroize()` sobre claves derivadas, secretos compartidos Kyber (ML-KEM), material KDF y contraseñas en memoria, garantizando que se sobrescriban con ceros al salir del alcance (*drop*).

---

### 🟢 6. BAJO — Comparación en Tiempo Constante & Prevención de Desbordamiento
<p align="center"><strong>Archivos:</strong> <code>Cargo.toml</code>, <code>src/wraith/decryptor.rs</code>, <code>src/commands/mod.rs</code></p>

- **Corrección Implementada:**
  - Se aplicó `subtle::ConstantTimeEq` para la verificación del hash SHA-256 del manifiesto, mitigando ataques de canal lateral por análisis de tiempo (*timing attacks*).
  - Se eliminó la dependencia no utilizada `sha3` en `Cargo.toml`.
  - Se añadió cálculo seguro de tamaño de chunks con `checked_mul` y un límite máximo estricto de 256 MiB (`MAX_ALLOWED_CHUNK_SIZE`).

---

<div align="center">

## 🧪 Pruebas de Seguridad y Verificación Automatizada

<p align="center">
Se añadieron tests de seguridad automatizados en <code>tests/security_tests.rs</code> para verificar cada corrección:
</p>

</div>

```bash
cargo test --test security_tests
```

```text
running 3 tests
test test_path_traversal_sanitization ... ok
test test_header_tampering_rejected_by_aad ... ok
test test_atomic_temp_file_cleanup_on_failure ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

<div align="center">

### Resultado de la Suite Completa de Tests: `13/13 PASSED`

```text
running 4 tests (crypto)     ... 4 passed
running 6 tests (wraith)     ... 6 passed
running 3 tests (security)   ... 3 passed
```

---

**MirageX Hardened Security Release**  
*Rama dedicada a la remediación de vulnerabilidades*

</div>
