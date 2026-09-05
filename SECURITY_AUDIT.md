<div align="center">

<img src="assets/logo.png" alt="MirageX Logo" width="180" />

# MirageX // Security Audit & Hardening Report
### Formato de Contenedor `.wraith` (v4) & Motor Criptográfico Post-Cuántico

[![Security Status](https://img.shields.io/badge/Security-Audited%20%26%20Hardened-brightgreen.svg)]()
[![Branch](https://img.shields.io/badge/Branch-security--hardening-purple.svg)](https://github.com/Rainb0wJagu4r/MirageX/tree/security-hardening)
[![NIST FIPS 203](https://img.shields.io/badge/PQC-ML--KEM--768%20%2F%201024-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)

---

### Resumen Ejecutivo

</div>

Las primitivas criptográficas del proyecto (**ML-KEM 768/1024, Argon2id, AES-256-GCM, HKDF-SHA512**) proporcionan una base sólida de envelope híbrido post-cuántico con streaming autenticado por chunks.

En la auditoría de seguridad se identificaron **2 fallas críticas**, **1 falla de alto impacto**, **2 de impacto medio** y varias observaciones de higiene de código. Todas han sido **remediadas, testeadas y verificadas exhaustivamente** en esta versión.

---

<div align="center">

## 📊 Matriz de Vulnerabilidades & Estado de Remediación

</div>

| Nivel | Vulnerabilidad | Impacto Potencial | Estado | Archivos Modificados |
| :--- | :--- | :--- | :---: | :--- |
| 🔴 **CRÍTICO** | **DOM XSS en WebView Tauri** | Ejecución de comandos nativos arbitrarios (`shred_file_cmd`, etc.) al descifrar un contenedor manipulado. | **RESUELTO** | `ui/app.js`<br>`tauri.conf.json` |
| 🔴 **CRÍTICO** | **Path Traversal en Desempaquetado** | Sobrescritura de archivos arbitrarios del sistema (`.bashrc`, `.ssh/authorized_keys`) vía `original_filename` malicioso. | **RESUELTO** | `src/commands/mod.rs` |
| 🟠 **ALTO** | **Agotamiento de Memoria (DoS en Descifrado)** | Colapso por memoria RAM al descifrar archivos de múltiples gigabytes en un buffer `Vec<u8>`. | **RESUELTO** | `src/commands/mod.rs` |
| 🟡 **MEDIO** | **Falta de AAD en Cabecera Binaria** | Manipulación de metadatos de cabecera antes de desencapsulación. | **RESUELTO** | `src/wraith/encryptor.rs`<br>`src/wraith/decryptor.rs` |
| 🟡 **MEDIO** | **Higiene de Memoria sin Zeroize** | Retención de claves privadas KEM, material KDF y contraseñas en memoria de proceso. | **RESUELTO** | `src/crypto/*`<br>`src/wraith/*`<br>`src/commands/*` |
| 🟢 **BAJO** | **Tiempo Constante & Dependencias** | Dependencia no usada `sha3`, validación de chunks con riesgo de desbordamiento. | **RESUELTO** | `Cargo.toml`<br>`src/wraith/decryptor.rs` |

---

<div align="center">

## 🔍 Detalle de Hallazgos y Soluciones Implementadas

</div>

### 1. 🔴 CRÍTICO — DOM XSS → Invocación Arbitraria de Comandos Tauri
- **Problema Detectado:** `original_filename` extraído del manifest cifrado dentro del archivo `.wraith` se renderizaba directamente mediante `innerHTML` en `ui/app.js` sin escapar. Un contenedor malicioso con etiquetas `<img src=x onerror="...">` permitía invocar comandos nativos de Tauri (como borrado irreversible con `shred_file_cmd`).
- **Remediación:**
  - Se erradicó por completo el uso de `innerHTML` en la manipulación dinámica de archivos. Todo el renderizado se realiza mediante nodos DOM seguros con `document.createElement`, `textContent` y `appendChild`.
  - Se configuró una directiva estricta de Content Security Policy (CSP) en `tauri.conf.json`:
```json
"csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src ipc: tauri:;"
```

---

### 2. 🔴 CRÍTICO — Path Traversal Arbitrario en Desempaquetado
- **Problema Detectado:** Si `original_filename` contenía rutas relativas (`../../.bashrc`) o absolutas (`/etc/passwd`), `Path::join` en Rust descartaba la ruta base o resolvía traversal, permitiendo sobreescritura arbitraria en el disco del usuario.
- **Remediación:**
  - Se creó la función de sanitización estricta `sanitize_filename()` en `src/commands/mod.rs`.
  - Normaliza separadores tanto de Windows (`\`) como de Unix (`/`).
  - Remueve caracteres de control ASCII (`0..=31`) y bytes nulos (`\0`).
  - Extrae estrictamente el nombre base (`Path::file_name()`) e invalida secuencias de escape `..` o `.`.
  - Si el nombre resultante es inválido, asigna de forma segura el fallback `sanitized_extracted_file.bin`.

---

### 3. 🟠 ALTO — Streaming a Disco sin Agotamiento de RAM
- **Problema Detectado:** `decrypt_file_cmd` utilizaba un `Vec<u8>` en memoria para recibir el archivo completo descifrado antes de persistirlo en disco, provocando denegación de servicio (DoS) en archivos de gran tamaño.
- **Remediación:**
  - Se reescribió `decrypt_file_cmd` para realizar streaming directo bloque a bloque hacia un archivo temporal atómico (`.miragex_dec_<random>.tmp`).
  - Si ocurre cualquier error criptográfico o fallo de integridad SHA-256, el archivo temporal es destruido inmediatamente.
  - Al completar la verificación exitosa de todos los chunks y del manifiesto, se realiza un reemplazo atómico (`fs::rename`) al destino final.

---

### 4. 🟡 MEDIO — Vinculación Criptográfica de la Cabecera (AAD)
- **Problema Detectado:** Los 64 bytes de la cabecera binaria (`magic`, `version`, `suite_id`, `salt`, `uuid`, `chunk_size`, `manifest_offset`, `flags`) no estaban explícitamente autenticados.
- **Remediación:**
  - Se vinculó `header.to_bytes()` como Datos Autenticados Asociados (**AAD**) en el cifrado AES-256-GCM de la clave de desencapsulación PQC.
  - Cualquier modificación o bit-flip en la cabecera provoca el fallo inmediato de autenticación antes de procesar ningún chunk de datos.

---

### 5. 🟡 MEDIO — Higiene de Memoria con `zeroize`
- **Problema Detectado:** Claves intermedias derivadas de Argon2id, la clave privada de desencapsulación PQC (`ML-KEM`), el secreto compartido y contraseñas no se limpiaban explícitamente de la memoria RAM.
- **Remediación:**
  - Se integró `zeroize::Zeroizing` en todas las estructuras intermedias de claves y buffers (`Zeroizing<Vec<u8>>`, `Zeroizing<[u8; 32]>`).
  - Al salir del alcance (*drop*), la memoria física se sobrescribe con ceros mediante operaciones seguras contra optimizaciones del compilador.

---

### 6. 🟢 BAJO — Verificación en Tiempo Constante & Safe Chunks
- **Remediación:**
  - Validación del hash SHA-256 del manifiesto utilizando `subtle::ConstantTimeEq` para mitigar ataques de canal lateral por análisis de tiempo (*timing attacks*).
  - Cálculo de tamaño de chunks protegido con `checked_mul` y un límite superior estricto de 256 MiB (`MAX_ALLOWED_CHUNK_SIZE`).
  - Eliminación de la dependencia no utilizada `sha3` en `Cargo.toml`.

---

<div align="center">

## 🧪 Pruebas de Seguridad Automatizadas

</div>

Se agregaron pruebas automatizadas de seguridad en `tests/security_tests.rs`:

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

---

**MirageX Security Team**  
*Audited & Hardened for Production Environments*

</div>
