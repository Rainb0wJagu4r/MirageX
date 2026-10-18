# Auditoría de Seguridad — Keyfiles VeraCrypt/Arcanum y Bóvedas `.wvault`

**Proyecto:** MirageX 4.0.1 — motor PQC y contenedor WRAITH v4
**Fecha:** 2026-10-18
**Base auditada:** `main` @ `360d2e2`
**Alcance:** motor de keyfiles (`src/crypto/keyfile.rs`), motor de bóvedas
(`src/vault/mod.rs`), integración Tauri (`src/commands/mod.rs`, `src/main.rs`),
CLI (`src/cli.rs`), UI de keyfiles/bóvedas (`ui/`) y dependencias del
`Cargo.lock`.

---

## 1. Resumen ejecutivo

Se identificaron **2 vulnerabilidades de severidad alta**, ambas corregidas y
con test de regresión:

1. **Tar-slip en la extracción de bóvedas**: un archivo `.wvault` manipulado
   podía escribir fuera de la carpeta de extracción mediante entradas symlink.
2. **Keyfile vacío aceptado**: un archivo de 0 bytes producía una contraseña
   efectiva predecible (64 ceros), permitiendo cifrado con una clave conocida.

Además se corrigieron **4 hallazgos medios/bajos**: sobrescritura silenciosa de
archivos con nombre controlado por el atacante, DoS de memoria en bóvedas,
zeroización incompleta y contraseña persistente en el portapapeles.

**Estado actual:** no se conoce ninguna vulnerabilidad crítica o alta abierta en
el código auditado. Los 11 identificadores de aviso de dependencias detectados
(10 incidencias distintas: `glib` aparece como GHSA y RUSTSEC) no afectan a las
crates criptográficas directas y la mayoría son específicos de Linux
(empaquetado GTK de Tauri) o avisos de "sin mantenimiento" sin CVE asociado.

> **Nota sobre Strix:** se intentó ejecutar Strix 1.6.2 (agente de pentesting)
> contra este repositorio. La instalación y la imagen sandbox están presentes,
> pero la credencial configurada (`gemini/gemini-3.8-flash`) devuelve
> `401 UNAUTHENTICATED — API key not valid`. Tampoco hay sesión de Strix Cloud
> ni login de ChatGPT. Como alternativa se descargó el modelo local
> `qwen2.5-coder:7b` (Ollama) y Strix llegó a iniciar el escaneo, pero el modelo
> no emitía las llamadas de herramientas/lifecycle que exige el agente: solo
> devolvía mensajes y el run quedó en 0 hallazgos. El escaneo se detuvo a
> petición del usuario para no seguir cargando la GPU. Por ello, **este informe
> no contiene resultados de Strix**; se basa en OSV.dev, Semgrep, revisión
> manual y pruebas de concepto reproducibles. Para completar el pentest hace
> falta una credencial válida (API key o `strix auth login chatgpt`) y anexar
> sus resultados a este documento.

---

## 2. Metodología

| Técnica | Herramienta | Cobertura |
|---|---|---|
| Dependencias | OSV.dev `querybatch` | 531 paquetes del `Cargo.lock` |
| Análisis estático | Semgrep `p/rust` + `p/secrets` | `src/`, `tests/` |
| Revisión manual | Lectura línea a línea | Crypto, parser WRAITH, bóvedas, Tauri IPC, UI |
| Pruebas de concepto | Rust (`cargo test`) | Tar-slip, cabecera/manifiesto, keyfiles, límites |
| Pentest con IA | Strix 1.6.2 | **No ejecutado** (credencial inválida) |

Comandos de verificación:

```bash
cargo test --all-targets          # 47 tests, 0 fallos
cargo build                       # OK
semgrep --config p/rust --config p/secrets src tests
```

---

## 3. Trazabilidad y verificación

Esta sección responde a "de dónde salió cada hallazgo" y "cómo sé que está
corregido". Cada fila enlaza el código vulnerable, el commit que lo corrigió y
el test que lo demuestra.

| ID | Origen en el repo | Commit del fix | Código actual | Prueba |
|---|---|---|---|---|
| MX-KF-01 | `src/vault/mod.rs` — working tree de Antigravity (nunca commiteado) | `46397c4` | `is_extractable_entry_type` L135; `unpack_in` L494 y L546 | `tests/vault_tests.rs:156` |
| MX-KF-02 | `src/crypto/keyfile.rs` — working tree de Antigravity (nunca commiteado) | `46397c4` | `apply_keyfiles` L85–92 | `src/crypto/keyfile.rs` (test unitario) y `tests/keyfile_tests.rs:157` |
| MX-VL-01 | `46397c4:src/commands/mod.rs` L687–690 y `commit_file_atomic` L425 | `360d2e2` | `unique_output_path` L427; `reject_symlink_destination` L454 | `tests/vault_tests.rs:265`, `:309`, `:353` |
| MX-VL-02 | `46397c4:src/vault/mod.rs` L148 y L272 (`Vec::new()` sin límite) | `360d2e2` | `MAX_VAULT_PLAINTEXT_SIZE` L31; `LimitedWriter` L39; `validate_source_paths` L144 | `tests/vault_tests.rs:399` + test unitario `test_limited_writer_enforces_limit_and_zeroizes` |
| MX-VL-03 | `46397c4:src/vault/mod.rs` (buffers sin `Zeroizing`) y keyfile sin scrub | `360d2e2` | `Zeroizing` en TAR; keyfile zeroizado en L163 | Inspección de código (la zeroización no es observable por un test funcional) |
| MX-UI-01 | `46397c4:ui/app.js` L569–578 (copiar sin limpiar) | `360d2e2` | `scheduleClipboardClear` L656 | Inspección + prueba manual de UI |
| MX-DEP-01/02 | `Cargo.lock` (dependencias transitivas de Tauri) | No aplica | — | OSV + `cargo tree -i` |
| MX-INFO-01 | Semgrep sobre el código actual | No aplica | — | Salida de Semgrep |

### 3.1 Origen exacto de los dos hallazgos altos

Los dos hallazgos altos **no tienen un commit vulnerable**: el código venía del
working tree que dejó Antigravity y nunca se llegó a commitear. El fix se aplicó
antes del primer commit (`46397c4`), por lo que la versión vulnerable no existe
en la historia de Git. Para que no quede duda de que el test no pasa "en vacío",
se revirtió cada fix en una **copia aislada** y se comprobó que el test falla:

```text
# Copia aislada /tmp/miragex_verify, reversión del fix de extracción (unpack_in -> unpack)
$ cargo test --test vault_tests test_vault_extraction_rejects_symlink_tar_slip -- --exact
thread 'test_vault_extraction_rejects_symlink_tar_slip' panicked at tests/vault_tests.rs:213:
tar-slip: file was written outside the extraction root
test result: FAILED. 0 passed; 1 failed
```

```text
# Copia aislada, reversión del chequeo de keyfile vacío en apply_keyfiles()
$ cargo test --lib empty_keyfile_rejected
thread 'crypto::keyfile::tests::test_empty_keyfile_rejected' panicked at src/crypto/keyfile.rs:245:
assertion failed: apply_keyfiles(b"password", &[Vec::new()]).is_err()
test result: FAILED. 0 passed; 1 failed
```

Restaurado el repo real, los mismos tests pasan:

```text
$ cargo test --test vault_tests
test result: ok. 8 passed; 0 failed

$ cargo test --test keyfile_tests
test result: ok. 6 passed; 0 failed

$ cargo test --lib keyfile
test result: ok. 6 passed; 0 failed
```

### 3.2 Cómo inspeccionar el código vulnerable y el corregido

```bash
# Código vulnerable de las medias (commit de features)
git show 46397c4:src/commands/mod.rs | sed -n '687,690p'   # out_p = parent_dir.join(nombre del manifiesto)
git show 46397c4:src/commands/mod.rs | sed -n '425,432p'   # commit_file_atomic sin chequeo de symlink
git show 46397c4:src/vault/mod.rs    | sed -n '148p;272p'  # Vec::new() sin límite ni Zeroizing
git show 46397c4:ui/app.js           | sed -n '569,578p'   # copia al portapapeles sin limpieza

# Diff del hardening
git show 360d2e2 -- src/commands/mod.rs src/vault/mod.rs src/crypto/keyfile.rs ui/app.js
```

Búsqueda por contenido (`pickaxe`) para confirmar en qué commit entró cada
defensa:

```text
$ git log -S "unpack_in" --oneline -- src/vault/mod.rs
46397c4 feat: add VeraCrypt/Arcanum keyfiles and encrypted vault containers

$ git log -S "Keyfile is empty" --oneline -- src/crypto/keyfile.rs
46397c4 feat: add VeraCrypt/Arcanum keyfiles and encrypted vault containers

$ git log -S "unique_output_path" --oneline -- src/commands/mod.rs
360d2e2 fix(security): harden vault limits, output overwrites and memory hygiene

$ git log -S "MAX_VAULT_PLAINTEXT_SIZE" --oneline -- src/vault/mod.rs
360d2e2 fix(security): harden vault limits, output overwrites and memory hygiene

$ git log -S "scheduleClipboardClear" --oneline -- ui/app.js
360d2e2 fix(security): harden vault limits, output overwrites and memory hygiene
```

### 3.3 Avisos de dependencias: origen exacto

No salen del código nuevo: salen del `Cargo.lock` (dependencias transitivas de
Tauri/GTK). Se consultaron las 531 entradas contra OSV.dev. Ejemplo de
verificación de alcance:

```bash
cargo tree -i glib --target aarch64-apple-darwin   # "nothing to print" -> no se compila en macOS
cargo tree -i unic-ucd-ident                        # urlpattern -> tauri-utils -> tauri
```

Los avisos de `glib`, `zbus`, `zvariant` y `proc-macro-error` son de la build
Linux; `unic-*` aparece en todas las plataformas vía `urlpattern`/Tauri, pero
son avisos de "sin mantenimiento", no vulnerabilidades explotables conocidas.

---

## 4. Hallazgos

| ID | Severidad | CWE | Hallazgo | Estado |
|---|---|---|---|---|
| MX-KF-01 | **Alta** | CWE-22 / CWE-59 | Tar-slip en extracción de bóvedas vía symlink | Corregido |
| MX-KF-02 | **Alta** | CWE-521 / CWE-1188 | Keyfile vacío deriva una clave predecible | Corregido |
| MX-VL-01 | Media | CWE-73 | Sobrescritura silenciosa con nombre controlado por el atacante | Corregido |
| MX-VL-02 | Media | CWE-400 | DoS de memoria al abrir una bóveda maliciosa | Corregido (límite 2 GiB) |
| MX-VL-03 | Baja | CWE-226 | Zeroización incompleta de keyfiles y buffers TAR | Corregido |
| MX-UI-01 | Baja | CWE-226 | Contraseña persistente en el portapapeles | Corregido |
| MX-DEP-01 | Baja | CWE-1104 | Dependencias sin mantenimiento (`unic-*`, `zbus`, `zvariant`, `proc-macro-error`) | Abierto / mitigado |
| MX-DEP-02 | Baja | CWE-1395 | UB en `glib 0.18.5` (solo Linux) | Abierto (Linux) |
| MX-INFO-01 | Info | — | 5 avisos de Semgrep, sin explotabilidad | Sin acción |

---

### MX-KF-01 — Tar-slip en extracción de bóvedas (Alta, corregido)

**Descripción.** `extract_vault_entry` y `extract_all_vault` validaban el
*path* de cada entrada del TAR, pero usaban `Entry::unpack`, que según la propia
documentación de `tar-rs` **no impide escribir fuera del destino**. Una entrada
symlink (`evil -> /tmp/fuera`) seguida de un archivo (`evil/pwned.txt`) permitía
crear el symlink y escribir el archivo a través de él fuera de la carpeta de
extracción.

**Impacto.** Escritura arbitraria de archivos fuera del directorio elegido por
el usuario, con los permisos del proceso. Requiere que la víctima abra una
bóveda manipulada y conozca/su contraseña (el atacante puede proporcionarla),
por lo que es un vector de ingeniería social con impacto de integridad.

**Evidencia.** PoC en `tests/vault_tests.rs`:
`test_vault_extraction_rejects_symlink_tar_slip` (falló antes del fix, pasa
después).

**Remediación aplicada.** Se rechazan entradas que no sean archivo regular o
directorio y se usa `unpack_in`, que canonicaliza el padre y rechaza escribir
fuera del destino. Código: `src/vault/mod.rs` (`is_extractable_entry_type`,
`extract_vault_entry`, `extract_all_vault`).

---

### MX-KF-02 — Keyfile vacío deriva una clave predecible (Alta, corregido)

**Descripción.** `read_keyfile_from_path` aceptaba archivos de 0 bytes y
`apply_keyfiles` los trataba como un pool nulo. Con autenticación "solo
keyfile", la contraseña efectiva resultante era de 64 bytes a cero.

**Impacto.** Cifrado con una clave efectiva conocida; un atacante podría
descifrar el contenedor sin el keyfile real.

**Evidencia.** Test `test_empty_keyfile_rejected` y
`test_empty_keyfile_file_on_disk_is_rejected`.

**Remediación aplicada.** Se devuelve error si el keyfile está vacío, igual que
VeraCrypt (`KeyFileProcess` falla con `totalRead == 0`). Código:
`src/crypto/keyfile.rs`.

---

### MX-VL-01 — Sobrescritura silenciosa con nombre controlado por el atacante (Media, corregido)

**Descripción.** Al descifrar sin `-o`, el destino era
`parent_dir.join(sanitize_filename(manifest.original_filename))`. El nombre
proviene del manifiesto (controlado por quien creó el contenedor) y
`commit_file_atomic` usaba `fs::rename`, que **reemplaza** un archivo existente
en POSIX. En Windows, el fallback `fs::copy` podía seguir un symlink y
sobrescribir su destino.

**Impacto.** Pérdida de datos o sobreescritura de un archivo elegido por el
atacante dentro de la carpeta del contenedor. En Windows, posible escritura
fuera de esa carpeta si existe un symlink plantado.

**Evidencia.** Tests:
`test_decrypt_default_output_does_not_overwrite_existing_file`,
`test_encrypt_default_output_does_not_overwrite_existing_container`,
`test_decrypt_rejects_symlink_output`.

**Remediación aplicada.** Los destinos automáticos usan un sufijo
`nombre (1).ext` si el archivo ya existe; se rechazan destinos que sean
symlinks. Código: `unique_output_path`, `reject_symlink_destination` y
`commit_file_atomic` en `src/commands/mod.rs`.

---

### MX-VL-02 — DoS de memoria al abrir una bóveda maliciosa (Media, corregido)

**Descripción.** El TAR descifrado se acumulaba en un `Vec` sin límite. Un
contenedor manipulado podía declarar/producir un texto plano arbitrariamente
grande y agotar la RAM del proceso.

**Impacto.** Denegación de servicio local al abrir una bóveda no confiable.

**Remediación aplicada.** `MAX_VAULT_PLAINTEXT_SIZE = 2 GiB` y un
`LimitedWriter` que aborta al superar el límite y zeroiza el buffer. La creación
de bóvedas rechaza fuentes por encima del límite antes de empaquetar. Código:
`src/vault/mod.rs`.

**Nota.** Los contenedores `.wraith` individuales siguen usando streaming con
memoria constante; este límite aplica solo a bóvedas `.wvault`.

---

### MX-VL-03 — Zeroización incompleta (Baja, corregido)

**Descripción.** Los bytes leídos de un keyfile se mantenían en un `Vec` sin
limpiar tras la derivación, y los buffers TAR de creación/descifrado no se
zeroizaban en rutas de error tempranas (por ejemplo, fallo de autenticación o
manifiesto que no es de bóveda).

**Remediación aplicada.** Se zeroizan los keyfiles tras `apply_keyfiles`, y los
buffers TAR usan `Zeroizing` desde su creación (`src/crypto/keyfile.rs`,
`src/vault/mod.rs`).

---

### MX-UI-01 — Contraseña persistente en el portapapeles (Baja, corregido)

**Descripción.** El botón de copiar contraseña del modal QR escribía la
contraseña en el portapapeles y no la eliminaba.

**Remediación aplicada.** Tras 30 segundos se lee el portapapeles y, **solo si
sigue conteniendo la contraseña copiada**, se vacía. Código:
`scheduleClipboardClear` en `ui/app.js`.

---

### MX-DEP-01 — Dependencias sin mantenimiento (Baja, abierto)

Detectadas con OSV.dev sobre las 531 dependencias del `Cargo.lock`:

| Crate | Versión | Aviso | Alcance |
|---|---|---|---|
| `unic-char-range` | 0.9.0 | RUSTSEC-2025-0075 | Todas las plataformas (vía `urlpattern` → `tauri-utils`) |
| `unic-common` | 0.9.0 | RUSTSEC-2025-0080 | Todas las plataformas |
| `unic-char-property` | 0.9.0 | RUSTSEC-2025-0081 | Todas las plataformas |
| `unic-ucd-version` | 0.9.0 | RUSTSEC-2025-0098 | Todas las plataformas |
| `unic-ucd-ident` | 0.9.0 | RUSTSEC-2025-0100 | Todas las plataformas |
| `zbus_names` | 4.3.4 | RUSTSEC-2026-0371 | Linux |
| `zvariant` | 5.15.0 | RUSTSEC-2026-0370 | Linux |
| `zvariant_derive` | 5.15.0 | RUSTSEC-2026-0372 | Linux |
| `proc-macro-error` | 1.0.4 | RUSTSEC-2024-0370 | Build, Linux |

Son avisos de **falta de mantenimiento**, no vulnerabilidades explotables
conocidas. Se resuelven actualizando la cadena de Tauri/GTK cuando haya
versiones disponibles. Mitigación recomendada: añadir `cargo audit`/OSV a CI y
revisar en cada actualización de Tauri.

---

### MX-DEP-02 — UB en `glib 0.18.5` (Baja, solo Linux)

`GHSA-wrw7-89jp-8q8g` / `RUSTSEC-2024-0429`: implementaciones incorrectas de
`Iterator`/`DoubleEndedIterator` para `glib::VariantStrIter` (escritura a través
de una referencia inmutable, UB). Corregido en `glib 0.20.0`.

`glib` es una dependencia **solo de Linux** del stack GTK de Tauri: no se
compila en macOS (`cargo tree -i glib --target aarch64-apple-darwin` no muestra
nada) y en Windows Tauri usa WebView2, no GTK. Impacto potencial en la build
Linux; se recomienda subir la cadena GTK/Tauri.

---

### MX-INFO-01 — Semgrep (Info, sin acción)

5 resultados, todos falsos positivos o de bajo riesgo:

- `env::args()` en la CLI (entrada por definición del usuario).
- `current_exe()` para registrar el menú contextual de Windows y los servicios
  de macOS (si el atacante controla el ejecutable, ya ejecuta código).
- `unsafe { setrlimit(RLIMIT_CORE, 0) }` — endurecimiento intencional y
  auditado.
- `temp_dir()` en un test unitario.

No se detectaron secretos hardcodeados.

---

## 5. Controles positivos verificados

- **Keyfiles compatibles con VeraCrypt/Arcanum:** 9 vectores dorados generados
  compilando el código C oficial (`Keyfiles.c` + `Crc.c`), coincidencia byte a
  byte, incluida la frontera 64/128, contraseñas >128 bytes, múltiples
  keyfiles y el tope de 1 MiB (`tests/keyfile_tests.rs`).
- **AES-256-GCM:** nonce por chunk determinista (`prefijo aleatorio de 4 bytes
  || índice de 8 bytes`) bajo una DEK única por contenedor; AAD vincula UUID,
  índice, flag final y longitud.
- **KDF:** Argon2id con parámetros acotados en cabecera (anti-DoS) y HKDF-SHA512
  con separación de dominio para DEK, manifiesto y wrapping PQC.
- **Parser WRAITH:** límites estrictos de longitudes, rechazo de flags no
  canónicos, verificación de orden de chunks, hash SHA-256, rechazo de basura
  final.
- **UI:** sin `innerHTML`, `eval` ni `document.write`; todo el contenido
  dinámico usa `textContent`. CSP `script-src 'self'`.
- **Tauri:** capacidades mínimas (`core:event`, `core:window`, `core:app`).

---

## 6. Limitaciones del análisis

- No se ejecutó Strix por falta de credencial válida; no hubo pentest autónomo.
- No se hizo fuzzing del parser de cabecera/manifiesto/TAR ni análisis formal.
- La interoperabilidad con volúmenes VeraCrypt reales no se probó: solo se
  verificó la derivación de keyfiles, no el montaje de `.tc/.hc/.vc` (que
  MirageX no soporta).
- La GUI no se probó visualmente en esta sesión.
- Los avisos de dependencias reflejan el `Cargo.lock` en la fecha de la
  auditoría.

---

## 7. Recomendaciones

1. Añadir `cargo audit` o consulta OSV a CI (hoy CI solo ejecuta tests).
2. Actualizar la cadena GTK/Tauri para resolver `glib` y las crates `zbus`.
3. Evaluar el refactor de bóvedas a streaming (archivo temporal) para eliminar
   el límite de 2 GiB y reducir el pico de RAM.
4. Añadir fuzzing (`cargo-fuzz`) para `WraithHeader::read_from`,
   `Manifest::decrypt` y el parser TAR de bóvedas.
5. Repetir el pentest con Strix cuando haya una credencial válida y anexar los
   resultados a este informe.

---

**Conclusión:** el código auditado no presenta vulnerabilidades críticas
conocidas tras las correcciones. Los riesgos residuales son de disponibilidad
(límite de memoria, ya acotado), de dependencias transitivas y de higiene
operativa. Las dos vulnerabilidades altas encontradas fueron reproducidas,
corregidas y cubiertas con tests de regresión.
