# MirageX / WRAITH v4 — Security Audit Report

**Audit date:** September 5, 2026
**Project:** MirageX v4.0.1 — Post-Quantum Decoupled Encryption Engine & WRAITH v4 Container
**Scope:** All Rust source (`src/`), integration tests (`tests/`), Tauri configuration, and UI layer (`ui/`)
**Status:** ⚠️ No critical/high-severity vulnerabilities found — 2 medium, 7 low, 4 cosmetic findings

---

## 1. Executive Summary

MirageX implements a hybrid post-quantum envelope (Argon2id + ML-KEM-768/1024 → HKDF-SHA512 → AES-256-GCM) with a streaming authenticated chunk container format (WRAITH v4). The cryptographic design is sound:

- Full domain separation of keys (wrap key / DEK / manifest key via distinct HKDF info strings)
- Deterministic NIST SP 800-38D-style chunk nonces (random 4-byte session prefix + 8-byte big-endian counter) — safe because each container gets a fresh DEK (fresh salt + UUID + shared secret)
- The entire 80-byte header is bound as AAD, so any header bit-flip, suite downgrade, or KDF-parameter tampering fails authentication
- Sequential chunk AAD (`UUID || ChunkIndex || IsFinal || PayloadLen`) blocks reordering, truncation, and bit-flip smuggling
- Parser enforces strict bounds before allocating (exact PQC ciphertext size, wrapped key ≤ 8 KiB, chunk payload ≤ 256 MiB, manifest ≤ 64 KiB), and chunk parsing only runs *after* the envelope is authenticated
- Atomic temp-file commits with `0o600` permissions and secure shredding of the temp file on any failure; unauthenticated trailing bytes are rejected
- UI is XSS-hardened (`textContent` only, strict CSP) and the threat model honestly documents SSD shredding limitations

**Verification performed:**
- `cargo test` — 20/20 tests pass (4 crypto, 10 security, 6 wraith)
- `cargo clippy --all-targets` — no errors; 23 style-level warnings only (auto-deref, `div_ceil`, too-many-args, etc.)

---

## 2. Findings by Severity

### 🔶 MEDIUM

#### M1. Unauthenticated Argon2 DoS (memory/time bomb) via crafted header

| | |
| :--- | :--- |
| **Files** | `src/wraith/header.rs` (lines 14–16), `src/wraith/decryptor.rs` (step 3) |
| **Risk** | Medium — availability / resource exhaustion |

The container header stores Argon2id parameters (`m_cost`, `t_cost`, `p_cost`) and the decryptor derives the password key **before any authenticated check**. The bounds enforced in `WraithHeader::read_from` are extremely permissive:

```rust
pub const MAX_ARGON2_M_COST: u32 = 2 * 1024 * 1024; // 2 GiB
pub const MAX_ARGON2_T_COST: u32 = 1000;
pub const MAX_ARGON2_P_COST: u32 = 64;
```

An attacker can craft a `.wraith` file that forces the victim's machine to run Argon2id with 2 GiB RAM × 1000 iterations × 64 lanes — effectively pinning memory and burning CPU for an unbounded time per file opened, with no password required to trigger it.

**Recommendation:**
- Tighten bounds (e.g., `m ≤ 1 GiB`, `t ≤ 10`, `p ≤ 8`), and/or
- Reject parameter combinations whose estimated work factor exceeds a configured maximum before running the KDF.

---

#### M2. Plaintext ML-KEM decapsulation key not zeroized

| | |
| :--- | :--- |
| **File** | `src/wraith/decryptor.rs` (~line 96) |
| **Risk** | Medium — violates the project's own threat-model claim (memory residue mitigation) |

The decrypted ML-KEM decapsulation key — the most sensitive secret in the decrypt flow — is stored in a plain `Vec<u8>`:

```rust
let decaps_key_bytes = decrypt_aes_gcm(
    &*pqc_wrap_key,
    &wrap_nonce,
    &wrapped_decaps_key,
    &header_bytes,
).map_err(|_| WraithError::ManifestAuthFailed)?;
```

The threat model (§4) claims "Sensitive keys, passwords, and buffers are wrapped in `zeroize::Zeroizing` and wiped on drop", but this key is not. Same applies (lower severity) to `wrapped_decaps_key` in both `encryptor.rs` and `decryptor.rs` (an *encrypted* key, so less critical).

**Recommendation:** wrap the decapsulation key in `Zeroizing<Vec<u8>>` (and zeroize `wrapped_decaps_key` on drop for consistency).

---

### 🔹 LOW

#### L1. Core dumps not disabled
- **Files:** `src/main.rs`, `Cargo.toml`
- **Issue:** The threat model promises core-dump mitigation, but nothing sets `RLIMIT_CORE = 0`. Combined with `panic = "abort"` in the release profile, a crash can leave key material in a core dump on macOS/Linux.
- **Fix:** Set the core-size rlimit to 0 at process startup (Unix), or document the residual risk.

#### L2. CLI password visible in process list; partial zeroization
- **Files:** `src/cli.rs` (`get_password`, `handle_encrypt`, `handle_decrypt`)
- **Issue:** `-p/--password` places the password in the process list (documented in the help text, but still discouraged). Also, the local `password` String in `handle_encrypt`/`handle_decrypt` is not zeroized after the call — the command function zeroizes its own copy, but the caller's copy persists until the function returns.
- **Fix:** Prefer `--password-stdin` / interactive prompt; zeroize the local String after the call.

#### L3. `permissions/default.json` is dead configuration
- **Files:** `permissions/default.json`, `tauri.conf.json`
- **Issue:** The capabilities in `tauri.conf.json` do not reference this permission set, and custom commands are not gated by the Tauri ACL anyway. The "least-privilege capability" comment is therefore misleading.
- **Fix:** Either wire the permission set into the capability or remove the file.

#### L4. Read errors silently swallowed in `inspect.rs`
- **File:** `src/wraith/inspect.rs`
- **Issue:** `reader.read_exact(&mut u32_buf).unwrap_or_default()` and `let _ = reader.read_exact(...)` ignore EOF/read failures (display-only path, not exploitable, but poor hygiene).
- **Fix:** Propagate errors instead of defaulting.

#### L5. Shred failures silently ignored after encrypt/decrypt
- **File:** `src/commands/mod.rs` (`encrypt_file_cmd`, `decrypt_file_cmd`)
- **Issue:** `let _ = storage.shred_file_with_mode(...)` — if secure deletion of the source fails, the user is still told the operation succeeded.
- **Fix:** Surface a warning (or error) when `shred_source` fails.

#### L6. Silent overwrite of existing output files
- **File:** `src/commands/mod.rs` (`commit_file_atomic`)
- **Issue:** `fs::rename` atomically replaces an existing destination on Unix without confirmation; on Windows it fails instead. Inconsistent and potentially destructive UX.
- **Fix:** Check for destination existence and confirm, or document the behavior.

#### L7. Version inconsistencies
- **Files:** `Cargo.toml` (4.0.1) vs `tauri.conf.json` (4.0.0) vs CLI help text (v4.0.0)
- **Fix:** Align all version strings.

#### L8. Dead code compiled into the library
- **File:** `src/crypto/test_kem.rs`
- **Issue:** `pub fn test_pqc()` is never called but is compiled into the lib crate.
- **Fix:** Remove the file or move it into `tests/`.

---

### ✨ COSMETIC

- **Decrypt progress percentage is fake:** hard-coded `50.0` until the final chunk (`decryptor.rs`), then `100.0`. Telemetry shown to users is misleading.
- **Modulo bias in JS password generator** (`ui/app.js`): `charset[array[i] % charset.length]` — negligible bias with a 94-char charset, but rejection sampling would be cleaner.
- **Clippy style warnings:** 23 warnings across the crate (auto-deref, `div_ceil` reimplementation, `assert_eq!` with literals, too-many-args on `encrypt_file_cmd`). No correctness warnings.
- **`chunk_size` in the header is not validated at decrypt time** (`header.rs` `read_from`) — not exploitable because the header is authenticated before chunk parsing, but inconsistent with the encrypt-side validation.

---

## 3. Strengths (keep these)

1. **Hybrid PQC envelope with domain separation** — wrap key, DEK, and manifest key derived via distinct HKDF info strings; header bound as AAD for the wrap.
2. **Deterministic chunk nonces** — unique per container because the DEK is unique per container (fresh salt + UUID + shared secret).
3. **Strict sequential chunk AAD** — reorder, truncation, and bit-flips all fail per-chunk authentication.
4. **Allocation-bomb resistance** — exact-size PQC ciphertext check, bounded wrapped-key/manifest lengths; chunk parsing happens only after envelope authentication.
5. **Atomic temp-file workflow** — `0o600` exclusive creation, shred-on-failure, trailing-garbage rejection, constant-time hash comparison (`subtle`).
6. **XSS-hardened UI** — `textContent` only for dynamic content, restrictive CSP, no remote resources.
7. **Honest documentation** — SSD/NVMe shredding is correctly described as best-effort; upstream `ml-kem` audit status is disclosed.

---

## 4. Suggested Next Steps

1. Fix the two medium findings (Argon2 parameter bounds + decapsulation-key zeroization).
2. Disable core dumps at startup.
3. Add a fuzz harness (`cargo-fuzz`) targeting `decrypt_stream` and `inspect_container` for malformed-input hardening.
4. Align version strings and remove dead code / dead config.
5. Consider an independent third-party crypto review of the WRAITH v4 format specification (as noted in the project roadmap).

---

*Audited against: `Cargo.toml` v4.0.1, release profile `panic="abort"`, `overflow-checks=true`.*