// MirageX Controller & Secure IPC Bridge
// Zero External Dependencies // XSS-Hardened DOM

// Helper to invoke Tauri IPC command
async function invokeBackend(cmd, args = {}) {
  const tauri = window.__TAURI__;
  if (tauri) {
    if (tauri.core && typeof tauri.core.invoke === 'function') {
      return await tauri.core.invoke(cmd, args);
    }
    if (typeof tauri.invoke === 'function') {
      return await tauri.invoke(cmd, args);
    }
  }
  console.warn(`[MirageX Web Mode] Simulating IPC: ${cmd}`, args);
  if (cmd === 'run_benchmark_cmd') {
    return {
      miragex_768_encap_ops_sec: 9760.9,
      miragex_1024_encap_ops_sec: 7728.9,
      argon2id_time_ms: 80,
      aes_256_gcm_throughput_mb_s: 210.7
    };
  }
  throw new Error(`Tauri IPC no disponible. Ejecuta el binario MirageX.`);
}

// State
let selectedEncryptPath = null;
let selectedDecryptPath = null;
let selectedInspectPath = null;
let selectedShredPath = null;

let selectedEncryptKeyfilePath = null;
let selectedDecryptKeyfilePath = null;
let selectedWatchKeyfilePath = null;
let selectedVaultSources = [];
let selectedVaultCreateKeyfilePath = null;
let selectedVaultOpenPath = null;
let selectedVaultOpenKeyfilePath = null;
let currentVaultSession = null;
let vaultCachedEntries = [];
let collectedEntropyBytes = [];
let clipboardClearTimer = null;

// DOM Initialization
document.addEventListener('DOMContentLoaded', () => {
  setupLanguageLogic();
  setupTabs();
  setupPasswordLogic();
  setupQrModalLogic();
  setupKeyfileLogic();
  setupVaultLogic();
  setupDropzones();
  setupActions();
  setupTauriNativeEvents();
  setupUpdaterLogic();
  setupExternalLinks();
  checkInitialFilePayload();
  setupEncryptBackupMode();
  initWatcherPanel();
  initBetaLabs();
});

// 1. Navigation Tabs
function setupTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  const contents = document.querySelectorAll('.tab-content');

  function activateTab(tabName) {
    const targetTab = document.querySelector(`.nav-tab[data-tab="${tabName}"]`);
    const targetContent = document.getElementById(`tab-${tabName}`);
    if (targetTab && targetContent) {
      tabs.forEach(t => t.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));
      targetTab.classList.add('active');
      targetContent.classList.add('active');
      const workspace = document.querySelector('.hud-workspace');
      if (workspace) workspace.scrollTop = 0;
    }
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      activateTab(tab.dataset.tab);
    });
  });

  const btnQuickGuide = document.getElementById('btn-quick-guide');
  if (btnQuickGuide) {
    btnQuickGuide.addEventListener('click', () => {
      activateTab('guide');
    });
  }

  document.querySelectorAll('.btn-guide-pill, .btn-case-cta').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.goto;
      if (target) activateTab(target);
    });
  });

  document.querySelectorAll('input[name="pqc-suite"]').forEach(radio => {
    radio.addEventListener('change', () => {
      document.querySelectorAll('.radio-card').forEach(c => c.classList.remove('active'));
      radio.closest('.radio-card').classList.add('active');
    });
  });
}

// 1.1 External Links Handler (Cross-Platform Browser Launcher)
function setupExternalLinks() {
  document.addEventListener('click', async (e) => {
    const linkEl = e.target.closest('.external-link');
    if (!linkEl) return;
    e.preventDefault();
    const url = linkEl.dataset.url || linkEl.getAttribute('href');
    if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
      try {
        await invokeBackend('open_external_url_cmd', { url });
      } catch (err) {
        console.warn('Fallback al abrir navegador nativo:', err);
        window.open(url, '_blank');
      }
    }
  });
}

// 2. Native Tauri Drag & Drop Listener
function setupTauriNativeEvents() {
  const tauri = window.__TAURI__;
  let listen = null;
  if (tauri) {
    if (tauri.event && typeof tauri.event.listen === 'function') {
      listen = tauri.event.listen;
    } else if (tauri.core && typeof tauri.core.listen === 'function') {
      listen = tauri.core.listen;
    } else if (typeof tauri.listen === 'function') {
      listen = tauri.listen;
    }
  }

  if (listen) {
    listen('tauri://drag-drop', (event) => {
      let paths = [];
      if (event.payload && Array.isArray(event.payload.paths)) {
        paths = event.payload.paths;
      } else if (Array.isArray(event.payload)) {
        paths = event.payload;
      }

      if (paths.length > 0) {
        const fullPath = paths[0];
        const fileName = fullPath.split('/').pop() || fullPath.split('\\').pop() || fullPath;
        const activeTab = document.querySelector('.nav-tab.active')?.dataset?.tab || 'encrypt';

        if (activeTab === 'encrypt') {
          selectedEncryptPath = fullPath;
          document.getElementById('meta-encrypt-name').textContent = fileName;
          document.getElementById('meta-encrypt-path').textContent = fullPath;
          document.getElementById('meta-encrypt-size').textContent = 'Ruta absoluta detectada por macOS';
          document.getElementById('encrypt-file-meta').style.display = 'flex';
          showToast(`Archivo seleccionado: ${fileName}`, 'success');
        } else if (activeTab === 'decrypt') {
          selectedDecryptPath = fullPath;
          document.getElementById('meta-decrypt-name').textContent = fileName;
          document.getElementById('meta-decrypt-path').textContent = fullPath;
          document.getElementById('decrypt-file-meta').style.display = 'flex';
          showToast(`Contenedor seleccionado: ${fileName}`, 'success');
        } else if (activeTab === 'inspect') {
          selectedInspectPath = fullPath;
          runInspection(fullPath);
        } else if (activeTab === 'shred') {
          selectedShredPath = fullPath;
          document.getElementById('shred-file-title').textContent = `Seleccionado para destruir: ${fileName}`;
          showToast(`Archivo listo para triturar: ${fileName}`, 'info');
        }
      }
    });

    listen('tauri://drag-over', () => {
      document.querySelectorAll('.dropzone').forEach(d => d.classList.add('dragover'));
    });

    listen('tauri://drag-leave', () => {
      document.querySelectorAll('.dropzone').forEach(d => d.classList.remove('dragover'));
    });

    listen('open-file-payload', (event) => {
      const payload = event.payload;
      if (payload && payload.path) {
        handleIncomingFile(payload.path, payload.name, payload.size, payload.action);
      }
    });
  }
}

// 3. Dropzones with Native Dialog Pickers
function setupDropzones() {
  const encDropzone = document.getElementById('encrypt-dropzone');
  encDropzone.addEventListener('click', async () => {
    try {
      const fileInfo = await invokeBackend('select_file_dialog');
      if (fileInfo) {
        selectedEncryptPath = fileInfo.path;
        document.getElementById('meta-encrypt-name').textContent = fileInfo.name;
        document.getElementById('meta-encrypt-path').textContent = fileInfo.path;
        document.getElementById('meta-encrypt-size').textContent = formatBytes(fileInfo.size);
        updateEncryptOutputPreview();
        document.getElementById('encrypt-file-meta').style.display = 'flex';
        showToast(`Archivo cargado: ${fileInfo.name}`, 'success');
      }
    } catch (e) {
      console.error(e);
    }
  });

  const decDropzone = document.getElementById('decrypt-dropzone');
  decDropzone.addEventListener('click', async () => {
    try {
      const fileInfo = await invokeBackend('select_wraith_dialog');
      if (fileInfo) {
        selectedDecryptPath = fileInfo.path;
        document.getElementById('meta-decrypt-name').textContent = fileInfo.name;
        document.getElementById('meta-decrypt-path').textContent = fileInfo.path;
        document.getElementById('decrypt-file-meta').style.display = 'flex';
        checkDecryptManifestNotice(fileInfo.path);
        showToast(`Contenedor cargado: ${fileInfo.name}`, 'success');
      }
    } catch (e) {
      console.error(e);
    }
  });

  const inspDropzone = document.getElementById('inspect-dropzone');
  inspDropzone.addEventListener('click', async () => {
    try {
      const fileInfo = await invokeBackend('select_wraith_dialog');
      if (fileInfo) {
        selectedInspectPath = fileInfo.path;
        runInspection(fileInfo.path);
      }
    } catch (e) {
      console.error(e);
    }
  });

  const shredDropzone = document.getElementById('shred-dropzone');
  shredDropzone.addEventListener('click', async () => {
    try {
      const fileInfo = await invokeBackend('select_file_dialog');
      if (fileInfo) {
        selectedShredPath = fileInfo.path;
        document.getElementById('shred-file-title').textContent = `Seleccionado: ${fileInfo.name}`;
        showToast(`Archivo listo para triturar: ${fileInfo.name}`, 'info');
      }
    } catch (e) {
      console.error(e);
    }
  });

  const vaultCreateDrop = document.getElementById('vault-create-dropzone');
  if (vaultCreateDrop) {
    vaultCreateDrop.addEventListener('click', async () => {
      try {
        const files = await invokeBackend('select_vault_sources_dialog');
        if (files && files.length > 0) {
          addVaultSources(files);
        }
      } catch (e) {
        console.error(e);
      }
    });
  }

  const vaultOpenDrop = document.getElementById('vault-open-dropzone');
  if (vaultOpenDrop) {
    vaultOpenDrop.addEventListener('click', async () => {
      try {
        const fileInfo = await invokeBackend('select_vault_dialog');
        if (fileInfo) {
          selectedVaultOpenPath = fileInfo.path;
          document.getElementById('meta-vault-open-name').textContent = fileInfo.name;
          document.getElementById('meta-vault-open-path').textContent = fileInfo.path;
          document.getElementById('vault-open-meta').style.display = 'flex';
          showToast(`Bóveda cargada: ${fileInfo.name}`, 'info');
        }
      } catch (e) {
        console.error(e);
      }
    });
  }
}

// 4. Password Logic
function setupPasswordLogic() {
  const passInput = document.getElementById('encrypt-password');
  const meterBar = document.getElementById('pass-meter-bar');
  const meterText = document.getElementById('pass-meter-text');
  const btnGen = document.getElementById('btn-gen-pass');
  const btnToggle = document.getElementById('btn-toggle-encrypt-pass');
  const btnToggleDec = document.getElementById('btn-toggle-decrypt-pass');

  passInput.addEventListener('input', () => {
    const pwd = passInput.value;
    const score = evaluatePasswordEntropy(pwd);
    meterBar.style.width = `${score.pct}%`;
    meterBar.style.background = score.color;
    meterText.textContent = `Entropía: ${score.label} (~${score.bits} bits)`;
  });

  btnGen.addEventListener('click', () => {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
    let generated = '';
    const array = new Uint8Array(24);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < 24; i++) {
      generated += charset[array[i] % charset.length];
    }
    passInput.value = generated;
    passInput.dispatchEvent(new Event('input'));
    showToast('Contraseña cuánticamente robusta generada.', 'success');
  });

  btnToggle.addEventListener('click', () => {
    passInput.type = passInput.type === 'password' ? 'text' : 'password';
  });

  btnToggleDec.addEventListener('click', () => {
    const decInput = document.getElementById('decrypt-password');
    decInput.type = decInput.type === 'password' ? 'text' : 'password';
  });
}

function evaluatePasswordEntropy(pwd) {
  if (!pwd) return { pct: 0, color: '#ef4444', label: 'Esperando entrada...', bits: 0 };
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;

  const bits = Math.round(pwd.length * (Math.log2(pool || 1)));
  if (bits < 40) return { pct: 25, color: '#ef4444', label: 'Muy Débil', bits };
  if (bits < 64) return { pct: 50, color: '#fbbf24', label: 'Media', bits };
  if (bits < 90) return { pct: 75, color: '#c084fc', label: 'Robusta', bits };
  return { pct: 100, color: '#10b981', label: 'Criptográficamente Imbatible', bits };
}

// 5. Action Handlers (XSS-Safe DOM Manipulation)
function setupActions() {
  // Shred Options toggles
  const shredSourceChk = document.getElementById('shred-source-chk');
  const encryptShredOpts = document.getElementById('encrypt-shred-options');
  if (shredSourceChk && encryptShredOpts) {
    shredSourceChk.addEventListener('change', () => {
      encryptShredOpts.style.display = shredSourceChk.checked ? 'block' : 'none';
    });
  }

  const shredContainerChk = document.getElementById('shred-container-chk');
  const decryptShredOpts = document.getElementById('decrypt-shred-options');
  if (shredContainerChk && decryptShredOpts) {
    shredContainerChk.addEventListener('change', () => {
      decryptShredOpts.style.display = shredContainerChk.checked ? 'block' : 'none';
    });
  }

  const nameFuzzingChk = document.getElementById('encrypt-name-fuzzing-chk');
  if (nameFuzzingChk) {
    nameFuzzingChk.addEventListener('change', updateEncryptOutputPreview);
  }

  // Encrypt Button
  document.getElementById('btn-start-encrypt').addEventListener('click', async () => {
    const isBackupMode = document.getElementById('toggle-encrypt-backup-mode')?.checked;
    if (isBackupMode) {
      const srcFolder = document.getElementById('backup-main-src-input')?.value.trim();
      const dstFolder = document.getElementById('backup-main-dst-input')?.value.trim();
      if (!srcFolder || !dstFolder) {
        showToast('Selecciona la carpeta origen y el directorio destino para el respaldo.', 'warning');
        return;
      }
      const password = document.getElementById('encrypt-password').value;
      if (!password && !selectedEncryptKeyfilePath) {
        showToast('Introduce una contraseña o keyfile para proteger el respaldo.', 'error');
        return;
      }
      const suiteVal = document.querySelector('input[name="pqc-suite"]:checked')?.value === '2' ? '1024' : '768';

      const telemetryCard = document.getElementById('encrypt-telemetry');
      const progressFill = document.getElementById('encrypt-progress-fill');
      telemetryCard.style.display = 'block';
      progressFill.style.width = '30%';

      try {
        const res = await invokeBackend('create_backup_archive_cmd', {
          sourcePath: srcFolder,
          destPath: dstFolder,
          password: password,
          keyfilePaths: selectedEncryptKeyfilePath ? [selectedEncryptKeyfilePath] : [],
          suite: suiteVal,
        });

        progressFill.style.width = '100%';
        document.getElementById('encrypt-speed').textContent = `${res.total_files} archivos (${formatBytes(res.total_bytes)})`;
        showToast(`¡Respaldo criptográfico completado! Creado: ${res.manifest_file}`, 'success');
      } catch (err) {
        showToast(`Error al generar respaldo: ${err}`, 'error');
        progressFill.style.width = '0%';
      }
      return;
    }

    if (!selectedEncryptPath) {
      showToast('Por favor selecciona un archivo a cifrar.', 'error');
      return;
    }
    const password = document.getElementById('encrypt-password').value;
    if (!password && !selectedEncryptKeyfilePath) {
      showToast('Introduce una contraseña o selecciona un keyfile para el cifrado.', 'error');
      return;
    }

    const suiteId = parseInt(document.querySelector('input[name="pqc-suite"]:checked').value);
    const chunkSizeMb = parseInt(document.getElementById('chunk-size-select').value);
    const shredSource = document.getElementById('shred-source-chk').checked;
    const shredMode = document.getElementById('encrypt-shred-media').value;
    const shredPasses = parseInt(document.getElementById('encrypt-shred-passes').value);
    const isNameFuzzing = document.getElementById('encrypt-name-fuzzing-chk') ? document.getElementById('encrypt-name-fuzzing-chk').checked : true;

    const telemetryCard = document.getElementById('encrypt-telemetry');
    const progressFill = document.getElementById('encrypt-progress-fill');
    telemetryCard.style.display = 'block';
    progressFill.style.width = '30%';

    try {
      const res = await invokeBackend('encrypt_file_cmd', {
        inputPath: selectedEncryptPath,
        outputPath: null,
        password: password,
        keyfilePath: selectedEncryptKeyfilePath || null,
        suiteId: suiteId,
        chunkSizeMb: chunkSizeMb,
        shredSource: shredSource,
        shredMode: shredSource ? shredMode : null,
        shredPasses: shredSource ? shredPasses : null,
        nameFuzzing: isNameFuzzing,
      });

      progressFill.style.width = '100%';
      document.getElementById('encrypt-speed').textContent = `Listo en ${res.elapsed_ms} ms`;
      const outName = res.output_path.split('/').pop().split('\\').pop();
      if (res.name_fuzzed) {
        showToast(`¡Cifrado con Name Fuzzing exitoso! Contenedor anonimizado: ${outName}`, 'success');
      } else {
        showToast(`¡Cifrado MirageX exitoso! Creado: ${outName}`, 'success');
      }
    } catch (err) {
      showToast(`Error al cifrar: ${err}`, 'error');
      progressFill.style.width = '0%';
    }
  });

  // Decrypt Button (XSS Safe - Zero innerHTML)
  document.getElementById('btn-start-decrypt').addEventListener('click', async () => {
    if (!selectedDecryptPath) {
      showToast('Por favor selecciona un contenedor .wraith.', 'error');
      return;
    }
    const password = document.getElementById('decrypt-password').value;
    if (!password && !selectedDecryptKeyfilePath) {
      showToast('Introduce la contraseña o selecciona el keyfile para desencapsular.', 'error');
      return;
    }

    const shredContainer = document.getElementById('shred-container-chk').checked;
    const shredMode = document.getElementById('decrypt-shred-media').value;
    const shredPasses = parseInt(document.getElementById('decrypt-shred-passes').value);

    const resultBox = document.getElementById('decrypt-result-box');
    resultBox.textContent = ''; // Clear securely

    try {
      const res = await invokeBackend('decrypt_file_cmd', {
        inputPath: selectedDecryptPath,
        outputPath: null,
        password: password,
        keyfilePath: selectedDecryptKeyfilePath || null,
        shredSource: shredContainer,
        shredMode: shredContainer ? shredMode : null,
        shredPasses: shredContainer ? shredPasses : null,
      });

      // Secure DOM Construction
      const container = document.createElement('div');
      container.style.display = 'flex';
      container.style.flexDirection = 'column';
      container.style.gap = '10px';
      container.style.fontFamily = 'var(--font-mono)';
      container.style.fontSize = '11px';

      const title = document.createElement('div');
      title.style.color = 'var(--green)';
      title.style.fontWeight = 'bold';
      title.style.fontSize = '13px';
      title.textContent = '✅ AUTENTICIDAD & INTEGRIDAD MIRAGEX VERIFICADAS';
      container.appendChild(title);

      const addRow = (label, value, valueColor = '#fff') => {
        const row = document.createElement('div');
        const lbl = document.createElement('span');
        lbl.style.color = 'var(--text-secondary)';
        lbl.textContent = `${label}: `;
        const val = document.createElement('span');
        val.style.color = valueColor;
        val.style.wordBreak = 'break-all';
        val.textContent = value;
        row.appendChild(lbl);
        row.appendChild(val);
        container.appendChild(row);
      };

      addRow('Archivo Restaurado', res.original_filename);
      addRow('Destino', res.output_path, 'var(--purple-light)');
      addRow('Tamaño', formatBytes(res.restored_size));
      addRow('Hash SHA-256', res.sha256_hex, 'var(--yellow)');
      addRow('Tiempo de cómputo', `${res.elapsed_ms} ms`);

      resultBox.appendChild(container);
      showToast('Contenedor restaurado con éxito.', 'success');
    } catch (err) {
      const errDiv = document.createElement('div');
      errDiv.style.color = 'var(--red)';
      errDiv.style.fontFamily = 'var(--font-mono)';
      errDiv.style.fontSize = '12px';
      errDiv.style.textAlign = 'center';
      errDiv.textContent = `❌ Fallo de autenticación: Contraseña incorrecta o datos corruptos (${err})`;
      resultBox.appendChild(errDiv);
      showToast(`Error al descifrar: ${err}`, 'error');
    }
  });

  // Benchmark Button
  document.getElementById('btn-run-bench').addEventListener('click', async () => {
    const btn = document.getElementById('btn-run-bench');
    btn.disabled = true;
    btn.textContent = '⏳ Evaluando algoritmo MirageX...';

    try {
      const bench = await invokeBackend('run_benchmark_cmd');
      document.getElementById('bench-768').textContent = `${bench.miragex_768_encap_ops_sec.toFixed(1)} ops/s`;
      document.getElementById('bench-1024').textContent = `${bench.miragex_1024_encap_ops_sec.toFixed(1)} ops/s`;
      document.getElementById('bench-argon').textContent = `${bench.argon2id_time_ms} ms`;
      document.getElementById('bench-aes').textContent = `${bench.aes_256_gcm_throughput_mb_s.toFixed(1)} MB/s`;
      showToast('Benchmark de MirageX completado con éxito.', 'success');
    } catch (err) {
      showToast(`Error en benchmark: ${err}`, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = '⚡ Ejecutar Test de Estrés';
    }
  });

  // Shredder Button (Supporting SSD Wear-Leveling Mitigation & HDD Physical Multi-Pass)
  document.getElementById('btn-execute-shred').addEventListener('click', async () => {
    if (!selectedShredPath) {
      showToast('Selecciona un archivo para triturar.', 'error');
      return;
    }
    const passes = parseInt(document.getElementById('shred-passes-select').value);
    const mediaMode = document.getElementById('shred-media-select').value;
    const modeLabel = mediaMode === 'ssd' ? 'SSD/NVMe (Mitigación FTL Wear-Leveling)' : 'HDD (Sobrescritura Física)';

    if (!confirm(`¿Deseas ejecutar el borrado seguro de '${selectedShredPath}' en modo ${modeLabel} con ${passes} pasadas?\n\nNota técnica: En medios HDD se efectúa sobrescritura magnética física directa; en unidades SSD/NVMe con wear-leveling se aplica una secuencia de alta entropía anti-deduplicación con ofuscación de metadatos.`)) {
      return;
    }

    try {
      const msg = await invokeBackend('shred_file_cmd', {
        inputPath: selectedShredPath,
        passes: passes,
        mode: mediaMode,
      });
      showToast(msg, 'success');
      selectedShredPath = null;
      document.getElementById('shred-file-title').textContent = `Archivo procesado con éxito (${modeLabel}).`;
    } catch (err) {
      showToast(`Fallo de destrucción: ${err}`, 'error');
    }
  });
}

// 6. Inspection Logic (XSS-Safe)
async function runInspection(path) {
  const inspectionResults = document.getElementById('inspection-results');
  try {
    const info = await invokeBackend('inspect_container_cmd', { inputPath: path });
    document.getElementById('insp-magic').textContent = `${info.magic} v${info.version}`;
    document.getElementById('insp-suite').textContent = info.suite_name;
    document.getElementById('insp-chunk-size').textContent = info.legacy_project_mirage ? 'Monolítico (Legacy)' : `${info.chunk_size_mb} MiB (${info.chunk_size_bytes} B)`;
    document.getElementById('insp-pqc-size').textContent = info.is_pqc ? `${info.pqc_ciphertext_size} Bytes (ML-KEM)` : '0 Bytes (Criptografía Clásica)';
    
    document.getElementById('insp-raw-json').textContent = JSON.stringify(info, null, 2);
    inspectionResults.style.display = 'block';

    if (info.legacy_project_mirage) {
      showToast('⚠️ Detectado contenedor de la versión anterior (Project Mirage v2/v1).', 'info');
    } else {
      showToast('✨ Contenedor MirageX v4 Post-Cuántico inspeccionado.', 'success');
    }
  } catch (err) {
    showToast(`Error de inspección: ${err}`, 'error');
  }
}

// 7. QR Code Password Sharing & Shoulder-Surfing Protection
let qrTimerInterval = null;
let currentQrPassword = '';
let qrRevealed = false;

function setupQrModalLogic() {
  const btnShareEnc = document.getElementById('btn-share-qr-encrypt');
  const btnShareDec = document.getElementById('btn-share-qr-decrypt');
  const btnCloseModal = document.getElementById('btn-close-qr-modal');
  const modalOverlay = document.getElementById('qr-modal-overlay');
  const btnToggleReveal = document.getElementById('btn-toggle-qr-reveal');
  const btnCopyPass = document.getElementById('btn-copy-qr-pass');

  if (btnShareEnc) {
    btnShareEnc.addEventListener('click', () => {
      const pass = document.getElementById('encrypt-password').value;
      openQrModal(pass, 'Contraseña de Cifrado');
    });
  }

  if (btnShareDec) {
    btnShareDec.addEventListener('click', () => {
      const pass = document.getElementById('decrypt-password').value;
      openQrModal(pass, 'Contraseña de Descifrado');
    });
  }

  if (btnCloseModal) {
    btnCloseModal.addEventListener('click', closeQrModal);
  }

  if (modalOverlay) {
    modalOverlay.addEventListener('click', (e) => {
      if (e.target === modalOverlay) closeQrModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeQrModal();
  });

  if (btnToggleReveal) {
    btnToggleReveal.addEventListener('click', () => {
      qrRevealed = !qrRevealed;
      const passText = document.getElementById('qr-password-text');
      if (qrRevealed) {
        passText.textContent = currentQrPassword;
      } else {
        passText.textContent = '•'.repeat(Math.min(currentQrPassword.length, 24));
      }
    });
  }

  if (btnCopyPass) {
    btnCopyPass.addEventListener('click', async () => {
      if (!currentQrPassword) return;
      try {
        await navigator.clipboard.writeText(currentQrPassword);
        scheduleClipboardClear(currentQrPassword);
        showToast('Contraseña copiada. Se borrará del portapapeles en 30 s.', 'success');
      } catch (e) {
        showToast('No se pudo acceder al portapapeles.', 'error');
      }
    });
  }

  // Context menu setup button in header
  const btnContextMenu = document.getElementById('btn-setup-context-menu');
  if (btnContextMenu) {
    btnContextMenu.addEventListener('click', async () => {
      try {
        const res = await invokeBackend('setup_context_menu_cmd');
        showToast(res || 'Menú contextual configurado exitosamente.', 'success');
      } catch (err) {
        showToast(`Error al configurar menú contextual: ${err}`, 'error');
      }
    });
  }
}

function openQrModal(password, title) {
  if (!password || password.trim() === '') {
    showToast('Introduce o genera una contraseña primero para generar el código QR.', 'error');
    return;
  }

  currentQrPassword = password;
  qrRevealed = false;

  const modal = document.getElementById('qr-modal-overlay');
  const canvas = document.getElementById('qr-code-canvas');
  const passText = document.getElementById('qr-password-text');
  const timerFill = document.getElementById('qr-timer-fill');
  const timerLabel = document.getElementById('qr-timer-label');

  passText.textContent = '•'.repeat(Math.min(password.length, 24));

  if (window.QRCodeGenerator && typeof window.QRCodeGenerator.generate === 'function') {
    window.QRCodeGenerator.generate(password, canvas, {
      size: 220,
      margin: 3,
      colorDark: '#0a0714',
      colorLight: '#ffffff'
    });
  }

  // 30s auto-close security countdown
  let timeLeft = 30;
  if (qrTimerInterval) clearInterval(qrTimerInterval);
  timerFill.style.width = '100%';
  timerLabel.textContent = `Auto-cierre de seguridad en ${timeLeft}s`;

  qrTimerInterval = setInterval(() => {
    timeLeft -= 1;
    const pct = Math.max(0, (timeLeft / 30) * 100);
    timerFill.style.width = `${pct}%`;
    timerLabel.textContent = `Auto-cierre de seguridad en ${timeLeft}s`;
    if (timeLeft <= 0) {
      closeQrModal();
      showToast('Código QR cerrado automáticamente por seguridad.', 'info');
    }
  }, 1000);

  modal.style.display = 'flex';
}

function closeQrModal() {
  const modal = document.getElementById('qr-modal-overlay');
  if (modal) modal.style.display = 'none';
  if (qrTimerInterval) {
    clearInterval(qrTimerInterval);
    qrTimerInterval = null;
  }
  currentQrPassword = '';
  qrRevealed = false;
}

// Clears the clipboard after 30 s, but only if it still contains the copied
// password (never wipes unrelated clipboard content the user copied later).
function scheduleClipboardClear(password) {
  if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
  clipboardClearTimer = setTimeout(async () => {
    clipboardClearTimer = null;
    try {
      const current = await navigator.clipboard.readText();
      if (current === password) {
        await navigator.clipboard.writeText('');
        showToast('Contraseña eliminada del portapapeles.', 'info');
      }
    } catch (e) {
      // Clipboard read may be denied; do not clear blindly.
      console.debug('Clipboard auto-clear skipped:', e);
    }
  }, 30000);
}

// 8. OS Context Menu & Incoming File Payload Handler
async function checkInitialFilePayload() {
  try {
    const payload = await invokeBackend('get_initial_file_cmd');
    if (payload && payload.path) {
      handleIncomingFile(payload.path, payload.name, payload.size, payload.action);
    }
  } catch (e) {
    console.debug('No initial file payload:', e);
  }
}

function handleIncomingFile(fullPath, fileName, fileSize, action) {
  fileName = fileName || fullPath.split('/').pop() || fullPath.split('\\').pop() || fullPath;
  const isWraith = fullPath.toLowerCase().endsWith('.wraith');

  if (action === 'decrypt' || (isWraith && action !== 'encrypt')) {
    // Switch to Decrypt tab
    document.querySelector('.nav-tab[data-tab="decrypt"]')?.click();
    selectedDecryptPath = fullPath;
    document.getElementById('meta-decrypt-name').textContent = fileName;
    document.getElementById('meta-decrypt-path').textContent = fullPath;
    document.getElementById('decrypt-file-meta').style.display = 'flex';
    checkDecryptManifestNotice(fullPath);
    document.getElementById('decrypt-password').focus();
    showToast(`Contenedor cargado desde menú contextual: ${fileName}`, 'success');
  } else {
    // Switch to Encrypt tab
    document.querySelector('.nav-tab[data-tab="encrypt"]')?.click();
    selectedEncryptPath = fullPath;
    document.getElementById('meta-encrypt-name').textContent = fileName;
    document.getElementById('meta-encrypt-path').textContent = fullPath;
    document.getElementById('meta-encrypt-size').textContent = fileSize ? formatBytes(fileSize) : 'Detectado por menú contextual';
    updateEncryptOutputPreview();
    document.getElementById('encrypt-file-meta').style.display = 'flex';
    document.getElementById('encrypt-password').focus();
    showToast(`Archivo listo para cifrar desde menú contextual: ${fileName}`, 'success');
  }
}

function updateEncryptOutputPreview() {
  const preview = document.getElementById('meta-encrypt-out-preview');
  if (!preview) return;
  const isFuzzing = document.getElementById('encrypt-name-fuzzing-chk')?.checked;
  if (!selectedEncryptPath) {
    preview.textContent = isFuzzing ? '[sha256].wraith (Name Fuzzing Activo)' : 'nombre_archivo.wraith';
    preview.style.color = isFuzzing ? 'var(--velvet-pink)' : 'var(--text-secondary)';
    return;
  }
  const name = selectedEncryptPath.split('/').pop().split('\\').pop();
  if (isFuzzing) {
    preview.textContent = `[sha256].wraith (Anonimizado // Cero metadatos)`;
    preview.style.color = 'var(--velvet-pink)';
  } else {
    preview.textContent = `${name}.wraith (Nombre legible sin anonimizar)`;
    preview.style.color = 'var(--text-secondary)';
  }
}

// Utilities
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = msg; // Text only, never innerHTML
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 9. Keyfile Logic & Interactive Generator (VeraCrypt/Arcanum Compatible)
let activeKeyfileTarget = 'encrypt';

function setupKeyfileLogic() {
  // Encrypt Tab Keyfile
  const btnSelectEncKf = document.getElementById('btn-select-keyfile-encrypt');
  if (btnSelectEncKf) {
    btnSelectEncKf.addEventListener('click', async () => {
      try {
        const fileInfo = await invokeBackend('select_keyfile_dialog');
        if (fileInfo) {
          selectedEncryptKeyfilePath = fileInfo.path;
          document.getElementById('encrypt-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
          document.getElementById('btn-clear-keyfile-encrypt').style.display = 'inline-block';
          showToast(`Keyfile seleccionado: ${fileInfo.name}`, 'info');
        }
      } catch (e) {
        console.error(e);
      }
    });
  }

  const btnClearEncKf = document.getElementById('btn-clear-keyfile-encrypt');
  if (btnClearEncKf) {
    btnClearEncKf.addEventListener('click', () => {
      selectedEncryptKeyfilePath = null;
      document.getElementById('encrypt-keyfile-display').value = '';
      btnClearEncKf.style.display = 'none';
    });
  }

  // Decrypt Tab Keyfile
  const btnSelectDecKf = document.getElementById('btn-select-keyfile-decrypt');
  if (btnSelectDecKf) {
    btnSelectDecKf.addEventListener('click', async () => {
      try {
        const fileInfo = await invokeBackend('select_keyfile_dialog');
        if (fileInfo) {
          selectedDecryptKeyfilePath = fileInfo.path;
          document.getElementById('decrypt-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
          document.getElementById('btn-clear-keyfile-decrypt').style.display = 'inline-block';
          showToast(`Keyfile seleccionado: ${fileInfo.name}`, 'info');
        }
      } catch (e) {
        console.error(e);
      }
    });
  }

  const btnClearDecKf = document.getElementById('btn-clear-keyfile-decrypt');
  if (btnClearDecKf) {
    btnClearDecKf.addEventListener('click', () => {
      selectedDecryptKeyfilePath = null;
      document.getElementById('decrypt-keyfile-display').value = '';
      btnClearDecKf.style.display = 'none';
    });
  }

  // Vault Create Keyfile
  const btnSelectVaultCreateKf = document.getElementById('btn-select-keyfile-vault-create');
  if (btnSelectVaultCreateKf) {
    btnSelectVaultCreateKf.addEventListener('click', async () => {
      try {
        const fileInfo = await invokeBackend('select_keyfile_dialog');
        if (fileInfo) {
          selectedVaultCreateKeyfilePath = fileInfo.path;
          document.getElementById('vault-create-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
          document.getElementById('btn-clear-keyfile-vault-create').style.display = 'inline-block';
          showToast(`Keyfile para bóveda: ${fileInfo.name}`, 'info');
        }
      } catch (e) {
        console.error(e);
      }
    });
  }

  const btnClearVaultCreateKf = document.getElementById('btn-clear-keyfile-vault-create');
  if (btnClearVaultCreateKf) {
    btnClearVaultCreateKf.addEventListener('click', () => {
      selectedVaultCreateKeyfilePath = null;
      document.getElementById('vault-create-keyfile-display').value = '';
      btnClearVaultCreateKf.style.display = 'none';
    });
  }

  // Vault Open Keyfile
  const btnSelectVaultOpenKf = document.getElementById('btn-select-keyfile-vault-open');
  if (btnSelectVaultOpenKf) {
    btnSelectVaultOpenKf.addEventListener('click', async () => {
      try {
        const fileInfo = await invokeBackend('select_keyfile_dialog');
        if (fileInfo) {
          selectedVaultOpenKeyfilePath = fileInfo.path;
          document.getElementById('vault-open-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
          document.getElementById('btn-clear-keyfile-vault-open').style.display = 'inline-block';
          showToast(`Keyfile para desbloqueo: ${fileInfo.name}`, 'info');
        }
      } catch (e) {
        console.error(e);
      }
    });
  }

  const btnClearVaultOpenKf = document.getElementById('btn-clear-keyfile-vault-open');
  if (btnClearVaultOpenKf) {
    btnClearVaultOpenKf.addEventListener('click', () => {
      selectedVaultOpenKeyfilePath = null;
      document.getElementById('vault-open-keyfile-display').value = '';
      btnClearVaultOpenKf.style.display = 'none';
    });
  }

  // Watcher Tab Keyfile
  const btnSelectWatchKf = document.getElementById('btn-select-keyfile-watch');
  if (btnSelectWatchKf) {
    btnSelectWatchKf.addEventListener('click', async () => {
      try {
        const fileInfo = await invokeBackend('select_keyfile_dialog');
        if (fileInfo) {
          selectedWatchKeyfilePath = fileInfo.path;
          document.getElementById('watch-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
          document.getElementById('btn-clear-keyfile-watch').style.display = 'inline-block';
          showToast(`Keyfile seleccionado: ${fileInfo.name}`, 'info');
        }
      } catch (e) {
        console.error(e);
      }
    });
  }

  const btnClearWatchKf = document.getElementById('btn-clear-keyfile-watch');
  if (btnClearWatchKf) {
    btnClearWatchKf.addEventListener('click', () => {
      selectedWatchKeyfilePath = null;
      document.getElementById('watch-keyfile-display').value = '';
      btnClearWatchKf.style.display = 'none';
    });
  }

  // Open Generator Modal buttons
  const btnOpenGenKf = document.getElementById('btn-open-gen-keyfile');
  if (btnOpenGenKf) {
    btnOpenGenKf.addEventListener('click', () => {
      activeKeyfileTarget = 'encrypt';
      openKeyfileModal();
    });
  }

  const btnOpenGenKfVault = document.getElementById('btn-open-gen-keyfile-vault');
  if (btnOpenGenKfVault) {
    btnOpenGenKfVault.addEventListener('click', () => {
      activeKeyfileTarget = 'vault-create';
      openKeyfileModal();
    });
  }

  const btnOpenGenKfWatch = document.getElementById('btn-open-gen-keyfile-watch');
  if (btnOpenGenKfWatch) {
    btnOpenGenKfWatch.addEventListener('click', () => {
      activeKeyfileTarget = 'watcher';
      openKeyfileModal();
    });
  }

  const btnCloseKfModal = document.getElementById('btn-close-keyfile-modal');
  if (btnCloseKfModal) btnCloseKfModal.addEventListener('click', closeKeyfileModal);

  const btnCancelKfModal = document.getElementById('btn-cancel-keyfile-modal');
  if (btnCancelKfModal) btnCancelKfModal.addEventListener('click', closeKeyfileModal);

  // Setup canvas entropy tracking
  setupEntropyRadar();

  // Save Keyfile
  const btnSaveKf = document.getElementById('btn-save-keyfile-modal');
  if (btnSaveKf) {
    btnSaveKf.addEventListener('click', async () => {
      const sizeRadio = document.querySelector('input[name="keyfile-size-radio"]:checked');
      const size = parseInt(sizeRadio ? sizeRadio.value : '64');
      try {
        const fileInfo = await invokeBackend('generate_keyfile_cmd', {
          size,
          entropy: collectedEntropyBytes,
          defaultName: 'miragex.key'
        });

        if (fileInfo) {
          showToast(`Keyfile generado y guardado: ${fileInfo.name}`, 'success');
          if (activeKeyfileTarget === 'encrypt') {
            selectedEncryptKeyfilePath = fileInfo.path;
            document.getElementById('encrypt-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
            document.getElementById('btn-clear-keyfile-encrypt').style.display = 'inline-block';
          } else if (activeKeyfileTarget === 'vault-create') {
            selectedVaultCreateKeyfilePath = fileInfo.path;
            document.getElementById('vault-create-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
            document.getElementById('btn-clear-keyfile-vault-create').style.display = 'inline-block';
          } else if (activeKeyfileTarget === 'watcher') {
            selectedWatchKeyfilePath = fileInfo.path;
            document.getElementById('watch-keyfile-display').value = `${fileInfo.name} (${formatBytes(fileInfo.size)})`;
            document.getElementById('btn-clear-keyfile-watch').style.display = 'inline-block';
          }
          closeKeyfileModal();
        }
      } catch (err) {
        showToast(`Error al guardar keyfile: ${err}`, 'error');
      }
    });
  }

  // Radio button card styling for keyfile size
  document.querySelectorAll('input[name="keyfile-size-radio"]').forEach(radio => {
    radio.addEventListener('change', () => {
      document.querySelectorAll('.keyfile-size-options .radio-card').forEach(c => c.classList.remove('active'));
      radio.closest('.radio-card').classList.add('active');
    });
  });
}

function openKeyfileModal() {
  const modal = document.getElementById('modal-keyfile-gen');
  if (modal) modal.style.display = 'flex';
  collectedEntropyBytes = [];
  updateEntropyUI(0);
  if (window.initEntropyCanvas) window.initEntropyCanvas();
}

function closeKeyfileModal() {
  const modal = document.getElementById('modal-keyfile-gen');
  if (modal) modal.style.display = 'none';
}

function setupEntropyRadar() {
  const canvas = document.getElementById('entropy-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let points = [];

  function addEntropyPoint(e) {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    points.push({ x, y, alpha: 1.0, r: Math.random() * 3 + 2 });
    if (points.length > 50) points.shift();

    if (collectedEntropyBytes.length < 256) {
      collectedEntropyBytes.push((Math.floor(x) & 0xFF) ^ ((Math.floor(y) >> 2) & 0xFF));
      collectedEntropyBytes.push((Date.now() & 0xFF) ^ ((e.movementX || 1) & 0xFF));
      const pct = Math.min(100, Math.round((collectedEntropyBytes.length / 256) * 100));
      updateEntropyUI(pct);
    }

    drawRadar();
  }

  canvas.addEventListener('mousemove', addEntropyPoint);
  canvas.addEventListener('touchmove', (e) => {
    if (e.touches.length > 0) addEntropyPoint(e.touches[0]);
  }, { passive: true });

  function drawRadar() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw radar grid
    ctx.strokeStyle = 'rgba(176, 38, 255, 0.18)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(canvas.width / 2, canvas.height / 2, 30, 0, Math.PI * 2);
    ctx.arc(canvas.width / 2, canvas.height / 2, 60, 0, Math.PI * 2);
    ctx.moveTo(canvas.width / 2, 0); ctx.lineTo(canvas.width / 2, canvas.height);
    ctx.moveTo(0, canvas.height / 2); ctx.lineTo(canvas.width, canvas.height / 2);
    ctx.stroke();

    // Draw collected particle points
    for (const p of points) {
      ctx.fillStyle = `rgba(176, 38, 255, ${p.alpha})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = `rgba(16, 185, 129, ${p.alpha * 0.8})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r * 0.5, 0, Math.PI * 2);
      ctx.fill();

      p.alpha *= 0.95;
    }
  }

  window.initEntropyCanvas = () => {
    points = [];
    drawRadar();
  };
}

function updateEntropyUI(pct) {
  const bar = document.getElementById('entropy-bar-fill');
  const text = document.getElementById('entropy-percent-text');
  if (bar) bar.style.width = `${pct}%`;
  if (text) text.textContent = `${pct}% ${pct >= 100 ? '✓ (Entropía Óptima)' : ''}`;
}

// 10. Vault Logic & In-App Portable File Explorer (Arcanum/VeraCrypt Style)
function setupVaultLogic() {
  const btnClearSources = document.getElementById('btn-clear-vault-sources');
  if (btnClearSources) {
    btnClearSources.addEventListener('click', () => {
      selectedVaultSources = [];
      renderVaultSourcesList();
    });
  }

  // Add a whole folder as a vault source
  const btnAddFolder = document.getElementById('btn-vault-add-folder');
  if (btnAddFolder) {
    btnAddFolder.addEventListener('click', async () => {
      try {
        const folder = await invokeBackend('select_vault_source_folder_dialog');
        if (folder) {
          folder.is_dir = true;
          addVaultSources([folder]);
        }
      } catch (e) {
        showToast(`Error al seleccionar la carpeta: ${e}`, 'error');
      }
    });
  }

  const btnGenPassVault = document.getElementById('btn-gen-pass-vault');
  if (btnGenPassVault) {
    btnGenPassVault.addEventListener('click', () => {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()_+=-[]{}';
      let pass = '';
      const arr = new Uint8Array(24);
      window.crypto.getRandomValues(arr);
      for (let i = 0; i < 24; i++) pass += chars[arr[i] % chars.length];
      const input = document.getElementById('vault-create-password');
      input.value = pass;
      input.type = 'text';
      showToast('Contraseña de alta entropía generada para la bóveda.', 'info');
    });
  }

  const btnToggleCreatePass = document.getElementById('btn-toggle-vault-create-pass');
  if (btnToggleCreatePass) {
    btnToggleCreatePass.addEventListener('click', () => {
      const input = document.getElementById('vault-create-password');
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  }

  const btnToggleOpenPass = document.getElementById('btn-toggle-vault-open-pass');
  if (btnToggleOpenPass) {
    btnToggleOpenPass.addEventListener('click', () => {
      const input = document.getElementById('vault-open-password');
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  }

  // Create Vault Action
  const btnCreateVault = document.getElementById('btn-execute-create-vault');
  if (btnCreateVault) {
    btnCreateVault.addEventListener('click', async () => {
      if (selectedVaultSources.length === 0) {
        showToast('Por favor añade al menos un archivo o carpeta a la bóveda.', 'error');
        return;
      }

      const password = document.getElementById('vault-create-password').value;
      if (!password && !selectedVaultCreateKeyfilePath) {
        showToast('Introduce una contraseña o selecciona un keyfile para la bóveda.', 'error');
        return;
      }

      try {
        const outPath = await invokeBackend('create_vault_cmd', {
          sourcePaths: selectedVaultSources.map(s => s.path),
          outputPath: null,
          password: password || null,
          keyfilePath: selectedVaultCreateKeyfilePath || null,
          suiteId: 1,
        });

        showToast(`¡Bóveda creada exitosamente!: ${outPath}`, 'success');
        selectedVaultOpenPath = outPath;
        const fileName = outPath.split('/').pop() || outPath.split('\\').pop() || outPath;
        document.getElementById('meta-vault-open-name').textContent = fileName;
        document.getElementById('meta-vault-open-path').textContent = outPath;
        document.getElementById('vault-open-meta').style.display = 'flex';
        if (password) document.getElementById('vault-open-password').value = password;
        if (selectedVaultCreateKeyfilePath) {
          selectedVaultOpenKeyfilePath = selectedVaultCreateKeyfilePath;
          document.getElementById('vault-open-keyfile-display').value = document.getElementById('vault-create-keyfile-display').value;
          document.getElementById('btn-clear-keyfile-vault-open').style.display = 'inline-block';
        }
      } catch (err) {
        showToast(`Error al crear la bóveda: ${err}`, 'error');
      }
    });
  }

  // Open Vault Action
  const btnOpenVault = document.getElementById('btn-execute-open-vault');
  if (btnOpenVault) {
    btnOpenVault.addEventListener('click', async () => {
      if (!selectedVaultOpenPath) {
        showToast('Por favor selecciona un archivo de bóveda .wvault o .wraith.', 'error');
        return;
      }

      const password = document.getElementById('vault-open-password').value;
      if (!password && !selectedVaultOpenKeyfilePath) {
        showToast('Introduce la contraseña o keyfile para desbloquear la bóveda.', 'error');
        return;
      }

      try {
        const session = await invokeBackend('open_vault_cmd', {
          vaultPath: selectedVaultOpenPath,
          password: password || null,
          keyfilePath: selectedVaultOpenKeyfilePath || null,
        });

        currentVaultSession = session;
        vaultCachedEntries = session.entries;
        showToast(`¡Bóveda desbloqueada! ${session.total_entries} elementos listos.`, 'success');
        renderUnlockedVaultView();
      } catch (err) {
        showToast(`Fallo de desbloqueo: ${err}`, 'error');
      }
    });
  }

  // Close / Lock Vault Action
  const btnCloseVault = document.getElementById('btn-close-lock-vault');
  if (btnCloseVault) {
    btnCloseVault.addEventListener('click', async () => {
      if (!currentVaultSession) return;
      try {
        await invokeBackend('close_vault_cmd', { sessionId: currentVaultSession.session_id });
        showToast('Bóveda bloqueada y memoria zeroizada de forma segura.', 'info');
      } catch (e) {
        console.warn(e);
      }
      currentVaultSession = null;
      vaultCachedEntries = [];
      document.getElementById('vault-unlocked-view').style.display = 'none';
      document.getElementById('vault-locked-view').style.display = 'grid';
    });
  }

  // Extract All Action
  const btnExtractAll = document.getElementById('btn-extract-all-vault');
  if (btnExtractAll) {
    btnExtractAll.addEventListener('click', async () => {
      if (!currentVaultSession) return;
      try {
        const count = await invokeBackend('extract_all_vault_cmd', {
          sessionId: currentVaultSession.session_id,
          destinationDir: null,
        });
        showToast(`Se han extraído ${count} archivos correctamente en la carpeta de destino.`, 'success');
      } catch (err) {
        showToast(`Error al extraer archivos: ${err}`, 'error');
      }
    });
  }

  // Real-time search in vault
  const searchInput = document.getElementById('vault-search-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase().trim();
      filterVaultTable(query);
    });
  }
}

function addVaultSources(files) {
  for (const f of files) {
    if (!selectedVaultSources.some(s => s.path === f.path)) {
      selectedVaultSources.push(f);
    }
  }
  renderVaultSourcesList();
}

function renderVaultSourcesList() {
  const box = document.getElementById('vault-sources-list-box');
  const list = document.getElementById('vault-sources-items');
  const count = document.getElementById('vault-sources-count');
  if (!box || !list || !count) return;

  if (selectedVaultSources.length === 0) {
    box.style.display = 'none';
    return;
  }

  box.style.display = 'flex';
  count.textContent = selectedVaultSources.length;
  list.textContent = '';

  selectedVaultSources.forEach((item, idx) => {
    const li = document.createElement('li');
    const icon = item.is_dir ? '📁 ' : '📄 ';
    const detail = item.is_dir ? 'Carpeta completa' : formatBytes(item.size);
    li.textContent = `${icon}${item.name} (${detail})`;
    if (item.is_dir) li.classList.add('vault-source-folder');

    const rmBtn = document.createElement('button');
    rmBtn.type = 'button';
    rmBtn.textContent = '✕';
    rmBtn.className = 'btn-icon';
    rmBtn.style.padding = '2px 6px';
    rmBtn.style.fontSize = '10px';
    rmBtn.addEventListener('click', () => {
      selectedVaultSources.splice(idx, 1);
      renderVaultSourcesList();
    });

    li.appendChild(rmBtn);
    list.appendChild(li);
  });
}

function renderUnlockedVaultView() {
  if (!currentVaultSession) return;
  document.getElementById('vault-locked-view').style.display = 'none';
  const unlockedView = document.getElementById('vault-unlocked-view');
  unlockedView.style.display = 'block';

  const fileName = currentVaultSession.vault_path.split('/').pop() || currentVaultSession.vault_path.split('\\').pop() || currentVaultSession.vault_path;
  document.getElementById('vault-unlocked-name').textContent = `BÓVEDA: ${fileName}`;
  document.getElementById('vault-unlocked-sub').textContent = `${currentVaultSession.total_entries} archivos // ${formatBytes(currentVaultSession.total_unpacked_size)} total`;

  document.getElementById('vault-search-input').value = '';
  renderVaultTableRows(vaultCachedEntries);
}

function getFileIcon(path, isDir) {
  if (isDir) return '📁';
  const ext = path.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'pdf': case 'doc': case 'docx': case 'txt': case 'md': return '📄';
    case 'jpg': case 'jpeg': case 'png': case 'gif': case 'svg': case 'webp': return '🖼️';
    case 'mp3': case 'wav': case 'flac': case 'ogg': return '🎵';
    case 'mp4': case 'mkv': case 'avi': case 'mov': return '🎬';
    case 'zip': case 'tar': case 'gz': case '7z': case 'rar': return '📦';
    case 'rs': case 'js': case 'ts': case 'py': case 'cpp': case 'c': case 'html': return '⚙️';
    default: return '💾';
  }
}

function renderVaultTableRows(entries) {
  const tbody = document.getElementById('vault-files-tbody');
  if (!tbody) return;
  tbody.textContent = '';

  if (entries.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.style.textAlign = 'center';
    td.style.padding = '20px';
    td.style.color = 'var(--text-muted)';
    td.textContent = 'No se encontraron archivos en la bóveda.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  entries.forEach(entry => {
    const tr = document.createElement('tr');

    // Icon
    const tdIcon = document.createElement('td');
    tdIcon.textContent = getFileIcon(entry.path, entry.is_dir);
    tdIcon.style.textAlign = 'center';

    // Path / Name
    const tdName = document.createElement('td');
    tdName.textContent = entry.path;
    if (entry.is_dir) {
      const badge = document.createElement('span');
      badge.className = 'vault-badge-dir';
      badge.textContent = 'CARPETA';
      badge.style.marginLeft = '8px';
      tdName.appendChild(badge);
    }

    // Size
    const tdSize = document.createElement('td');
    tdSize.textContent = entry.is_dir ? '-' : formatBytes(entry.size);

    // Actions
    const tdAct = document.createElement('td');
    tdAct.style.textAlign = 'right';
    if (!entry.is_dir) {
      const extBtn = document.createElement('button');
      extBtn.type = 'button';
      extBtn.className = 'btn-sm btn-secondary';
      extBtn.textContent = '📥 Extraer';
      extBtn.addEventListener('click', async () => {
        try {
          const savedPath = await invokeBackend('extract_vault_entry_cmd', {
            sessionId: currentVaultSession.session_id,
            entryPath: entry.path,
            destinationDir: null,
          });
          showToast(`Archivo extraído: ${savedPath}`, 'success');
        } catch (err) {
          showToast(`Error al extraer: ${err}`, 'error');
        }
      });
      tdAct.appendChild(extBtn);
    }

    tr.appendChild(tdIcon);
    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdAct);
    tbody.appendChild(tr);
  });
}

function filterVaultTable(query) {
  if (!query) {
    renderVaultTableRows(vaultCachedEntries);
    return;
  }
  const filtered = vaultCachedEntries.filter(e => e.path.toLowerCase().includes(query));
  renderVaultTableRows(filtered);
}

// ==========================================================================
// 8. In-App Updater & Changelog Logic (Windows, macOS & Linux Multiplatform)
// ==========================================================================
function setupUpdaterLogic() {
  const modal = document.getElementById('modal-updater-changelog');
  const btnOpen = document.getElementById('btn-open-updater');
  const btnClose = document.getElementById('btn-close-updater-modal');
  const btnGuideChangelog = document.getElementById('btn-guide-changelog');
  const btnCheckNow = document.getElementById('btn-check-updates-now');
  const btnInstall = document.getElementById('btn-execute-install-update');
  const btnRestart = document.getElementById('btn-execute-restart-app');

  const badgeDot = document.getElementById('updater-badge-dot');
  const btnLabel = document.getElementById('updater-btn-label');
  const lblCurrentVersion = document.getElementById('lbl-current-version');
  const badgeStatus = document.getElementById('badge-update-status');
  const lblMessage = document.getElementById('lbl-update-message');

  const cardAction = document.getElementById('card-update-action');
  const lblNewVerTitle = document.getElementById('lbl-new-version-title');
  const lblNewVerSummary = document.getElementById('lbl-new-version-summary');

  const progressWrapper = document.getElementById('wrapper-update-progress');
  const progressBar = document.getElementById('bar-update-progress');
  const progressStats = document.getElementById('lbl-update-progress-stats');
  const changelogList = document.getElementById('changelog-entries-list');

  function openModal() {
    if (modal) {
      modal.style.display = 'flex';
      fetchChangelogAndCheckUpdates(false);
    }
  }

  function closeModal() {
    if (modal) modal.style.display = 'none';
  }

  if (btnOpen) btnOpen.addEventListener('click', openModal);
  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (btnGuideChangelog) btnGuideChangelog.addEventListener('click', openModal);

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }

  if (btnCheckNow) {
    btnCheckNow.addEventListener('click', () => {
      fetchChangelogAndCheckUpdates(true);
    });
  }

  // Listen to Tauri progress event
  const tauri = window.__TAURI__;
  let listen = null;
  if (tauri) {
    if (tauri.event && typeof tauri.event.listen === 'function') {
      listen = tauri.event.listen;
    } else if (tauri.core && typeof tauri.core.listen === 'function') {
      listen = tauri.core.listen;
    } else if (typeof tauri.listen === 'function') {
      listen = tauri.listen;
    }
  }

  if (listen) {
    listen('update-download-progress', (event) => {
      const payload = event.payload;
      if (!payload) return;
      if (progressWrapper) progressWrapper.style.display = 'flex';
      const pct = payload.percent !== undefined && payload.percent !== null ? payload.percent : 50;
      if (progressBar) progressBar.style.width = `${pct}%`;
      const downloadedMb = (payload.downloaded_bytes / (1024 * 1024)).toFixed(1);
      const totalMb = payload.total ? (payload.total / (1024 * 1024)).toFixed(1) : '?';
      if (progressStats) progressStats.textContent = `Descargando paquete oficial... ${pct}% (${downloadedMb} MB / ${totalMb} MB)`;
    });

    listen('update-download-finished', () => {
      if (progressBar) progressBar.style.width = '100%';
      if (progressStats) progressStats.textContent = `Descarga y validación criptográfica completada al 100%.`;
      if (btnInstall) btnInstall.style.display = 'none';
      if (btnRestart) btnRestart.style.display = 'inline-block';
      showToast('Actualización lista. Reinicia MirageX para aplicar los cambios.', 'success');
    });
  }

  if (btnInstall) {
    btnInstall.addEventListener('click', async () => {
      try {
        btnInstall.disabled = true;
        btnInstall.textContent = '⏳ Descargando e instalando...';
        if (progressWrapper) progressWrapper.style.display = 'flex';
        if (progressBar) progressBar.style.width = '10%';
        if (progressStats) progressStats.textContent = 'Iniciando descarga segura en segundo plano...';

        const res = await invokeBackend('install_app_update_cmd');
        showToast(res || 'Actualización descargada correctamente.', 'success');
        btnInstall.style.display = 'none';
        btnRestart.style.display = 'inline-block';
      } catch (err) {
        btnInstall.disabled = false;
        btnInstall.textContent = '🚀 REINTENTAR INSTALAR ACTUALIZACIÓN';
        showToast(`Error al instalar actualización: ${err}`, 'error');
      }
    });
  }

  if (btnRestart) {
    btnRestart.addEventListener('click', async () => {
      try {
        await invokeBackend('restart_app_cmd');
      } catch (err) {
        showToast(`Error al reiniciar: ${err}`, 'error');
      }
    });
  }

  async function fetchChangelogAndCheckUpdates(showUserFeedback = false) {
    if (showUserFeedback) {
      if (lblMessage) lblMessage.textContent = 'Conectando con el repositorio y verificando firmas criptográficas...';
      if (btnCheckNow) {
        btnCheckNow.disabled = true;
        btnCheckNow.textContent = '⏳ Verificando...';
      }
    }

    try {
      // 1. Fetch Changelog History
      let history = [];
      try {
        history = await invokeBackend('get_changelog_history_cmd');
      } catch (e) {
        console.warn('Fallback al leer changelog:', e);
      }

      // 2. Check for App Updates
      let checkRes = null;
      try {
        checkRes = await invokeBackend('check_app_update_cmd');
      } catch (e) {
        console.warn('Error al verificar actualización:', e);
      }

      if (checkRes && checkRes.changelog_history && checkRes.changelog_history.length > 0) {
        history = checkRes.changelog_history;
      }

      renderChangelogHistory(history);

      if (checkRes) {
        if (lblCurrentVersion) lblCurrentVersion.textContent = `v${checkRes.current_version}`;

        if (checkRes.has_update) {
          if (badgeDot) badgeDot.style.display = 'inline-block';
          if (btnLabel) btnLabel.textContent = `ACTUALIZAR A v${checkRes.latest_version}`;
          if (badgeStatus) {
            badgeStatus.textContent = 'NUEVA VERSIÓN DISPONIBLE';
            badgeStatus.className = 'badge pink';
          }
          if (lblMessage) {
            lblMessage.textContent = `Se ha detectado la versión v${checkRes.latest_version}. Publicada con nuevas características y parches.`;
          }
          if (cardAction) cardAction.style.display = 'flex';
          if (lblNewVerTitle) lblNewVerTitle.textContent = `MirageX v${checkRes.latest_version} Disponible`;
          if (lblNewVerSummary) {
            lblNewVerSummary.textContent = checkRes.release_notes || 'Esta versión incluye mejoras críticas en el motor criptográfico y nuevas herramientas.';
          }
          if (btnInstall) {
            btnInstall.style.display = 'inline-block';
            btnInstall.disabled = false;
            btnInstall.textContent = `🚀 DESCARGAR E INSTALAR ACTUALIZACIÓN (v${checkRes.latest_version})`;
          }
          if (btnRestart) btnRestart.style.display = 'none';
          if (showUserFeedback) showToast(`¡Nueva versión v${checkRes.latest_version} lista para instalar!`, 'info');
        } else {
          if (badgeDot) badgeDot.style.display = 'none';
          if (btnLabel) btnLabel.textContent = 'UPDATES & CHANGELOG';
          if (badgeStatus) {
            badgeStatus.textContent = 'SISTEMA ACTUALIZADO';
            badgeStatus.className = 'badge green';
          }
          if (lblMessage) {
            if (checkRes.error) {
              lblMessage.textContent = `Estás en la versión local v${checkRes.current_version}. ${checkRes.error}`;
            } else {
              lblMessage.textContent = `Tu versión v${checkRes.current_version} es la más reciente. Cuentas con la máxima protección post-cuántica.`;
            }
          }
          if (cardAction) cardAction.style.display = 'none';
          if (showUserFeedback) showToast('Tu aplicación ya está en la versión más reciente.', 'success');
        }
      }
    } catch (err) {
      if (showUserFeedback) showToast(`No se pudo verificar actualizaciones: ${err}`, 'error');
    } finally {
      if (btnCheckNow) {
        btnCheckNow.disabled = false;
        btnCheckNow.textContent = '🔍 Buscar Actualizaciones';
      }
    }
  }

  function renderChangelogHistory(entries) {
    if (!changelogList) return;
    changelogList.innerHTML = '';

    if (!entries || entries.length === 0) {
      changelogList.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; padding: 10px;">No hay entradas de Changelog disponibles.</div>';
      return;
    }

    entries.forEach(entry => {
      const card = document.createElement('div');
      card.className = `changelog-card ${entry.is_current ? 'current' : ''}`;

      const top = document.createElement('div');
      top.className = 'changelog-card-top';

      const verDiv = document.createElement('div');
      verDiv.className = 'changelog-card-version';

      const badgeVer = document.createElement('span');
      badgeVer.className = entry.is_current ? 'badge pink' : 'badge purple';
      badgeVer.textContent = entry.version;
      verDiv.appendChild(badgeVer);

      if (entry.is_current) {
        const badgeCurrent = document.createElement('span');
        badgeCurrent.className = 'badge green';
        badgeCurrent.textContent = 'VERSIÓN ACTUAL';
        verDiv.appendChild(badgeCurrent);
      }

      const dateSpan = document.createElement('span');
      dateSpan.className = 'changelog-date';
      dateSpan.textContent = `📅 ${entry.date}`;

      top.appendChild(verDiv);
      top.appendChild(dateSpan);
      card.appendChild(top);

      const titleEl = document.createElement('div');
      titleEl.className = 'changelog-ver-title';
      titleEl.textContent = entry.title;
      card.appendChild(titleEl);

      // Highlights
      if (entry.highlights && entry.highlights.length > 0) {
        const secTitle = document.createElement('div');
        secTitle.className = 'changelog-section-title';
        secTitle.textContent = '✨ Novedades & Características:';
        card.appendChild(secTitle);

        const ul = document.createElement('ul');
        ul.className = 'changelog-items-list';
        entry.highlights.forEach(h => {
          const li = document.createElement('li');
          li.className = 'changelog-item';
          li.textContent = h;
          ul.appendChild(li);
        });
        card.appendChild(ul);
      }

      // Security notes
      if (entry.security_notes && entry.security_notes.length > 0) {
        const secTitle2 = document.createElement('div');
        secTitle2.className = 'changelog-section-title';
        secTitle2.textContent = '🛡️ Seguridad & Hardening Criptográfico:';
        card.appendChild(secTitle2);

        const ul2 = document.createElement('ul');
        ul2.className = 'changelog-items-list';
        entry.security_notes.forEach(s => {
          const li = document.createElement('li');
          li.className = 'changelog-sec-item';
          li.textContent = s;
          ul2.appendChild(li);
        });
        card.appendChild(ul2);
      }

      changelogList.appendChild(card);
    });
  }

  // Silent check on app launch after 3 seconds
  setTimeout(() => {
    fetchChangelogAndCheckUpdates(false);
  }, 3000);

  // Initialize Experimental Beta Labs Features
  initBetaLabs();
}
// --------------------------------------------------------------------------
// Decrypt Manifest Detection
// --------------------------------------------------------------------------
function checkDecryptManifestNotice(filePath) {
  const notice = document.getElementById('decrypt-backup-manifest-notice');
  if (!notice) return;
  if (!filePath) {
    notice.style.display = 'none';
    return;
  }
  const fileName = (filePath.split('/').pop() || filePath.split('\\').pop() || '').toLowerCase();
  if (fileName.includes('manifest') && fileName.endsWith('.wraith')) {
    notice.style.display = 'block';
  } else {
    notice.style.display = 'none';
  }
}

// --------------------------------------------------------------------------
// Cloud Backup Mode Integration (CIFRAR & DESCIFRAR)
// --------------------------------------------------------------------------
function setupEncryptBackupMode() {
  const toggleBackup = document.getElementById('toggle-encrypt-backup-mode');
  const singleFileSection = document.getElementById('encrypt-single-file-section');
  const backupModeSection = document.getElementById('encrypt-backup-mode-section');
  const originTitle = document.getElementById('lbl-encrypt-origin-title');
  const originBadge = document.getElementById('badge-encrypt-origin');
  const btnStartEncrypt = document.getElementById('btn-start-encrypt');

  toggleBackup?.addEventListener('change', () => {
    if (toggleBackup.checked) {
      if (singleFileSection) singleFileSection.style.display = 'none';
      if (backupModeSection) backupModeSection.style.display = 'block';
      if (originTitle) originTitle.textContent = 'RESPALDO CIFRADO PARA LA NUBE';
      if (originBadge) originBadge.textContent = 'RESTIC / BORG / RSYNC';
      if (btnStartEncrypt) btnStartEncrypt.textContent = '🚀 GENERAR RESPALDO CRIPTOGRÁFICO ANONIMIZADO';
    } else {
      if (singleFileSection) singleFileSection.style.display = 'block';
      if (backupModeSection) backupModeSection.style.display = 'none';
      if (originTitle) originTitle.textContent = 'ORIGEN DE DATOS & ARCHIVO';
      if (originBadge) originBadge.textContent = 'ARCHIVO INDIVIDUAL';
      if (btnStartEncrypt) btnStartEncrypt.textContent = '🔒 INICIAR CIFRADO MIRAGEX';
    }
  });

  const btnBrowseSrc = document.getElementById('btn-browse-backup-main-src');
  const inpBackupSrc = document.getElementById('backup-main-src-input');
  btnBrowseSrc?.addEventListener('click', async () => {
    try {
      const folder = await invokeBackend('select_folder_dialog');
      if (folder && inpBackupSrc) inpBackupSrc.value = folder;
    } catch (e) {
      showToast(`Error seleccionando carpeta origen: ${e}`, 'error');
    }
  });

  const btnBrowseDst = document.getElementById('btn-browse-backup-main-dst');
  const inpBackupDst = document.getElementById('backup-main-dst-input');
  btnBrowseDst?.addEventListener('click', async () => {
    try {
      const folder = await invokeBackend('select_folder_dialog');
      if (folder && inpBackupDst) inpBackupDst.value = folder;
    } catch (e) {
      showToast(`Error seleccionando carpeta destino: ${e}`, 'error');
    }
  });

  // Decrypt backup manifest restore
  const btnBrowseRestoreDest = document.getElementById('btn-browse-restore-cloud-dest');
  const inpRestoreDest = document.getElementById('restore-cloud-dest-input');
  btnBrowseRestoreDest?.addEventListener('click', async () => {
    try {
      const folder = await invokeBackend('select_folder_dialog');
      if (folder && inpRestoreDest) inpRestoreDest.value = folder;
    } catch (e) {
      showToast(`Error seleccionando carpeta de destino: ${e}`, 'error');
    }
  });

  const btnExecRestoreCloud = document.getElementById('btn-execute-restore-cloud-main');
  btnExecRestoreCloud?.addEventListener('click', async () => {
    if (!selectedDecryptPath) {
      showToast('Selecciona el contenedor de manifiesto (backup_manifest.wraith)', 'warning');
      return;
    }
    const destDir = inpRestoreDest?.value.trim();
    if (!destDir) {
      showToast('Selecciona la carpeta de destino para restaurar los archivos.', 'warning');
      return;
    }
    const pass = document.getElementById('decrypt-password')?.value || '';
    if (!pass && !selectedDecryptKeyfilePath) {
      showToast('Introduce la contraseña o keyfile para restaurar el manifiesto.', 'warning');
      return;
    }

    try {
      btnExecRestoreCloud.disabled = true;
      btnExecRestoreCloud.textContent = '⏳ Verificando hashes y restaurando archivos...';

      const manifestPath = selectedDecryptPath;
      const lastSlash = Math.max(manifestPath.lastIndexOf('/'), manifestPath.lastIndexOf('\\'));
      const backupDir = lastSlash > 0 ? manifestPath.substring(0, lastSlash) : manifestPath;

      const res = await invokeBackend('restore_backup_archive_cmd', {
        backupPath: backupDir,
        restorePath: destDir,
        password: pass,
        keyfilePaths: selectedDecryptKeyfilePath ? [selectedDecryptKeyfilePath] : [],
      });

      showToast(`¡Restauración exitosa! ${res.restored_files} archivos restaurados.`, 'success');
      const resultBox = document.getElementById('decrypt-result-box');
      if (resultBox) {
        resultBox.innerHTML = `
          <div class="result-box success" style="margin-top: 10px;">
            <div style="font-weight: 800; color: #4ade80; margin-bottom: 6px;">✓ RESTAURACIÓN DE RESPALDO COMPLETA</div>
            <div>• <strong>Archivos reconstruidos:</strong> ${res.restored_files}</div>
            <div>• <strong>Bytes verificados con SHA-256:</strong> ${formatBytes(res.restored_bytes)}</div>
            <div>• <strong>Destino:</strong> <code>${res.restore_dir}</code></div>
          </div>
        `;
      }
    } catch (e) {
      showToast(`Error restaurando respaldo: ${e}`, 'error');
    } finally {
      btnExecRestoreCloud.disabled = false;
      btnExecRestoreCloud.textContent = '🗄️ RESTAURAR ÁRBOL COMPLETO DE RESPALDO';
    }
  });
}

// --------------------------------------------------------------------------
// Vigilante / Carpeta Vigilada (Auto-Cifrado en Tiempo Real)
// --------------------------------------------------------------------------
function initWatcherPanel() {
  const inpWatchFolder = document.getElementById('watch-folder-input');
  const inpWatchOutput = document.getElementById('watch-output-input');
  const btnBrowseWatchFolder = document.getElementById('btn-browse-watch-folder');
  const btnBrowseWatchOutput = document.getElementById('btn-browse-watch-output');
  const inpWatchPass = document.getElementById('watch-password');
  const btnToggleWatchPass = document.getElementById('btn-toggle-watch-pass');
  const selectWatchSuite = document.getElementById('watch-suite-select');

  const filterRadios = document.querySelectorAll('input[name="watch-filter-mode"]');
  const watchExtWrapper = document.getElementById('watch-extensions-wrapper');
  const inpWatchExt = document.getElementById('watch-filter-extensions-input');
  const selectWatchTimeout = document.getElementById('watch-timeout-select');
  const chkWatchNameFuzzing = document.getElementById('watch-name-fuzzing-chk');
  const chkWatchRecursive = document.getElementById('watch-recursive-chk');
  const chkWatchNotify = document.getElementById('watch-notify-chk');
  const chkWatchShred = document.getElementById('watch-shred-source-chk');

  const btnStartWatcher = document.getElementById('btn-start-watcher');
  const btnStopWatcher = document.getElementById('btn-stop-watcher');
  const badgeStatusTop = document.getElementById('watcher-badge-status-top');
  const badgeRam = document.getElementById('watcher-badge-ram');
  const badgeCount = document.getElementById('watcher-badge-count');
  const statusText = document.getElementById('watcher-status-text');
  const terminalLog = document.getElementById('watcher-log-terminal');
  const navBadge = document.getElementById('nav-watcher-badge');

  const btnExportCsv = document.getElementById('btn-export-audit-csv');
  const btnExportJsonl = document.getElementById('btn-export-audit-jsonl');

  let watcherInterval = null;

  btnBrowseWatchFolder?.addEventListener('click', async () => {
    try {
      const folder = await invokeBackend('select_folder_dialog');
      if (folder && inpWatchFolder) inpWatchFolder.value = folder;
    } catch (e) {
      showToast(`Error seleccionando carpeta origen: ${e}`, 'error');
    }
  });

  btnBrowseWatchOutput?.addEventListener('click', async () => {
    try {
      const folder = await invokeBackend('select_folder_dialog');
      if (folder && inpWatchOutput) inpWatchOutput.value = folder;
    } catch (e) {
      showToast(`Error seleccionando carpeta destino: ${e}`, 'error');
    }
  });

  btnToggleWatchPass?.addEventListener('click', () => {
    if (inpWatchPass) {
      inpWatchPass.type = inpWatchPass.type === 'password' ? 'text' : 'password';
    }
  });

  filterRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      filterRadios.forEach(r => r.closest('.radio-card')?.classList.remove('active'));
      radio.closest('.radio-card')?.classList.add('active');
      if (watchExtWrapper) {
        watchExtWrapper.style.display = radio.value === 'whitelist' ? 'block' : 'none';
      }
    });
  });

  btnStartWatcher?.addEventListener('click', async () => {
    const watchDir = inpWatchFolder?.value.trim();
    const outputDir = inpWatchOutput?.value.trim();
    const password = inpWatchPass?.value || '';

    if (!watchDir) {
      showToast('Selecciona la carpeta a vigilar.', 'warning');
      return;
    }
    if (!outputDir) {
      showToast('Selecciona la carpeta de salida cifrada.', 'warning');
      return;
    }
    if (!password && !selectedWatchKeyfilePath) {
      showToast('Ingresa una contraseña o keyfile para el auto-cifrado.', 'warning');
      return;
    }

    const selectedFilterMode = document.querySelector('input[name="watch-filter-mode"]:checked')?.value || 'all';
    const rawExtensions = inpWatchExt?.value || '';
    const filterExtensions = selectedFilterMode === 'whitelist'
      ? rawExtensions.split(',').map(s => s.trim().replace(/^\./, '').toLowerCase()).filter(Boolean)
      : [];

    const timeoutMinutes = parseInt(selectWatchTimeout?.value || '15', 10);
    const suite = selectWatchSuite?.value || '768';
    const isNameFuzzing = chkWatchNameFuzzing ? chkWatchNameFuzzing.checked : true;
    const isRecursive = chkWatchRecursive ? chkWatchRecursive.checked : true;
    const isNotify = chkWatchNotify ? chkWatchNotify.checked : true;
    const isShred = chkWatchShred ? chkWatchShred.checked : false;

    try {
      btnStartWatcher.disabled = true;
      const keyfiles = selectedWatchKeyfilePath ? [selectedWatchKeyfilePath] : [];
      const res = await invokeBackend('start_folder_watcher_cmd', {
        config: {
          watch_dir: watchDir,
          output_dir: outputDir,
          password: password,
          keyfile_paths: keyfiles,
          suite: suite,
          name_fuzzing: isNameFuzzing,
          shred_source: isShred,
          recursive: isRecursive,
          filter_mode: selectedFilterMode,
          filter_extensions: filterExtensions,
          inactivity_timeout_minutes: timeoutMinutes,
          os_notifications: isNotify,
        }
      });

      showToast(res, 'success');
      btnStartWatcher.style.display = 'none';
      if (btnStopWatcher) btnStopWatcher.style.display = 'block';
      if (badgeStatusTop) {
        badgeStatusTop.className = 'badge green';
        badgeStatusTop.textContent = '🟢 VIGILANDO EN VIVO';
      }
      if (badgeRam) {
        badgeRam.className = 'badge purple';
        badgeRam.textContent = '🛡️ CLAVES EN RAM';
      }
      if (navBadge) {
        navBadge.style.display = 'inline-block';
      }
      if (statusText) statusText.textContent = 'ACTIVO // POLLING CADA 1500 MS';

      appendWatcherLog(`[INICIADO] Motor de Vigilancia MirageX v4.1 activo`);
      appendWatcherLog(`[ORIGEN] ${watchDir} ${isRecursive ? '(Recursivo)' : '(Directorio Raíz)'}`);
      appendWatcherLog(`[DESTINO] ${outputDir}`);
      appendWatcherLog(`[NAME FUZZING] ${isNameFuzzing ? 'ACTIVADO ([sha256].wraith anonimizado)' : 'Conservar nombre original'}`);
      appendWatcherLog(`[FILTRO] Modo: ${selectedFilterMode.toUpperCase()}${selectedFilterMode === 'whitelist' ? ' [' + filterExtensions.join(', ') + ']' : ''}`);
      appendWatcherLog(`[AUTO-BLOQUEO] Inactividad RAM: ${timeoutMinutes > 0 ? timeoutMinutes + ' min' : 'Desactivado'}`);
      appendWatcherLog(`[SEGURIDAD] Triturado: ${isShred ? 'ACTIVADO (CSPRNG 3 pases)' : 'Conservar original'}`);

      if (watcherInterval) clearInterval(watcherInterval);
      watcherInterval = setInterval(pollWatcherStatus, 1500);
    } catch (e) {
      showToast(`Error iniciando vigilancia: ${e}`, 'error');
    } finally {
      btnStartWatcher.disabled = false;
    }
  });

  btnStopWatcher?.addEventListener('click', async () => {
    try {
      btnStopWatcher.disabled = true;
      const res = await invokeBackend('stop_folder_watcher_cmd');
      showToast(res, 'info');
      setWatcherUIStopped(false);
      appendWatcherLog(`[DETENIDO] Vigilancia pausada por el usuario.`);
    } catch (e) {
      showToast(`Error deteniendo vigilancia: ${e}`, 'error');
    } finally {
      btnStopWatcher.disabled = false;
    }
  });

  function setWatcherUIStopped(wasAutoLocked = false) {
    if (btnStopWatcher) btnStopWatcher.style.display = 'none';
    if (btnStartWatcher) btnStartWatcher.style.display = 'block';
    if (badgeStatusTop) {
      badgeStatusTop.className = wasAutoLocked ? 'badge yellow' : 'badge gray';
      badgeStatusTop.textContent = wasAutoLocked ? '🔒 BLOQUEADO POR INACTIVIDAD' : '⚪ INACTIVO';
    }
    if (badgeRam) {
      badgeRam.className = wasAutoLocked ? 'badge red' : 'badge purple';
      badgeRam.textContent = wasAutoLocked ? '🧹 RAM PURGADA (ZEROIZE)' : '🛡️ CLAVES EN RAM';
    }
    if (navBadge) {
      navBadge.style.display = 'none';
    }
    if (statusText) statusText.textContent = wasAutoLocked ? 'BLOQUEADO' : 'INACTIVO';
    if (watcherInterval) {
      clearInterval(watcherInterval);
      watcherInterval = null;
    }
  }

  async function pollWatcherStatus() {
    try {
      const st = await invokeBackend('get_watcher_status_cmd');
      if (st) {
        if (!st.is_active && watcherInterval) {
          const autoLocked = st.auto_locked;
          setWatcherUIStopped(autoLocked);
          if (autoLocked) {
            appendWatcherLog(`[AUTO-BLOQUEO] Clave purgada de RAM (zeroize) tras período de inactividad.`);
            showToast('El vigilante se ha auto-bloqueado por inactividad para proteger la clave en memoria.', 'info');
          }
          return;
        }

        if (badgeCount) badgeCount.textContent = `${st.processed_count} ARCHIVOS PROCESADOS`;
        if (st.last_event) {
          appendWatcherLog(st.last_event);
        }
      }
    } catch (_) {}
  }

  function appendWatcherLog(msg) {
    if (!terminalLog) return;
    const time = new Date().toLocaleTimeString();
    const line = `[${time}] ${msg}`;
    if (!terminalLog.textContent.includes(line)) {
      terminalLog.textContent += `
${line}`;
      terminalLog.scrollTop = terminalLog.scrollHeight;
    }
  }

  // Audit Log Exports
  btnExportCsv?.addEventListener('click', async () => {
    try {
      const csv = await invokeBackend('export_watcher_audit_log_cmd', { format: 'csv' });
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `miragex_watcher_audit_${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Registro de auditoría exportado en CSV.', 'success');
    } catch (e) {
      showToast(`Error exportando CSV: ${e}`, 'error');
    }
  });

  btnExportJsonl?.addEventListener('click', async () => {
    try {
      const jsonl = await invokeBackend('export_watcher_audit_log_cmd', { format: 'jsonl' });
      const blob = new Blob([jsonl], { type: 'application/x-ndjson;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `miragex_watcher_audit_${new Date().toISOString().slice(0, 10)}.jsonl`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Registro de auditoría exportado en JSONL.', 'success');
    } catch (e) {
      showToast(`Error exportando JSONL: ${e}`, 'error');
    }
  });
}

// --------------------------------------------------------------------------
// Beta Labs (Integración de Sistema, Menú Contextual, QuickLook & Linux)
// --------------------------------------------------------------------------
function initBetaLabs() {
  // Navigation shortcuts from Beta promo cards
  const btnGotoWatcher = document.getElementById('btn-goto-watcher-tab');
  btnGotoWatcher?.addEventListener('click', () => {
    document.querySelector('.nav-tab[data-tab="watcher"]')?.click();
  });

  const btnGotoEncrypt = document.getElementById('btn-goto-encrypt-tab');
  btnGotoEncrypt?.addEventListener('click', () => {
    document.querySelector('.nav-tab[data-tab="encrypt"]')?.click();
    const toggle = document.getElementById('toggle-encrypt-backup-mode');
    if (toggle && !toggle.checked) {
      toggle.checked = true;
      toggle.dispatchEvent(new Event('change'));
    }
  });

  // --- 3. MENÚ CONTEXTUAL ---
  const btnInstallContext = document.getElementById('btn-install-context-menu');
  const btnUninstallContext = document.getElementById('btn-uninstall-context-menu');
  const btnExportContextScripts = document.getElementById('btn-export-context-scripts');
  const contextScriptsContainer = document.getElementById('context-scripts-container');
  const btnCloseContextScripts = document.getElementById('btn-close-context-scripts');
  const contextScriptCode = document.getElementById('context-script-code');
  const tabScriptBat = document.getElementById('tab-script-bat');
  const tabScriptReg = document.getElementById('tab-script-reg');
  const tabScriptSh = document.getElementById('tab-script-sh');

  let exportedScripts = null;

  btnInstallContext?.addEventListener('click', async () => {
    try {
      const res = await invokeBackend('setup_context_menu_cmd');
      showToast(res, 'success');
    } catch (e) {
      showToast(`Error registrando menú contextual: ${e}`, 'error');
    }
  });

  btnUninstallContext?.addEventListener('click', async () => {
    try {
      const res = await invokeBackend('remove_context_menu_cmd');
      showToast(res, 'info');
    } catch (e) {
      showToast(`Error al desinstalar: ${e}`, 'error');
    }
  });

  btnExportContextScripts?.addEventListener('click', async () => {
    try {
      exportedScripts = await invokeBackend('export_context_menu_scripts_cmd');
      contextScriptsContainer.style.display = 'block';
      showScriptTab('bat');
    } catch (e) {
      showToast(`Error exportando scripts: ${e}`, 'error');
    }
  });

  btnCloseContextScripts?.addEventListener('click', () => {
    contextScriptsContainer.style.display = 'none';
  });

  tabScriptBat?.addEventListener('click', () => showScriptTab('bat'));
  tabScriptReg?.addEventListener('click', () => showScriptTab('reg'));
  tabScriptSh?.addEventListener('click', () => showScriptTab('sh'));

  function showScriptTab(type) {
    if (!exportedScripts) return;
    [tabScriptBat, tabScriptReg, tabScriptSh].forEach(t => t?.classList.remove('active'));
    if (type === 'bat') {
      tabScriptBat?.classList.add('active');
      contextScriptCode.textContent = exportedScripts.windows_bat;
    } else if (type === 'reg') {
      tabScriptReg?.classList.add('active');
      contextScriptCode.textContent = exportedScripts.windows_reg;
    } else {
      tabScriptSh?.classList.add('active');
      contextScriptCode.textContent = exportedScripts.linux_sh;
    }
  }

  // --- 4. VISTA PREVIA DE CABECERA & QUICK LOOK ---
  const inpPreviewFile = document.getElementById('preview-file-input');
  const btnBrowsePreviewFile = document.getElementById('btn-browse-preview-file');
  const previewDisplayCard = document.getElementById('preview-display-card');
  const previewFilenameTitle = document.getElementById('preview-filename-title');
  const previewSuiteVal = document.getElementById('preview-suite-val');
  const previewArgonVal = document.getElementById('preview-argon-val');
  const previewChunkVal = document.getElementById('preview-chunk-val');
  const previewSizeVal = document.getElementById('preview-size-val');
  const previewAsciiBox = document.getElementById('preview-ascii-box');
  const btnInstallQuicklookAction = document.getElementById('btn-install-quicklook-action');

  btnBrowsePreviewFile?.addEventListener('click', async () => {
    try {
      const f = await invokeBackend('select_wraith_dialog');
      if (f) {
        inpPreviewFile.value = f.path;
        loadHeaderPreview(f.path);
      }
    } catch (e) {
      showToast(`Error seleccionando archivo: ${e}`, 'error');
    }
  });

  async function loadHeaderPreview(filePath) {
    try {
      const info = await invokeBackend('inspect_header_for_preview_cmd', { filePath });
      previewDisplayCard.style.display = 'block';
      previewFilenameTitle.textContent = info.file_name;
      previewSuiteVal.textContent = info.suite_name;
      previewArgonVal.textContent = info.argon2_summary;
      previewChunkVal.textContent = `${info.chunk_size_mb.toFixed(1)} MB (AEAD GCM)`;
      previewSizeVal.textContent = `${(info.file_size / (1024 * 1024)).toFixed(2)} MB`;
      previewAsciiBox.textContent = info.summary_text;
      showToast('Cabecera WRAITH verificada sin descifrar el contenido.', 'success');
    } catch (e) {
      showToast(`No se pudo leer cabecera WRAITH: ${e}`, 'error');
    }
  }

  btnInstallQuicklookAction?.addEventListener('click', async () => {
    try {
      const res = await invokeBackend('setup_quicklook_preview_cmd');
      showToast(res, 'success');
    } catch (e) {
      showToast(`Error registrando Quick Look: ${e}`, 'error');
    }
  });

  // --- 5. INTEGRACIÓN EN LINUX ---
  const btnInstallLinuxMime = document.getElementById('btn-install-linux-integration');
  const btnExportLinuxSh = document.getElementById('btn-export-linux-sh');

  btnInstallLinuxMime?.addEventListener('click', async () => {
    try {
      const res = await invokeBackend('setup_linux_desktop_integration_cmd');
      showToast(res, 'success');
    } catch (e) {
      showToast(`Resultado: ${e}`, 'info');
    }
  });

  btnExportLinuxSh?.addEventListener('click', async () => {
    try {
      const scripts = await invokeBackend('export_context_menu_scripts_cmd');
      const blob = new Blob([scripts.linux_sh], { type: 'text/x-shellscript' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'install_miragex_linux.sh';
      a.click();
      URL.revokeObjectURL(url);
      showToast('Script de instalación de Linux exportado.', 'success');
    } catch (e) {
      showToast(`Error exportando script: ${e}`, 'error');
    }
  });
}

// ==========================================
// 15. BILINGUAL INTERNATIONALIZATION (i18n)
// 🇲🇽 Español (MX) & 🇺🇸 English (US)
// ==========================================
let currentLang = 'es';

const I18N = {
  es: {
    // Brand & HUD
    brand_sub: "MOTOR CRIPTOGRÁFICO POST-CUÁNTICO // FORMATO WRAITH v4",
    status_algo: "ALGORITMO: MIRAGEX (NIST FIPS 203)",
    btn_quick_guide: "💡 ¿POR DÓNDE EMPIEZO?",
    btn_updates: "🔄 UPDATES & CHANGELOG",
    btn_context_menu: "🖱️ INTEGRACIÓN MENÚ OS",
    status_zero_server: "ZERO-SERVER // IPC NATIVO",

    // Navigation Tabs
    nav_encrypt: "CIFRAR",
    nav_decrypt: "DESCIFRAR",
    nav_vault: "BÓVEDA",
    nav_watcher: "VIGILANTE",
    nav_inspect: "INSPECTOR",
    nav_benchmark: "BENCHMARK",
    nav_shred: "TRITURADOR",
    nav_guide: "GUÍA & AYUDA",
    nav_beta: "BETA LABS",
    badge_new: "NUEVO",

    // Common
    btn_browse: "📂 Explorar",
    btn_browse_kf: "📂 Examinar",
    btn_gen_kf: "🎲 Generar Keyfile",
    btn_remove_kf: "Quitar keyfile",
    ph_kf: "Sin keyfile (Opcional: 2FA o Solo-Keyfile)...",

    // Encrypt Tab
    enc_origin_title: "ORIGEN DE DATOS & ARCHIVO",
    badge_single_file: "ARCHIVO INDIVIDUAL",
    lbl_cloud_backup_mode: "🗄️ Modo Respaldo Nube (Restic/Borg)",
    drop_enc_title: "Arrastra tu archivo aquí",
    drop_enc_sub: "o haz clic para abrir el selector nativo",
    lbl_enc_pass: "CONTRASEÑA MAESTRA DE PROTECCIÓN",
    ph_enc_pass: "Introduce una contraseña para el envelope MirageX...",
    btn_gen: "🎲 Generar",
    lbl_enc_kf: "KEYFILE DE SEGURIDAD // ESTÁNDAR VERACRYPT & ARCANUM",
    hint_enc_kf: "Algoritmo de mezcla CRC-32 IEEE 802.3 y adición modular. Compatible con Arcanum y VeraCrypt.",
    card_suite_title: "SUITE DEL ALGORITMO MIRAGEX",
    lbl_security_mode: "MODO DE SEGURIDAD MIRAGEX",
    lbl_chunk_size: "STREAMING CHUNK SIZE",
    chk_name_fuzzing: "Name Fuzzing (Activo por defecto)",
    hint_name_fuzzing: "🛡️ Cero fuga de nombres o extensiones ([sha256].wraith). Se restaura al descifrar.",
    chk_shred_source: "Borrado seguro del archivo original tras cifrar",
    lbl_disk_type: "TIPO DE DISCO",
    lbl_passes: "PASADAS",
    btn_start_encrypt: "🔒 INICIAR CIFRADO MIRAGEX",
    telemetry_title: "TELEMETRÍA CRIPTOGRÁFICA MIRAGEX",

    // Decrypt Tab
    dec_card_title: "CONTENEDOR WRAITH (.wraith)",
    drop_dec_title: "Arrastra tu archivo .wraith aquí",
    drop_dec_sub: "o haz clic para examinar el disco",
    lbl_dec_pass: "CONTRASEÑA DE AUTENTICACIÓN",
    ph_dec_pass: "Contraseña de desencapsulado...",
    lbl_dec_kf: "KEYFILE DE DESENCRIPTACIÓN",
    chk_shred_container: "Borrado seguro del contenedor .wraith tras restauración",
    btn_start_decrypt: "🔓 DESENCAPSULAR & VERIFICAR CON MIRAGEX",
    dec_authenticity_title: "RESULTADO DE AUTENTICIDAD",
    dec_empty_text: "Esperando autenticación de contenedor para verificar integridad.",

    // Vault Tab
    vault_create_title: "CREAR NUEVA BÓVEDA CIFRADA",
    vault_create_drop: "Seleccionar Archivos para la Bóveda",
    vault_create_drop_sub: "O usa «Añadir carpeta completa» para empaquetar un directorio entero con ML-KEM + AES-256-GCM",
    btn_vault_add_folder: "📁 Añadir carpeta completa",
    lbl_vault_create_pass: "CONTRASEÑA DE LA BÓVEDA",
    ph_vault_create_pass: "Contraseña maestra de la bóveda...",
    lbl_vault_create_kf: "KEYFILE DE LA BÓVEDA",
    btn_execute_create_vault: "📦 CREAR Y CIFRAR BÓVEDA EN DISCO",
    vault_open_title: "DESBLOQUEAR BÓVEDA EXISTENTE",
    vault_open_drop: "Selecciona un archivo .wvault o .wraith",
    vault_open_drop_sub: "Abre y explora el árbol de archivos sin drivers de kernel",
    lbl_vault_open_pass: "CONTRASEÑA DE DESBLOQUEO",
    ph_vault_open_pass: "Contraseña de la bóveda...",
    lbl_vault_open_kf: "KEYFILE DE DESBLOQUEO",
    btn_execute_open_vault: "🔓 DESBLOQUEAR Y EXPLORAR BÓVEDA",
    btn_extract_all_vault: "📁 Extraer Todo a Carpeta",
    btn_close_lock_vault: "🔒 Bloquear y Cerrar Bóveda",
    ph_vault_search: "Buscar archivos dentro de la bóveda...",

    // Watcher Tab
    watcher_badge_top: "👁️ MOTOR DE VIGILANCIA EN TIEMPO REAL",
    watcher_badge_inactive: "⚪ INACTIVO",
    watcher_badge_active: "🟢 VIGILANDO EN VIVO",
    watcher_badge_ram: "🛡️ CLAVES EN RAM",
    watcher_hero_title: "Carpeta Vigilada // ",
    watcher_hero_title_hl: "Auto-Cifrado Continuo",
    watcher_hero_desc: "Todo archivo nuevo o modificado que se guarde en la carpeta vigilada es cifrado automáticamente en streaming como contenedor .wraith. Soporta filtrado de extensiones, modo recursivo, notificaciones de escritorio, triturado seguro y auto-bloqueo por inactividad.",
    watcher_dirs_title: "DIRECTORIOS & SEGURIDAD DE SESIÓN",
    watcher_lbl_watch_dir: "Directorio Vigilado (Carpeta Origen):",
    watcher_ph_watch_dir: "Selecciona la carpeta a monitorear...",
    watcher_lbl_output_dir: "Directorio de Salida Cifrada (.wraith):",
    watcher_ph_output_dir: "Selecciona la carpeta de destino...",
    watcher_lbl_pass: "Contraseña en Memoria (Sesión Activa):",
    watcher_ph_pass: "Contraseña para auto-cifrar...",
    watcher_lbl_algo: "Algoritmo Post-Cuántico:",
    lbl_watch_keyfile: "KEYFILE DE SEGURIDAD",
    hint_watch_keyfile: "Algoritmo de mezcla CRC-32 IEEE 802.3 y adición modular de 64 bytes.",
    watcher_rules_title: "REGLAS & AUTOMATIZACIÓN",
    watcher_lbl_filter: "Filtro de Archivos:",
    watcher_filter_all: "Todos los archivos",
    watcher_filter_whitelist: "Whitelist de extensiones",
    watcher_lbl_timeout: "Auto-Bloqueo de Seguridad por Inactividad:",
    watcher_timeout_0: "Desactivado (Mantener sesión abierta)",
    watcher_timeout_5: "5 minutos sin nuevos archivos",
    watcher_timeout_15: "15 minutos (Recomendado)",
    watcher_timeout_30: "30 minutos",
    watcher_timeout_60: "1 hora",
    watcher_chk_recursive: "Vigilancia recursiva (Monitorear subcarpetas anidadas)",
    watcher_chk_notify: "Notificaciones nativas del sistema operativo",
    lbl_watch_shred: "Borrado seguro del archivo original tras cifrar (Activo por defecto)",
    btn_start_watcher: "▶️ INICIAR VIGILANCIA",
    btn_stop_watcher: "⏹️ DETENER VIGILANCIA",
    watcher_audit_title: "REGISTRO DE AUDITORÍA & EVENTOS EN VIVO",
    watcher_console_title: "CONSOLA EN TIEMPO REAL",
    watcher_status_waiting: "ESPERANDO CONFIGURACIÓN",
    btn_export_csv: "📥 Exportar CSV",
    btn_export_jsonl: "📥 Exportar JSONL",

    // Inspector Tab
    inspect_card_title: "INSPECCIÓN ESTRUCTURAL DE CABECERAS WRAITH (CERO CONOCIMIENTO)",
    drop_inspect_title: "Arrastra un archivo .wraith para inspección inmediata",
    drop_inspect_sub: "Lee los metadatos de suite y UUID sin requerir la contraseña ni descifrar el contenido",

    // Benchmark Tab
    bench_card_title: "BENCHMARK DE RENDIMIENTO DEL ALGORITMO MIRAGEX",
    btn_run_bench: "⚡ Ejecutar Test de Estrés",
    bench_desc: "Evalúa la velocidad de encapsulación post-cuántica (FIPS 203), derivación de claves Argon2id y tasa de transferencia por aceleración de hardware AES-256-GCM.",

    // Shredder Tab
    shred_card_title: "TRITURADOR CRIPTOGRÁFICO CSPRNG (SECURE WIPE)",
    drop_shred_title: "Arrastra o selecciona un archivo sensible para borrado seguro",
    drop_shred_sub: "Sobreescritura multi-paso con CSPRNG + Patrones complementarios + Truncamiento (mitigación best-effort en memorias flash con wear-leveling)",
    btn_execute_shred: "🌪️ EJECUTAR BORRADO SEGURO DEL ARCHIVO",

    // Guide Tab
    guide_hero_badge: "💡 GUÍA OFICIAL MIRAGEX",
    guide_hero_title: "¿No sabes por dónde empezar? ",
    guide_hero_title_hl: "Te guiamos paso a paso.",
    guide_hero_desc: "MirageX está diseñado para que cualquier persona pueda proteger sus documentos más valiosos con seguridad de grado militar y resistencia post-cuántica (NIST FIPS 203). Aquí aprenderás qué herramienta usar según lo que necesites hacer.",

    // Keyfile Modal
    kf_modal_title: "GENERADOR DE KEYFILE CRIPTOGRÁFICO",
    kf_modal_notice: "🛡️ CSPRNG + Entropía Física: Mueve el mouse sobre el sensor para cosechar entropía cuántica complementaria.",
    kf_lbl_harvest: "COSECHA DE ENTROPÍA DEL USUARIO:",
    kf_lbl_size: "TAMAÑO DEL KEYFILE",
    btn_cancel: "Cancelar",
    btn_save_kf: "💾 Guardar Keyfile en Disco",
  },

  en: {
    // Brand & HUD
    brand_sub: "POST-QUANTUM CRYPTOGRAPHIC ENGINE // WRAITH v4 FORMAT",
    status_algo: "ALGORITHM: MIRAGEX (NIST FIPS 203)",
    btn_quick_guide: "💡 QUICK START GUIDE",
    btn_updates: "🔄 UPDATES & CHANGELOG",
    btn_context_menu: "🖱️ OS CONTEXT MENU",
    status_zero_server: "ZERO-SERVER // NATIVE IPC",

    // Navigation Tabs
    nav_encrypt: "ENCRYPT",
    nav_decrypt: "DECRYPT",
    nav_vault: "VAULT",
    nav_watcher: "WATCHER",
    nav_inspect: "INSPECTOR",
    nav_benchmark: "BENCHMARK",
    nav_shred: "SHREDDER",
    nav_guide: "GUIDE & HELP",
    nav_beta: "BETA LABS",
    badge_new: "NEW",

    // Common
    btn_browse: "📂 Browse",
    btn_browse_kf: "📂 Browse",
    btn_gen_kf: "🎲 Generate Keyfile",
    btn_remove_kf: "Remove keyfile",
    ph_kf: "No keyfile (Optional: 2FA or Keyfile-only)...",

    // Encrypt Tab
    enc_origin_title: "DATA SOURCE & FILE",
    badge_single_file: "SINGLE FILE",
    lbl_cloud_backup_mode: "🗄️ Cloud Backup Mode (Restic/Borg)",
    drop_enc_title: "Drag & drop your file here",
    drop_enc_sub: "or click to open native file selector",
    lbl_enc_pass: "MASTER PROTECTION PASSWORD",
    ph_enc_pass: "Enter password for MirageX envelope...",
    btn_gen: "🎲 Generate",
    lbl_enc_kf: "SECURITY KEYFILE // VERACRYPT & ARCANUM STANDARD",
    hint_enc_kf: "CRC-32 IEEE 802.3 and modular addition mixing algorithm. Compatible with Arcanum and VeraCrypt.",
    card_suite_title: "MIRAGEX ALGORITHM SUITE",
    lbl_security_mode: "MIRAGEX SECURITY MODE",
    lbl_chunk_size: "STREAMING CHUNK SIZE",
    chk_name_fuzzing: "Name Fuzzing (Active by default)",
    hint_name_fuzzing: "🛡️ Zero metadata or filename leakage ([sha256].wraith). Restored upon decryption.",
    chk_shred_source: "Securely shred original file after encryption",
    lbl_disk_type: "STORAGE TYPE",
    lbl_passes: "PASSES",
    btn_start_encrypt: "🔒 START MIRAGEX ENCRYPTION",
    telemetry_title: "MIRAGEX CRYPTOGRAPHIC TELEMETRY",

    // Decrypt Tab
    dec_card_title: "WRAITH CONTAINER (.wraith)",
    drop_dec_title: "Drag & drop your .wraith file here",
    drop_dec_sub: "or click to browse disk",
    lbl_dec_pass: "AUTHENTICATION PASSWORD",
    ph_dec_pass: "Container decryption password...",
    lbl_dec_kf: "DECRYPTION KEYFILE",
    chk_shred_container: "Securely shred .wraith container after restoration",
    btn_start_decrypt: "🔓 DECAPSULATE & VERIFY WITH MIRAGEX",
    dec_authenticity_title: "AUTHENTICITY RESULT",
    dec_empty_text: "Waiting for container authentication to verify integrity.",

    // Vault Tab
    vault_create_title: "CREATE NEW ENCRYPTED VAULT",
    vault_create_drop: "Select Files for Vault",
    vault_create_drop_sub: "Or click «Add entire folder» to bundle a whole directory with ML-KEM + AES-256-GCM",
    btn_vault_add_folder: "📁 Add entire folder",
    lbl_vault_create_pass: "VAULT MASTER PASSWORD",
    ph_vault_create_pass: "Vault master password...",
    lbl_vault_create_kf: "VAULT KEYFILE",
    btn_execute_create_vault: "📦 CREATE & ENCRYPT VAULT ON DISK",
    vault_open_title: "UNLOCK EXISTING VAULT",
    vault_open_drop: "Select a .wvault or .wraith file",
    vault_open_drop_sub: "Open and browse the file tree without kernel drivers",
    lbl_vault_open_pass: "UNLOCK PASSWORD",
    ph_vault_open_pass: "Vault password...",
    lbl_vault_open_kf: "UNLOCK KEYFILE",
    btn_execute_open_vault: "🔓 UNLOCK & EXPLORE VAULT",
    btn_extract_all_vault: "📁 Extract All to Folder",
    btn_close_lock_vault: "🔒 Lock & Close Vault",
    ph_vault_search: "Search files inside vault...",

    // Watcher Tab
    watcher_badge_top: "👁️ REAL-TIME SURVEILLANCE ENGINE",
    watcher_badge_inactive: "⚪ INACTIVE",
    watcher_badge_active: "🟢 MONITORING LIVE",
    watcher_badge_ram: "🛡️ KEYS IN RAM",
    watcher_hero_title: "Watched Folder // ",
    watcher_hero_title_hl: "Continuous Auto-Encryption",
    watcher_hero_desc: "Every new or modified file saved in the watched folder is automatically streaming-encrypted into a .wraith container. Supports extension filtering, recursive mode, OS desktop notifications, secure shredding, and inactivity auto-lock.",
    watcher_dirs_title: "DIRECTORIES & SESSION SECURITY",
    watcher_lbl_watch_dir: "Watched Directory (Source Folder):",
    watcher_ph_watch_dir: "Select folder to monitor...",
    watcher_lbl_output_dir: "Encrypted Output Directory (.wraith):",
    watcher_ph_output_dir: "Select destination folder...",
    watcher_lbl_pass: "Password in Memory (Active Session):",
    watcher_ph_pass: "Password for auto-encryption...",
    watcher_lbl_algo: "Post-Quantum Algorithm:",
    lbl_watch_keyfile: "SECURITY KEYFILE",
    hint_watch_keyfile: "CRC-32 IEEE 802.3 and 64-byte modular addition mixing algorithm.",
    watcher_rules_title: "RULES & AUTOMATION",
    watcher_lbl_filter: "File Filter:",
    watcher_filter_all: "All files",
    watcher_filter_whitelist: "Extensions whitelist",
    watcher_lbl_timeout: "Inactivity Security Auto-Lock:",
    watcher_timeout_0: "Disabled (Keep session open)",
    watcher_timeout_5: "5 minutes without new files",
    watcher_timeout_15: "15 minutes (Recommended)",
    watcher_timeout_30: "30 minutes",
    watcher_timeout_60: "1 hour",
    watcher_chk_recursive: "Recursive surveillance (Monitor nested subfolders)",
    watcher_chk_notify: "Native OS desktop notifications",
    lbl_watch_shred: "Secure shredding of original file after encryption (Active by default)",
    btn_start_watcher: "▶️ START SURVEILLANCE",
    btn_stop_watcher: "⏹️ STOP SURVEILLANCE",
    watcher_audit_title: "AUDIT LOG & LIVE EVENTS",
    watcher_console_title: "REAL-TIME CONSOLE",
    watcher_status_waiting: "WAITING FOR CONFIGURATION",
    btn_export_csv: "📥 Export CSV",
    btn_export_jsonl: "📥 Export JSONL",

    // Inspector Tab
    inspect_card_title: "STRUCTURAL INSPECTION OF WRAITH HEADERS (ZERO-KNOWLEDGE)",
    drop_inspect_title: "Drag & drop a .wraith file for immediate inspection",
    drop_inspect_sub: "Reads suite metadata and UUID without requiring password or decrypting content",

    // Benchmark Tab
    bench_card_title: "MIRAGEX ALGORITHM PERFORMANCE BENCHMARK",
    btn_run_bench: "⚡ Run Stress Benchmark",
    bench_desc: "Evaluates post-quantum encapsulation speed (FIPS 203), Argon2id key derivation, and hardware-accelerated AES-256-GCM throughput.",

    // Shredder Tab
    shred_card_title: "CSPRNG CRYPTOGRAPHIC SHREDDER (SECURE WIPE)",
    drop_shred_title: "Drag or select a sensitive file for secure shredding",
    drop_shred_sub: "Multi-pass overwrite with CSPRNG + Complementary patterns + Truncation (best-effort mitigation on wear-leveling flash drives)",
    btn_execute_shred: "🌪️ SECURELY SHRED & DESTROY FILE",

    // Guide Tab
    guide_hero_badge: "💡 OFFICIAL MIRAGEX GUIDE",
    guide_hero_title: "Not sure where to start? ",
    guide_hero_title_hl: "We will guide you step by step.",
    guide_hero_desc: "MirageX is designed so anyone can protect their most valuable documents with military-grade security and post-quantum resistance (NIST FIPS 203). Here you will learn which tool to use for each need.",

    // Keyfile Modal
    kf_modal_title: "CRYPTOGRAPHIC KEYFILE GENERATOR",
    kf_modal_notice: "🛡️ CSPRNG + Physical Entropy: Move the mouse over the sensor to harvest complementary quantum entropy.",
    kf_lbl_harvest: "USER ENTROPY HARVEST:",
    kf_lbl_size: "KEYFILE SIZE",
    btn_cancel: "Cancel",
    btn_save_kf: "💾 Save Keyfile to Disk",
  }
};

function applyLanguage(lang) {
  const dict = I18N[lang] || I18N.es;
  document.documentElement.lang = lang;

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key] !== undefined) {
      el.textContent = dict[key];
    }
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (dict[key] !== undefined) {
      el.placeholder = dict[key];
    }
  });

  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    if (dict[key] !== undefined) {
      el.title = dict[key];
    }
  });

  const flagEl = document.getElementById('lang-flag');
  const textEl = document.getElementById('lang-text');
  if (flagEl && textEl) {
    if (lang === 'en') {
      flagEl.textContent = '🇺🇸';
      textEl.textContent = 'English';
    } else {
      flagEl.textContent = '🇲🇽';
      textEl.textContent = 'Español';
    }
  }
}

function setupLanguageLogic() {
  try {
    const saved = localStorage.getItem('miragex_lang');
    if (saved === 'en' || saved === 'es') {
      currentLang = saved;
    }
  } catch (e) {
    console.warn('localStorage read error', e);
  }

  applyLanguage(currentLang);

  const btnToggle = document.getElementById('btn-lang-toggle');
  if (btnToggle) {
    btnToggle.addEventListener('click', () => {
      currentLang = (currentLang === 'es') ? 'en' : 'es';
      try {
        localStorage.setItem('miragex_lang', currentLang);
      } catch (e) {
        console.warn('localStorage write error', e);
      }
      applyLanguage(currentLang);
    });
  }
}
