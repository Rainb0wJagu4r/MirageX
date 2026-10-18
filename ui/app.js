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

  // Encrypt Button
  document.getElementById('btn-start-encrypt').addEventListener('click', async () => {
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
      });

      progressFill.style.width = '100%';
      document.getElementById('encrypt-speed').textContent = `Listo en ${res.elapsed_ms} ms`;
      showToast(`¡Cifrado MirageX exitoso! Creado: ${res.output_path}`, 'success');
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
    document.getElementById('decrypt-password').focus();
    showToast(`Contenedor cargado desde menú contextual: ${fileName}`, 'success');
  } else {
    // Switch to Encrypt tab
    document.querySelector('.nav-tab[data-tab="encrypt"]')?.click();
    selectedEncryptPath = fullPath;
    document.getElementById('meta-encrypt-name').textContent = fileName;
    document.getElementById('meta-encrypt-path').textContent = fullPath;
    document.getElementById('meta-encrypt-size').textContent = fileSize ? formatBytes(fileSize) : 'Detectado por menú contextual';
    document.getElementById('encrypt-file-meta').style.display = 'flex';
    document.getElementById('encrypt-password').focus();
    showToast(`Archivo listo para cifrar desde menú contextual: ${fileName}`, 'success');
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
              lblMessage.textContent = `Estás en la versión local v${checkRes.current_version}. (${checkRes.error})`;
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
}

