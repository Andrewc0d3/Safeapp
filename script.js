/* script.js: lógica de generación, cifrado y almacenamiento.
   Comentarios en cada bloque para que puedas seguirlo. */

/* ---------- Utiles de DOM ---------- */
const lengthEl = document.getElementById('length');
const lengthLabel = document.getElementById('lengthLabel');
const lowerEl = document.getElementById('lower');
const upperEl = document.getElementById('upper');
const numbersEl = document.getElementById('numbers');
const symbolsEl = document.getElementById('symbols');
const generatedEl = document.getElementById('generated');
const generateBtn = document.getElementById('generateBtn');
const copyBtn = document.getElementById('copyBtn');
const saveBtn = document.getElementById('saveBtn');
const entryNameEl = document.getElementById('entryName');
const entryUserEl = document.getElementById('entryUser');
const entriesEl = document.getElementById('entries');

const modal = document.getElementById('modal');
const masterInput = document.getElementById('masterInput');
const modalOk = document.getElementById('modalOk');
const modalCancel = document.getElementById('modalCancel');
const modalTitle = document.getElementById('modalTitle');
const modalMsg = document.getElementById('modalMsg');

const exportBtn = document.getElementById('exportBtn');
const importFile = document.getElementById('importFile');

/* ---------- Actualización UI ---------- */
lengthEl.addEventListener('input', () => lengthLabel.textContent = lengthEl.value);

/* ---------- Generador de contraseñas ---------- */
function generatePassword(length, opts) {
  // Construir el set de caracteres según opciones
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const nums = '0123456789';
  const syms = '!@#$%^&*()-_=+[]{};:,.<>?/~`|';

  let charset = '';
  if (opts.lower) charset += lower;
  if (opts.upper) charset += upper;
  if (opts.numbers) charset += nums;
  if (opts.symbols) charset += syms;
  if (!charset) return '';

  // Generación con crypto.getRandomValues para mayor entropía
  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  let pw = '';
  for (let i = 0; i < length; i++) {
    pw += charset[array[i] % charset.length];
  }
  return pw;
}

/* ---------- Eventos botones generar y copiar ---------- */
generateBtn.addEventListener('click', () => {
  const length = parseInt(lengthEl.value, 10);
  const opts = {
    lower: lowerEl.checked,
    upper: upperEl.checked,
    numbers: numbersEl.checked,
    symbols: symbolsEl.checked
  };
  const pw = generatePassword(length, opts);
  generatedEl.value = pw;
});

copyBtn.addEventListener('click', async () => {
  if (!generatedEl.value) return;
  try {
    await navigator.clipboard.writeText(generatedEl.value);
    copyBtn.textContent = '✓ Copiado';
    setTimeout(() => copyBtn.textContent = 'Copiar', 1500);
  } catch (e) {
    alert('No se pudo copiar: ' + e.message);
  }
});

/* ---------- Almacenamiento cifrado en localStorage ---------- */
/* Clave para localStorage */
const STORAGE_KEY = 'pwstore_v1';

/* Funciones de Web Crypto para derivar clave y cifrar/descifrar. */

/**
 * Deriva una clave AES-GCM desde una contraseña con PBKDF2.
 * - password: string
 * - salt: Uint8Array
 * - iterations: number (ej. 200000)
 * Retorna CryptoKey.
 */
async function deriveKey(password, salt, iterations = 200000) {
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const key = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return key;
}

/**
 * Cifra un objeto JS y devuelve {cipher, iv, salt} en base64.
 */
async function encryptObject(obj, masterPassword) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(masterPassword, salt);

  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(obj));
  const cipherBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );

  // convertir a base64 para almacenar en localStorage
  return {
    cipher: arrayBufferToBase64(cipherBuf),
    iv: arrayBufferToBase64(iv.buffer),
    salt: arrayBufferToBase64(salt.buffer)
  };
}

/**
 * Descifra y devuelve el objeto original.
 */
async function decryptObject(cipherB64, ivB64, saltB64, masterPassword) {
  const iv = base64ToUint8Array(ivB64);
  const salt = base64ToUint8Array(saltB64);
  const key = await deriveKey(masterPassword, salt);

  const cipherBuf = base64ToArrayBuffer(cipherB64);
  const plainBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    cipherBuf
  );
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(plainBuf));
}

/* ---------- Helpers base64/arraybuffer ---------- */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function base64ToUint8Array(base64) {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

/* ---------- Manipulación del "almacén" ---------- */
/* Obtener lista (array) de entradas desde localStorage (sin descifrar). */
function loadStoreRaw() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch (e) {
    console.error('Error parseando almacenamiento:', e);
    return [];
  }
}

/* Guardar lista (array) en localStorage */
function saveStoreRaw(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

/* Añadir una nueva entrada: recibe objeto ya cifrado (cipher, iv, salt) y metadatos */
function addEntryCiph(meta) {
  const list = loadStoreRaw();
  const id = crypto.randomUUID();
  list.unshift({ id, ...meta, createdAt: new Date().toISOString() });
  saveStoreRaw(list);
  renderEntries();
}

/* Borrar por id */
function deleteEntry(id) {
  const list = loadStoreRaw().filter(e => e.id !== id);
  saveStoreRaw(list);
  renderEntries();
}

/* ---------- Interacción para guardar (pide contraseña maestra) ---------- */
saveBtn.addEventListener('click', () => {
  const name = entryNameEl.value.trim();
  if (!name) return alert('Dale un nombre a la entrada (ej. Gmail).');

  const username = entryUserEl.value.trim();
  const password = generatedEl.value || prompt('Introduce la contraseña (o genera una primero):');
  if (!password) return;

  // Abrimos modal para pedir contraseña maestra y luego cifrar y guardar.
  openModal({
    title: 'Guardar entrada',
    msg: `Vas a cifrar y guardar la entrada "${name}". Introduce una contraseña maestra para protegerla.`,
    onConfirm: async (master) => {
      try {
        // construimos objeto a cifrar
        const obj = { name, username, password };
        const ciph = await encryptObject(obj, master);
        addEntryCiph({
          label: name,
          user: username,
          cipher: ciph.cipher,
          iv: ciph.iv,
          salt: ciph.salt
        });
        entryNameEl.value = '';
        entryUserEl.value = '';
        generatedEl.value = '';
      } catch (e) {
        alert('Error al cifrar/guardar: ' + e.message);
      }
    }
  });
});

/* ---------- Modal (simple) para pedir contraseña maestra ---------- */
let modalCallback = null;
function openModal({ title = 'Contraseña maestra', msg = '', onConfirm = null }) {
  modalTitle.textContent = title;
  modalMsg.textContent = msg;
  masterInput.value = '';
  modal.classList.remove('hidden');
  masterInput.focus();
  modalCallback = onConfirm;
}
function closeModal() {
  modal.classList.add('hidden');
  modalCallback = null;
}

modalOk.addEventListener('click', () => {
  const val = masterInput.value;
  if (!val) return alert('Introduce la contraseña maestra.');
  if (modalCallback) modalCallback(val);
  closeModal();
});
modalCancel.addEventListener('click', () => closeModal());

/* ---------- Renderizado de entradas ---------- */
function renderEntries() {
  entriesEl.innerHTML = '';
  const list = loadStoreRaw();
  if (!list.length) {
    entriesEl.innerHTML = '<p class="muted small">No hay entradas guardadas.</p>';
    return;
  }

  for (const e of list) {
    const el = document.createElement('div');
    el.className = 'entry';
    el.innerHTML = `
      <div class="left">
        <div class="meta">
          <strong>${escapeHtml(e.label)}</strong><br />
          <small class="muted">${escapeHtml(e.user || '')}</small>
        </div>
      </div>
      <div class="actions">
        <button class="viewBtn" data-id="${e.id}">Ver</button>
        <button class="copyBtn" data-id="${e.id}">Copiar</button>
        <button class="delBtn" data-id="${e.id}">Eliminar</button>
      </div>
    `;
    entriesEl.appendChild(el);
  }

  // eventos delegados
  entriesEl.querySelectorAll('.viewBtn').forEach(b => b.addEventListener('click', onView));
  entriesEl.querySelectorAll('.copyBtn').forEach(b => b.addEventListener('click', onCopy));
  entriesEl.querySelectorAll('.delBtn').forEach(b => b.addEventListener('click', onDelete));
}

/* Escape básico para mostrar texto seguro en HTML */
function escapeHtml(s) {
  return (s || '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
}

/* Acciones: ver, copiar, eliminar */
async function onView(evt) {
  const id = evt.target.dataset.id;
  const entry = loadStoreRaw().find(x => x.id === id);
  if (!entry) return alert('Entrada no encontrada.');
  openModal({
    title: `Ver "${entry.label}"`,
    msg: `Introduce la contraseña maestra para descifrar "${entry.label}".`,
    onConfirm: async (master) => {
      try {
        const data = await decryptObject(entry.cipher, entry.iv, entry.salt, master);
        alert(`Nombre: ${data.name}\nUsuario: ${data.username || '(vacío)'}\nContraseña: ${data.password}`);
      } catch (e) {
        alert('No se pudo descifrar: contraseña maestra incorrecta o datos corruptos.');
      }
    }
  });
}

async function onCopy(evt) {
  const id = evt.target.dataset.id;
  const entry = loadStoreRaw().find(x => x.id === id);
  if (!entry) return alert('Entrada no encontrada.');
  openModal({
    title: `Copiar "${entry.label}"`,
    msg: `Introduce la contraseña maestra para copiar la contraseña al portapapeles.`,
    onConfirm: async (master) => {
      try {
        const data = await decryptObject(entry.cipher, entry.iv, entry.salt, master);
        await navigator.clipboard.writeText(data.password);
        alert('Contraseña copiada al portapapeles.');
      } catch (e) {
        alert('No se pudo descifrar y copiar: contraseña maestra incorrecta o datos corruptos.');
      }
    }
  });
}

function onDelete(evt) {
  const id = evt.target.dataset.id;
  if (!confirm('¿Eliminar esta entrada? Esta acción no se puede deshacer.')) return;
  deleteEntry(id);
}

/* ---------- Exportar / importar ---------- */
/* Exportará el JSON tal cual está en localStorage (ya cifrado). */
exportBtn.addEventListener('click', () => {
  const raw = localStorage.getItem(STORAGE_KEY) || '[]';
  const blob = new Blob([raw], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'pwstore_export.json';
  a.click();
  URL.revokeObjectURL(url);
});

/* Import: reemplaza el almacén si el archivo es válido JSON */
importFile.addEventListener('change', async (evt) => {
  const file = evt.target.files[0];
  if (!file) return;
  const txt = await file.text();
  try {
    const parsed = JSON.parse(txt);
    if (!Array.isArray(parsed)) throw new Error('Formato inválido');
    if (!confirm('Importar reemplazará tu almacenamiento local actual. ¿Continuar?')) return;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
    renderEntries();
    alert('Importado correctamente.');
  } catch (e) {
    alert('Archivo inválido: ' + e.message);
  } finally {
    importFile.value = '';
  }
});

/* ---------- Inicialización ---------- */
renderEntries();
// Generar inicialmente para tener un ejemplo
generatedEl.value = generatePassword(parseInt(lengthEl.value, 10), {
  lower: true, upper: true, numbers: true, symbols: true
});
