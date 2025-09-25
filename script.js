// script.js: guarda y lista contraseñas en localStorage (sin cifrado)

// Elementos del DOM
const form = document.getElementById('passwordForm');
const siteInput = document.getElementById('site');
const userInput = document.getElementById('username');
const passInput = document.getElementById('password');
const listDiv = document.getElementById('passwordList');

// Clave en localStorage
const STORAGE_KEY = 'simple_passwords';

// Cargar al iniciar
document.addEventListener('DOMContentLoaded', renderList);

// Manejar envío de formulario
form.addEventListener('submit', e => {
  e.preventDefault();

  const entry = {
    site: siteInput.value.trim(),
    user: userInput.value.trim(),
    pass: passInput.value.trim()
  };

  if (!entry.site || !entry.user || !entry.pass) {
    alert('Todos los campos son obligatorios');
    return;
  }

  const data = getPasswords();
  data.push(entry);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));

  form.reset();
  renderList();
});

// Obtener array de contraseñas guardadas
function getPasswords() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : [];
}

// Eliminar una contraseña
function deletePassword(index) {
  const data = getPasswords();
  data.splice(index, 1);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  renderList();
}

// Pintar la lista en la página
function renderList() {
  const data = getPasswords();
  listDiv.innerHTML = '';

  if (data.length === 0) {
    listDiv.innerHTML = '<p>No hay contraseñas guardadas.</p>';
    return;
  }

  data.forEach((item, i) => {
    const div = document.createElement('div');
    div.className = 'password-item';

    const info = document.createElement('span');
    info.textContent = `${item.site} — ${item.user} — ${item.pass}`;

    const delBtn = document.createElement('button');
    delBtn.textContent = 'Eliminar';
    delBtn.addEventListener('click', () => deletePassword(i));

    div.appendChild(info);
    div.appendChild(delBtn);
    listDiv.appendChild(div);
  });
}
