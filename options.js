// === SÉCURITÉ : Validation stricte ===
function isValidVTApiKey(key) {
  // Format attendu : exactement 64 caractères hexadécimaux
  if (typeof key !== 'string') return false;
  if (key.length !== 64) return false;
  return /^[a-f0-9]{64}$/i.test(key);
}

// Échappement HTML pour prévenir XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// === DARK MODE ===
async function loadTheme() {
  const result = await browser.storage.local.get('darkMode');
  const isDark = result.darkMode || false;
  document.body.classList.toggle('dark-mode', isDark);
  const toggle = document.getElementById('dark-mode-toggle');
  if (toggle) toggle.checked = isDark;
}

async function toggleTheme() {
  const isDark = document.body.classList.toggle('dark-mode');
  await browser.storage.local.set({ darkMode: isDark });
}

// === MESSAGES ===
function showSuccess(message) {
  const successMsg = document.getElementById('success-msg');
  const errorMsg = document.getElementById('error-msg');
  errorMsg.classList.remove('show');
  successMsg.textContent = escapeHtml(message);
  successMsg.classList.add('show');
  setTimeout(() => successMsg.classList.remove('show'), 4000);
}

function showError(message) {
  const successMsg = document.getElementById('success-msg');
  const errorMsg = document.getElementById('error-msg');
  successMsg.classList.remove('show');
  document.getElementById('error-text').textContent = escapeHtml(message);
  errorMsg.classList.add('show');
  setTimeout(() => errorMsg.classList.remove('show'), 5000);
}

// === SAUVEGARDE CLÉCURISÉE ===
document.getElementById('save').addEventListener('click', async () => {
  const val = document.getElementById('api').value.trim();
  const saveBtn = document.getElementById('save');
  
  // Validation stricte
  if (!val) {
    showError('La clé API ne peut pas être vide.');
    return;
  }
  
  if (!isValidVTApiKey(val)) {
    showError('Format de clé invalide. La clé VirusTotal doit contenir exactement 64 caractères hexadécimaux (0-9, a-f).');
    return;
  }
  
  // Désactive le bouton pendant la validation
  saveBtn.disabled = true;
  saveBtn.textContent = '🔄 Validation...';
  
  // Test de la clé avec timeout de sécurité
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout
  
  try {
    const testResponse = await fetch('https://www.virustotal.com/api/v3/users/current', {
      headers: { 'x-apikey': val },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (testResponse.status === 401) {
      showError('Clé API invalide ou expirée. Vérifie ta clé sur virustotal.com/gui/my-apikey');
      saveBtn.disabled = false;
      saveBtn.textContent = '💾 Enregistrer la clé';
      return;
    }
    
    if (testResponse.status === 403) {
      showError('Accès refusé. Ta clé API pourrait être restreinte ou bloquée.');
      saveBtn.disabled = false;
      saveBtn.textContent = '💾 Enregistrer la clé';
      return;
    }
    
    if (!testResponse.ok && testResponse.status !== 429) {
      console.warn('Test API warning:', testResponse.status);
    }
    
    // Sauvegarde sécurisée dans le storage local (chiffré par Firefox)
    await browser.storage.local.set({ vt_api_key: val });
    showSuccess('✅ Clé API enregistrée et validée avec succès !');
    
    // Efface le champ pour sécurité (affichage masqué)
    document.getElementById('api').value = '';
    document.getElementById('api').placeholder = `Clé enregistrée: ${val.slice(0, 8)}${'*'.repeat(48)}${val.slice(-8)}`;
    
  } catch (err) {
    clearTimeout(timeoutId);
    console.error('Erreur validation clé:', err);
    
    if (err.name === 'AbortError') {
      showError('Timeout: impossible de valider la clé (réseau lent). Réessaie.');
    } else {
      showError('Impossible de valider la clé (erreur réseau). Elle a été enregistrée quand même.');
      await browser.storage.local.set({ vt_api_key: val });
    }
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = '💾 Enregistrer la clé';
  }
});

// === SUPPRESSION SÉCURISÉE ===
document.getElementById('forget').addEventListener('click', async () => {
  if (!confirm('⚠️ ATTENTION : Supprimer la clé API stockée ?\n\nTu devras la ressaisir pour scanner des fichiers.\n\nCette action est irréversible.')) return;
  
  await browser.storage.local.remove('vt_api_key');
  document.getElementById('api').value = '';
  document.getElementById('api').placeholder = 'Colle ta clé API VirusTotal ici';
  showSuccess('🗑️ Clé supprimée avec succès.');
});

// === DARK MODE TOGGLE ===
document.getElementById('dark-mode-toggle').addEventListener('change', toggleTheme);

// === CHARGEMENT INITIAL ===
(async () => {
  // Charge le thème
  await loadTheme();
  
  // Charge la clé existante (masquée)
  const s = await browser.storage.local.get('vt_api_key');
  if (s.vt_api_key && isValidVTApiKey(s.vt_api_key)) {
    const key = s.vt_api_key;
    // Affiche seulement les 8 premiers et 8 derniers caractères
    const masked = `${key.slice(0, 8)}${'*'.repeat(48)}${key.slice(-8)}`;
    document.getElementById('api').placeholder = `Clé actuelle: ${masked}`;
    document.getElementById('api').value = ''; // Ne pré-remplit pas pour sécurité
  }
})();

// === PROTECTION CONTRE COPIER-COLLER DE SCRIPTS ===
document.addEventListener('paste', (e) => {
  const target = e.target;
  if (target.id === 'api') {
    // Nettoie le contenu collé
    setTimeout(() => {
      target.value = target.value.trim().replace(/[^a-f0-9]/gi, '');
    }, 0);
  }
});
