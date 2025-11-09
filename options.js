// Validation de la clé API VirusTotal
function isValidVTApiKey(key) {
  // Format attendu : 64 caractères hexadécimaux
  return /^[a-f0-9]{64}$/i.test(key);
}

function showSuccess(message) {
  const successMsg = document.getElementById('success-msg');
  const errorMsg = document.getElementById('error-msg');
  errorMsg.classList.remove('show');
  successMsg.textContent = message;
  successMsg.classList.add('show');
  setTimeout(() => successMsg.classList.remove('show'), 4000);
}

function showError(message) {
  const successMsg = document.getElementById('success-msg');
  const errorMsg = document.getElementById('error-msg');
  successMsg.classList.remove('show');
  document.getElementById('error-text').textContent = message;
  errorMsg.classList.add('show');
  setTimeout(() => errorMsg.classList.remove('show'), 5000);
}

document.getElementById('save').addEventListener('click', async () => {
  const val = document.getElementById('api').value.trim();
  const saveBtn = document.getElementById('save');
  
  // Validation
  if (!val) {
    showError('La clé API ne peut pas être vide.');
    return;
  }
  
  if (!isValidVTApiKey(val)) {
    showError('Format de clé invalide. La clé VirusTotal doit contenir 64 caractères hexadécimaux.');
    return;
  }
  
  // Désactive le bouton pendant la validation
  saveBtn.disabled = true;
  saveBtn.textContent = '🔄 Validation...';
  
  // Test de la clé avec un appel simple
  try {
    const testResponse = await fetch('https://www.virustotal.com/api/v3/users/current', {
      headers: { 'x-apikey': val }
    });
    
    if (testResponse.status === 401) {
      showError('Clé API invalide ou expirée. Vérifie ta clé sur virustotal.com/gui/my-apikey');
      saveBtn.disabled = false;
      saveBtn.textContent = '💾 Enregistrer la clé';
      return;
    }
    
    if (!testResponse.ok && testResponse.status !== 429) { // Ignore rate limit pour validation
      console.warn('Test API warning:', testResponse.status);
    }
    
    await browser.storage.local.set({ vt_api_key: val });
    showSuccess('✅ Clé API enregistrée et validée avec succès !');
    
  } catch (err) {
    console.error('Erreur validation clé:', err);
    showError('Impossible de valider la clé (erreur réseau). Elle a été enregistrée quand même.');
    await browser.storage.local.set({ vt_api_key: val });
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = '💾 Enregistrer la clé';
  }
});

document.getElementById('forget').addEventListener('click', async () => {
  if (!confirm('Supprimer la clé API stockée ?\n\nTu devras la ressaisir pour scanner des fichiers.')) return;
  
  await browser.storage.local.remove('vt_api_key');
  document.getElementById('api').value = '';
  alert('🗑️ Clé supprimée.');
});

// Chargement de la clé existante (masquée partiellement)
(async () => {
  const s = await browser.storage.local.get('vt_api_key');
  if (s.vt_api_key) {
    // Affiche seulement les 8 premiers et 8 derniers caractères
    const key = s.vt_api_key;
    const masked = key.length > 16 
      ? `${key.slice(0, 8)}${'*'.repeat(48)}${key.slice(-8)}`
      : '*'.repeat(key.length);
    
    document.getElementById('api').value = key; // Affiche en clair pour modification
    document.getElementById('api').placeholder = `Clé actuelle: ${masked}`;
  }
})();
