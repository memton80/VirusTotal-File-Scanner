// === i18n Helper ===
function t(key) {
  return browser.i18n.getMessage(key) || key;
}

function translatePage() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const translation = t(key);
    
    if (el.tagName === 'INPUT' && el.type === 'text') {
      el.placeholder = translation;
    } else {
      el.textContent = translation;
    }
  });
  
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    el.title = t(key);
  });
  
  document.title = t('optionsTitle');
}

// === SÉCURITÉ : Validation ===
function isValidVTApiKey(key) {
  if (typeof key !== 'string') return false;
  if (key.length !== 64) return false;
  return /^[a-f0-9]{64}$/i.test(key);
}

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

// === SAUVEGARDE CLÉ ===
document.getElementById('save').addEventListener('click', async () => {
  const val = document.getElementById('api').value.trim();
  const saveBtn = document.getElementById('save');
  const saveBtnSpan = saveBtn.querySelector('span');
  
  if (!val) {
    showError(t('errorApiKeyEmpty'));
    return;
  }
  
  if (!isValidVTApiKey(val)) {
    showError(t('errorApiKeyInvalid'));
    return;
  }
  
  saveBtn.disabled = true;
  saveBtnSpan.textContent = t('btnValidating');
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  
  try {
    const testResponse = await fetch('https://www.virustotal.com/api/v3/users/current', {
      headers: { 'x-apikey': val },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (testResponse.status === 401) {
      showError(t('errorApiKeyUnauthorized'));
      saveBtn.disabled = false;
      saveBtnSpan.textContent = t('btnSaveKey');
      return;
    }
    
    if (testResponse.status === 403) {
      showError(t('errorApiKeyForbidden'));
      saveBtn.disabled = false;
      saveBtnSpan.textContent = t('btnSaveKey');
      return;
    }
    
    if (!testResponse.ok && testResponse.status !== 429) {
      console.warn('Test API warning:', testResponse.status);
    }
    
    await browser.storage.local.set({ vt_api_key: val });
    showSuccess(t('successApiKeySaved'));
    
    document.getElementById('api').value = '';
    document.getElementById('api').placeholder = `${t('placeholderApiKeySaved')}: ${val.slice(0, 8)}${'*'.repeat(48)}${val.slice(-8)}`;
    
  } catch (err) {
    clearTimeout(timeoutId);
    console.error('Erreur validation clé:', err);
    
    if (err.name === 'AbortError') {
      showError(t('errorApiKeyTimeout'));
    } else {
      showError(t('errorApiKeyNetwork'));
      await browser.storage.local.set({ vt_api_key: val });
    }
  } finally {
    saveBtn.disabled = false;
    saveBtnSpan.textContent = t('btnSaveKey');
  }
});

// === SUPPRESSION CLÉMECURISÉE ===
document.getElementById('forget').addEventListener('click', async () => {
  if (!confirm(t('confirmDeleteKey'))) return;
  
  await browser.storage.local.remove('vt_api_key');
  document.getElementById('api').value = '';
  document.getElementById('api').placeholder = t('placeholderApiKey');
  showSuccess(t('successApiKeyDeleted'));
});

// === DARK MODE TOGGLE ===
document.getElementById('dark-mode-toggle').addEventListener('change', toggleTheme);

// === CHARGEMENT INITIAL ===
(async () => {
  translatePage();
  await loadTheme();
  
  const s = await browser.storage.local.get('vt_api_key');
  if (s.vt_api_key && isValidVTApiKey(s.vt_api_key)) {
    const key = s.vt_api_key;
    const masked = `${key.slice(0, 8)}${'*'.repeat(48)}${key.slice(-8)}`;
    document.getElementById('api').placeholder = `${t('placeholderApiKeyCurrent')}: ${masked}`;
    document.getElementById('api').value = '';
  }
})();

// === PROTECTION COPIER-COLLER ===
document.addEventListener('paste', (e) => {
  const target = e.target;
  if (target.id === 'api') {
    setTimeout(() => {
      target.value = target.value.trim().replace(/[^a-f0-9]/gi, '');
    }, 0);
  }
});