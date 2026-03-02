// === Options - Page de configuration ===

// === MESSAGES ===
function showSuccess(message) {
  const successMsg = document.getElementById('success-msg');
  const errorMsg = document.getElementById('error-msg');
  errorMsg.classList.remove('show');
  successMsg.textContent = VTUtils.escapeHtml(message);
  successMsg.classList.add('show');
  setTimeout(() => successMsg.classList.remove('show'), 4000);
}

function showError(message) {
  const successMsg = document.getElementById('success-msg');
  const errorMsg = document.getElementById('error-msg');
  successMsg.classList.remove('show');
  document.getElementById('error-text').textContent = VTUtils.escapeHtml(message);
  errorMsg.classList.add('show');
  setTimeout(() => errorMsg.classList.remove('show'), 5000);
}

// === Event Listeners ===
document.addEventListener('DOMContentLoaded', () => {
  console.log('[options.js] DOM chargé');
  
  // === SAUVEGARDE CLÉ ===
  const saveBtn = document.getElementById('save');
  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      const val = document.getElementById('api').value.trim();
      const saveBtnEl = document.getElementById('save');
      const saveBtnSpan = saveBtnEl.querySelector('span');
      
      if (!val) {
        showError(VTUtils.t('errorApiKeyEmpty'));
        return;
      }
      
      if (!VTUtils.isValidApiKey(val)) {
        showError(VTUtils.t('errorApiKeyInvalid'));
        return;
      }
      
      saveBtnEl.disabled = true;
      saveBtnSpan.textContent = VTUtils.t('btnValidating');
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      
      try {
        const testResponse = await fetch('https://www.virustotal.com/api/v3/users/current', {
          headers: { 'x-apikey': val },
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (testResponse.status === 401) {
          showError(VTUtils.t('errorApiKeyUnauthorized'));
          saveBtnEl.disabled = false;
          saveBtnSpan.textContent = VTUtils.t('btnSaveKey');
          return;
        }
        
        if (testResponse.status === 403) {
          showError(VTUtils.t('errorApiKeyForbidden'));
          saveBtnEl.disabled = false;
          saveBtnSpan.textContent = VTUtils.t('btnSaveKey');
          return;
        }
        
        if (!testResponse.ok && testResponse.status !== 429) {
          console.warn('Test API warning:', testResponse.status);
        }
        
        await browser.storage.local.set({ vt_api_key: val });
        showSuccess(VTUtils.t('successApiKeySaved'));
        
        document.getElementById('api').value = '';
        const masked = `${val.slice(0, 8)}${'*'.repeat(48)}${val.slice(-8)}`;
        document.getElementById('api').placeholder = `${VTUtils.t('placeholderApiKeySaved')}: ${masked}`;
        
      } catch (err) {
        clearTimeout(timeoutId);
        console.error('Erreur validation clé:', err);
        
        if (err.name === 'AbortError') {
          showError(VTUtils.t('errorApiKeyTimeout'));
        } else {
          showError(VTUtils.t('errorApiKeyNetwork'));
          await browser.storage.local.set({ vt_api_key: val });
        }
      } finally {
        saveBtnEl.disabled = false;
        saveBtnSpan.textContent = VTUtils.t('btnSaveKey');
      }
    });
  }

  // === SUPPRESSION CLÉ ===
  const forgetBtn = document.getElementById('forget');
  if (forgetBtn) {
    forgetBtn.addEventListener('click', async () => {
      if (!confirm(VTUtils.t('confirmDeleteKey'))) return;
      
      await browser.storage.local.remove('vt_api_key');
      document.getElementById('api').value = '';
      document.getElementById('api').placeholder = VTUtils.t('placeholderApiKey');
      showSuccess(VTUtils.t('successApiKeyDeleted'));
    });
  }

  // === DARK MODE TOGGLE ===
  const darkModeToggle = document.getElementById('dark-mode-toggle');
  if (darkModeToggle) {
    darkModeToggle.addEventListener('change', () => {
      VTUtils.toggleTheme();
    });
  }

  // === CHARGEMENT INITIAL ===
  (async () => {
    try {
      VTUtils.translatePage();
      await VTUtils.loadTheme();
      
      const toggle = document.getElementById('dark-mode-toggle');
      if (toggle) toggle.checked = document.body.classList.contains('dark-mode');
      
      const s = await browser.storage.local.get('vt_api_key');
      if (s.vt_api_key && VTUtils.isValidApiKey(s.vt_api_key)) {
        const key = s.vt_api_key;
        const masked = `${key.slice(0, 8)}${'*'.repeat(48)}${key.slice(-8)}`;
        document.getElementById('api').placeholder = `${VTUtils.t('placeholderApiKeyCurrent')}: ${masked}`;
        document.getElementById('api').value = '';
      }
    } catch (e) {
      console.error('Erreur init options:', e);
    }
  })();
});

// === PROTECTION COPIER-COLLER ===
document.addEventListener('paste', (e) => {
  const target = e.target;
  if (target.id === 'api') {
    setTimeout(() => {
      target.value = target.value.trim().replace(/[^a-f0-9]/gi, '');
    }, 0);
  }
});

// === ONBOARDING GUIDE - PREMIÈRE INSTALLATION ===
(function initOnboarding() {
  const overlay = document.getElementById('onboarding-overlay');
  const step1 = document.getElementById('onboarding-step-1');
  const step2 = document.getElementById('onboarding-step-2');
  const step3 = document.getElementById('onboarding-step-3');
  const highlightDark = document.getElementById('highlight-darkmode');
  const highlightApi = document.getElementById('highlight-apikey');
  const highlightHowto = document.getElementById('highlight-howto');
  const btnNext1 = document.getElementById('onboarding-next-1');
  const btnNext2 = document.getElementById('onboarding-next-2');
  const btnPrev2 = document.getElementById('onboarding-prev-2');
  const btnPrev3 = document.getElementById('onboarding-prev-3');
  const btnFinish = document.getElementById('onboarding-finish');
  const btnSkip = document.getElementById('onboarding-skip');
  
  if (!overlay || !step1 || !step2) return;
  
  // Vérifier si c'est la première installation
  browser.storage.local.get(['first_install']).then((result) => {
    if (result.first_install === true) {
      console.log('[Onboarding] Première installation détectée, affichage du guide...');
      showOnboarding();
    }
  }).catch(err => {
    console.error('[Onboarding] Erreur:', err);
  });
  
  function showOnboarding() {
    overlay.classList.add('active');
    positionHighlights();
    
    // Mettre à jour les textes traduits
    const translatableElements = overlay.querySelectorAll('[data-i18n]');
    translatableElements.forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (VTUtils && VTUtils.t) {
        el.textContent = VTUtils.t(key);
      }
    });
    
    // Observer les redimensionnements
    window.addEventListener('resize', positionHighlights);
    window.addEventListener('scroll', positionHighlights);
  }
  
  function positionHighlights() {
    // Positionner le highlight sur le dark mode
    const darkModeCard = document.querySelector('.card:has(#dark-mode-toggle)');
    if (darkModeCard && highlightDark) {
      const rect = darkModeCard.getBoundingClientRect();
      highlightDark.style.top = (rect.top - 8) + 'px';
      highlightDark.style.left = (rect.left - 8) + 'px';
      highlightDark.style.width = (rect.width + 16) + 'px';
      highlightDark.style.height = (rect.height + 16) + 'px';
    }
    
    // Positionner le highlight sur la clé API
    const apiKeyCard = document.querySelector('.card:has(#api)');
    if (apiKeyCard && highlightApi) {
      const rect = apiKeyCard.getBoundingClientRect();
      highlightApi.style.top = (rect.top - 8) + 'px';
      highlightApi.style.left = (rect.left - 8) + 'px';
      highlightApi.style.width = (rect.width + 16) + 'px';
      highlightApi.style.height = (rect.height + 16) + 'px';
    }
    
    // Positionner le highlight sur "Comment obtenir une clé API"
    const howtoCard = document.querySelector('.info-box:has(a[href*="virustotal.com"])');
    if (howtoCard && highlightHowto) {
      const rect = howtoCard.getBoundingClientRect();
      highlightHowto.style.top = (rect.top - 8) + 'px';
      highlightHowto.style.left = (rect.left - 8) + 'px';
      highlightHowto.style.width = (rect.width + 16) + 'px';
      highlightHowto.style.height = (rect.height + 16) + 'px';
    }
  }
  
  function hideOnboarding() {
    overlay.classList.remove('active');
    // Marquer le guide comme terminé
    browser.storage.local.set({ first_install: false });
    window.removeEventListener('resize', positionHighlights);
    window.removeEventListener('scroll', positionHighlights);
  }
  
  // Navigation
  if (btnNext1) {
    btnNext1.addEventListener('click', () => {
      step1.style.display = 'none';
      step2.style.display = 'block';
      positionHighlights();
      
      // Scroll vers la section "Comment obtenir une clé"
      const howtoCard = document.querySelector('.info-box:has(a[href*="virustotal.com"])');
      if (howtoCard) {
        howtoCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }
  
  if (btnNext2) {
    btnNext2.addEventListener('click', () => {
      step2.style.display = 'none';
      step3.style.display = 'block';
      positionHighlights();
      
      // Scroll vers la section API
      const apiKeyCard = document.querySelector('.card:has(#api)');
      if (apiKeyCard) {
        apiKeyCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }
  
  if (btnPrev2) {
    btnPrev2.addEventListener('click', () => {
      step2.style.display = 'none';
      step1.style.display = 'block';
      positionHighlights();
      
      // Scroll vers le dark mode
      const darkModeCard = document.querySelector('.card:has(#dark-mode-toggle)');
      if (darkModeCard) {
        darkModeCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }
  
  if (btnPrev3) {
    btnPrev3.addEventListener('click', () => {
      step3.style.display = 'none';
      step2.style.display = 'block';
      positionHighlights();
      
      // Scroll vers la section "Comment obtenir une clé"
      const howtoCard = document.querySelector('.info-box:has(a[href*="virustotal.com"])');
      if (howtoCard) {
        howtoCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }
  
  if (btnFinish) {
    btnFinish.addEventListener('click', () => {
      hideOnboarding();
      
      // Focus sur le champ API
      const apiInput = document.getElementById('api');
      if (apiInput) {
        setTimeout(() => apiInput.focus(), 300);
      }
    });
  }
  
  if (btnSkip) {
    btnSkip.addEventListener('click', hideOnboarding);
  }
  
  // Ré-positionner après un court délai pour permettre le rendu
  setTimeout(positionHighlights, 100);
  setTimeout(positionHighlights, 500);
})();
