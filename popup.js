// === i18n Helper ===
function t(key) {
  return browser.i18n.getMessage(key) || key;
}

function translatePage() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    el.textContent = t(key);
  });
  
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    el.title = t(key);
  });
  
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    el.placeholder = t(key);
  });
}

// === SÉCURITÉ : Échappement HTML ===
function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(text);
  return div.innerHTML;
}

function sanitizeNumber(value, defaultValue = 0) {
  const num = parseInt(value, 10);
  return isNaN(num) ? defaultValue : Math.max(0, num);
}

// === DARK MODE ===
async function loadTheme() {
  const result = await browser.storage.local.get('darkMode');
  const isDark = result.darkMode || false;
  document.body.classList.toggle('dark-mode', isDark);
}

// === ÉTAT DE LA SURVEILLANCE ===
async function getScanningState() {
  try {
    const result = await browser.storage.local.get('scanning_enabled');
    return result.scanning_enabled !== false;
  } catch (err) {
    console.error('Erreur récupération état:', err);
    return true;
  }
}

async function setScanningState(enabled) {
  try {
    await browser.storage.local.set({ scanning_enabled: enabled });
    await updateUI();
    // L'icône sera mise à jour automatiquement par le listener dans background.js
  } catch (err) {
    console.error('Erreur sauvegarde état:', err);
  }
}

async function updateUI() {
  const enabled = await getScanningState();
  const toggleBtn = document.getElementById('toggle-scan');
  const header = document.getElementById('header');
  const headerText = document.getElementById('header-text');
  const statusBanner = document.getElementById('status-banner');
  
  if (enabled) {
    // Utilise textContent au lieu de innerHTML
    toggleBtn.textContent = '';
    const icon = document.createTextNode('⏸️ ');
    const text = document.createTextNode(t('btnPause'));
    toggleBtn.appendChild(icon);
    toggleBtn.appendChild(text);
    
    toggleBtn.className = 'btn btn-pause';
    header.classList.remove('paused');
    headerText.textContent = t('popupTitle');
    statusBanner.classList.remove('show');
  } else {
    // Utilise textContent au lieu de innerHTML
    toggleBtn.textContent = '';
    const icon = document.createTextNode('▶️ ');
    const text = document.createTextNode(t('btnResume'));
    toggleBtn.appendChild(icon);
    toggleBtn.appendChild(text);
    
    toggleBtn.className = 'btn btn-resume';
    header.classList.add('paused');
    headerText.textContent = `${t('popupTitle')} (⏸️)`;
    statusBanner.classList.add('show');
  }
}

// === NAVIGATION ===
document.getElementById('options').addEventListener('click', () => {
  try { 
    browser.runtime.openOptionsPage(); 
  } catch (e) { 
    console.error('Erreur ouverture options:', e);
    window.open('options.html'); 
  }
});

// === TOGGLE SURVEILLANCE ===
document.getElementById('toggle-scan').addEventListener('click', async () => {
  const currentState = await getScanningState();
  await setScanningState(!currentState);
});

// === CLEAR HISTORY ===
document.getElementById('clear-history').addEventListener('click', async () => {
  if (!confirm(t('confirmClearHistory'))) return;
  
  try {
    await browser.storage.local.remove(["scan_history", "last_scan_result"]);
    await renderLast();
  } catch (err) {
    console.error('Erreur suppression historique:', err);
    alert(t('errorClearHistory'));
  }
});

// === RENDER HISTORY ===
async function renderLast() {
  const out = document.getElementById('result');
  
  try {
    const s = await browser.storage.local.get('scan_history');
    const history = s.scan_history || [];

    if (history.length === 0) {
      // Utilise des éléments DOM au lieu de innerHTML
      out.textContent = '';
      
      const emptyState = document.createElement('div');
      emptyState.className = 'empty-state';
      
      const icon = document.createElement('div');
      icon.className = 'empty-state-icon';
      icon.textContent = '📭';
      
      const title = document.createElement('div');
      title.className = 'empty-state-text';
      title.textContent = t('emptyStateTitle');
      
      const subtext = document.createElement('div');
      subtext.className = 'empty-state-subtext';
      subtext.textContent = t('emptyStateSubtext');
      
      emptyState.appendChild(icon);
      emptyState.appendChild(title);
      emptyState.appendChild(subtext);
      out.appendChild(emptyState);
      return;
    }

    out.textContent = '';
    const listContainer = document.createElement('div');
    listContainer.className = 'history-list';
    
    for (const r of history) {
      const safeFilename = escapeHtml(r.filename || "fichier_inconnu");
      const safeDate = escapeHtml(new Date(r.timestamp || Date.now()).toLocaleString());
      const detections = sanitizeNumber(r.detections, 0);
      const totalEngines = sanitizeNumber(r.totalEngines, 0);
      
      let statusClass = 'safe';
      let statusEmoji = '✅';
      let badgeClass = 'safe';
      
      if (totalEngines > 0) {
        const detectionRate = (detections / totalEngines) * 100;
        
        if (detectionRate >= 10) {
          statusClass = 'malicious';
          statusEmoji = '🚨';
          badgeClass = 'malicious';
        } else if (detectionRate > 0) {
          statusClass = 'suspicious';
          statusEmoji = '⚠️';
          badgeClass = 'suspicious';
        }
      }

      const itemDiv = document.createElement('div');
      itemDiv.className = `history-item ${statusClass}`;
      
      // Header
      const itemHeader = document.createElement('div');
      itemHeader.className = 'item-header';
      
      const itemFilename = document.createElement('div');
      itemFilename.className = 'item-filename';
      itemFilename.textContent = '📄 ';
      
      const filenameSpan = document.createElement('span');
      filenameSpan.title = safeFilename;
      filenameSpan.textContent = safeFilename;
      itemFilename.appendChild(filenameSpan);
      
      const itemStatus = document.createElement('div');
      itemStatus.className = 'item-status';
      itemStatus.textContent = statusEmoji;
      
      itemHeader.appendChild(itemFilename);
      itemHeader.appendChild(itemStatus);
      
      // Meta
      const itemMeta = document.createElement('div');
      itemMeta.className = 'item-meta';
      
      const itemDate = document.createElement('div');
      itemDate.className = 'item-date';
      itemDate.textContent = `🕒 ${safeDate}`;
      
      const detectionBadge = document.createElement('div');
      detectionBadge.className = `detection-badge ${badgeClass}`;
      detectionBadge.textContent = `${detections}/${totalEngines} ${t('detections')}`;
      
      itemMeta.appendChild(itemDate);
      itemMeta.appendChild(detectionBadge);
      
      itemDiv.appendChild(itemHeader);
      itemDiv.appendChild(itemMeta);
      
      // Details par moteur
      if (r.perEngine && typeof r.perEngine === 'object') {
        const details = document.createElement('details');
        
        const summary = document.createElement('summary');
        summary.textContent = `🔍 ${t('detailsEngines')}`;
        details.appendChild(summary);
        
        const engineTableDiv = document.createElement('div');
        engineTableDiv.className = 'engine-table';
        
        const table = document.createElement('table');
        
        // Thead
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        
        const thEngine = document.createElement('th');
        thEngine.textContent = t('tableEngine');
        const thResult = document.createElement('th');
        thResult.textContent = t('tableResult');
        const thStatus = document.createElement('th');
        thStatus.textContent = t('tableStatus');
        
        headerRow.appendChild(thEngine);
        headerRow.appendChild(thResult);
        headerRow.appendChild(thStatus);
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        // Tbody
        const tbody = document.createElement('tbody');
        
        for (const [engine, result] of Object.entries(r.perEngine)) {
          if (!result || typeof result !== 'object') continue;
          
          const safeEngine = escapeHtml(String(engine).substring(0, 50));
          const safeCategory = escapeHtml(String(result.category || 'unknown').substring(0, 30));
          const safeResult = escapeHtml(String(result.result || '-').substring(0, 100));
          
          const statusEmoji = safeCategory === 'malicious' ? '🚨' : 
                             safeCategory === 'suspicious' ? '⚠️' : 
                             safeCategory === 'undetected' ? '✅' : '❓';
          
          const row = document.createElement('tr');
          
          const tdEngine = document.createElement('td');
          const strongEngine = document.createElement('strong');
          strongEngine.textContent = safeEngine;
          tdEngine.appendChild(strongEngine);
          
          const tdResult = document.createElement('td');
          tdResult.textContent = safeResult;
          
          const tdStatus = document.createElement('td');
          tdStatus.textContent = `${statusEmoji} ${safeCategory}`;
          
          row.appendChild(tdEngine);
          row.appendChild(tdResult);
          row.appendChild(tdStatus);
          tbody.appendChild(row);
        }
        
        table.appendChild(tbody);
        engineTableDiv.appendChild(table);
        details.appendChild(engineTableDiv);
        itemDiv.appendChild(details);
      }
      
      listContainer.appendChild(itemDiv);
    }
    
    out.appendChild(listContainer);
    
  } catch (err) {
    console.error('Erreur renderLast:', err);
    out.textContent = '';
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-state';
    errorDiv.textContent = t('errorLoadHistory');
    out.appendChild(errorDiv);
  }
}

// === INIT ===
(async () => {
  translatePage();
  await loadTheme();
  await updateUI();
  await renderLast();
})();