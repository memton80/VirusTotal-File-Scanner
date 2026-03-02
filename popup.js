// === Popup - Interface utilisateur popup ===

// === Vérification des dépendances ===
if (typeof VTUtils === 'undefined') {
  console.error('VTUtils non chargé !');
}
if (typeof VTIcons === 'undefined') {
  console.error('VTIcons non chargé !');
}
if (typeof scanHistory === 'undefined') {
  console.error('scanHistory non chargé !');
}

// === DARK MODE ===
async function updateThemeUI() {
  try {
    const isDark = await VTUtils.loadTheme();
    const toggle = document.getElementById('dark-mode-toggle');
    if (toggle) toggle.checked = isDark;
  } catch (e) {
    console.error('Erreur updateThemeUI:', e);
  }
}

// === ÉTAT DE LA SURVEILLANCE ===
// Note: getScanningState et setScanningState sont définis dans utils.js
// On utilise les fonctions de VTUtils directement

async function handleToggleScanning() {
  try {
    const currentState = await VTUtils.isScanningEnabled();
    await VTUtils.setScanningState(!currentState);
    await updateUI();
  } catch (err) {
    console.error('Erreur toggle état:', err);
  }
}

async function updateUI() {
  const enabled = await VTUtils.isScanningEnabled();
  const toggleBtn = document.getElementById('toggle-scan');
  const header = document.getElementById('header');
  const headerText = document.getElementById('header-text');
  const statusBanner = document.getElementById('status-banner');
  
  if (enabled) {
    toggleBtn.textContent = '';
    const icon = VTIcons.pause(16);
    const text = document.createTextNode(' ' + VTUtils.t('btnPause'));
    toggleBtn.appendChild(icon);
    toggleBtn.appendChild(text);
    
    toggleBtn.className = 'btn btn-pause';
    header.classList.remove('paused');
    headerText.textContent = VTUtils.t('popupTitle');
    statusBanner.classList.remove('show');
  } else {
    toggleBtn.textContent = '';
    const icon = VTIcons.play(16);
    const text = document.createTextNode(' ' + VTUtils.t('btnResume'));
    toggleBtn.appendChild(icon);
    toggleBtn.appendChild(text);
    
    toggleBtn.className = 'btn btn-resume';
    header.classList.add('paused');
    headerText.textContent = VTUtils.t('popupTitle');
    statusBanner.classList.add('show');
  }
}

// === Event Listeners (attendre que le DOM soit prêt) ===
document.addEventListener('DOMContentLoaded', () => {
  console.log('Popup DOM chargé');
  
  // === NAVIGATION ===
  const optionsBtn = document.getElementById('options');
  if (optionsBtn) {
    optionsBtn.addEventListener('click', () => {
      console.log('Clic sur options');
      try { 
        browser.runtime.openOptionsPage(); 
      } catch (e) { 
        console.error('Erreur ouverture options:', e);
        window.open('options.html'); 
      }
    });
  } else {
    console.error('Bouton options non trouvé');
  }

  // === TOGGLE SURVEILLANCE ===
  const toggleBtn = document.getElementById('toggle-scan');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', async () => {
      console.log('Toggle surveillance');
      await handleToggleScanning();
    });
  }

  // === CLEAR HISTORY ===
  const clearBtn = document.getElementById('clear-history');
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      console.log('Clear historique');
      if (!confirm(VTUtils.t('confirmClearHistory'))) return;
      
      try {
        if (typeof scanHistory !== 'undefined') {
          await scanHistory.clear();
          await renderLast();
        } else {
          console.error('scanHistory non disponible');
        }
      } catch (err) {
        console.error('Erreur suppression historique:', err);
        alert(VTUtils.t('errorClearHistory'));
      }
    });
  }
});

// === RENDER HISTORY ===
async function renderLast() {
  const out = document.getElementById('result');
  
  if (!out) {
    console.error('Element #result non trouvé');
    return;
  }
  
  if (typeof scanHistory === 'undefined') {
    console.error('scanHistory non disponible');
    out.textContent = 'Erreur: scanHistory non chargé';
    return;
  }
  
  try {
    const history = await scanHistory.getAll();

    if (history.length === 0) {
      out.textContent = '';
      
      const emptyState = document.createElement('div');
      emptyState.className = 'empty-state';
      
      const icon = document.createElement('div');
      icon.className = 'empty-state-icon';
      icon.appendChild(VTIcons.inbox(48));
      
      const title = document.createElement('div');
      title.className = 'empty-state-text';
      title.textContent = VTUtils.t('emptyStateTitle');
      
      const subtext = document.createElement('div');
      subtext.className = 'empty-state-subtext';
      subtext.textContent = VTUtils.t('emptyStateSubtext');
      
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
      const safeFilename = VTUtils.escapeHtml(r.filename || "fichier_inconnu");
      const safeDate = VTUtils.escapeHtml(new Date(r.timestamp || Date.now()).toLocaleString());
      const detections = VTUtils.sanitizeNumber(r.detections, 0);
      const totalEngines = VTUtils.sanitizeNumber(r.totalEngines, 0);
      
      // === FICHIER SENSIBLE (SCAN IGNULÉ) ===
      if (r.skipped && r.reason === 'sensitive') {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'history-item skipped';
        
        // Badge "Annulé" dans le coin
        const cancelledBanner = document.createElement('div');
        cancelledBanner.className = 'cancelled-banner';
        cancelledBanner.textContent = VTUtils.t('statusCancelled');
        itemDiv.appendChild(cancelledBanner);
        
        const itemHeader = document.createElement('div');
        itemHeader.className = 'item-header';
        itemHeader.style.marginTop = '20px';
        
        const itemFilename = document.createElement('div');
        itemFilename.className = 'item-filename';
        const fileIcon = VTIcons.fileText(14);
        fileIcon.style.opacity = '0.6';
        fileIcon.style.stroke = 'var(--text-hint)';
        itemFilename.appendChild(fileIcon);
        
        const filenameSpan = document.createElement('span');
        filenameSpan.title = safeFilename;
        filenameSpan.textContent = ' ' + safeFilename;
        filenameSpan.style.opacity = '0.8';
        filenameSpan.style.textDecoration = 'line-through';
        itemFilename.appendChild(filenameSpan);
        
        const itemStatus = document.createElement('div');
        itemStatus.className = 'item-status';
        // Icône bouclier barré pour indiquer protection/blocage
        const shieldIcon = VTIcons.shieldAlert(18);
        shieldIcon.style.stroke = 'var(--warning-color)';
        shieldIcon.style.opacity = '0.8';
        itemStatus.appendChild(shieldIcon);
        
        itemHeader.appendChild(itemFilename);
        itemHeader.appendChild(itemStatus);
        
        const itemMeta = document.createElement('div');
        itemMeta.className = 'item-meta';
        
        const itemDate = document.createElement('div');
        itemDate.className = 'item-date';
        const clockIcon = VTIcons.clock(12);
        clockIcon.style.stroke = 'var(--text-hint)';
        itemDate.appendChild(clockIcon);
        itemDate.appendChild(document.createTextNode(' ' + safeDate));
        
        const skipBadge = document.createElement('div');
        skipBadge.className = 'detection-badge skipped';
        // Créer l'icône SVG de manière sécurisée
        const shieldSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        shieldSvg.setAttribute('width', '12');
        shieldSvg.setAttribute('height', '12');
        shieldSvg.setAttribute('viewBox', '0 0 24 24');
        shieldSvg.setAttribute('fill', 'none');
        shieldSvg.setAttribute('stroke', 'currentColor');
        shieldSvg.setAttribute('stroke-width', '2');
        shieldSvg.setAttribute('stroke-linecap', 'round');
        shieldSvg.setAttribute('stroke-linejoin', 'round');
        shieldSvg.style.verticalAlign = 'middle';
        shieldSvg.style.marginRight = '4px';
        const shieldPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        shieldPath.setAttribute('d', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z');
        shieldSvg.appendChild(shieldPath);
        skipBadge.appendChild(shieldSvg);
        skipBadge.appendChild(document.createTextNode(' ' + VTUtils.t('statusSkippedSensitive')));
        
        itemMeta.appendChild(itemDate);
        itemMeta.appendChild(skipBadge);
        
        itemDiv.appendChild(itemHeader);
        itemDiv.appendChild(itemMeta);
        listContainer.appendChild(itemDiv);
        continue;
      }
      
      let statusClass = 'safe';
      let statusIcon = VTIcons.check(16);
      statusIcon.classList.add('status-icon-safe');
      let badgeClass = 'safe';
      
      if (totalEngines > 0) {
        const detectionRate = (detections / totalEngines) * 100;
        
        if (detectionRate >= 10) {
          statusClass = 'malicious';
          statusIcon = VTIcons.shieldAlert(16);
          statusIcon.classList.add('status-icon-malicious');
          badgeClass = 'malicious';
        } else if (detectionRate > 0) {
          statusClass = 'suspicious';
          statusIcon = VTIcons.alertTriangle(16);
          statusIcon.classList.add('status-icon-suspicious');
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
      const fileIcon = VTIcons.fileText(14);
      itemFilename.appendChild(fileIcon);
      
      const filenameSpan = document.createElement('span');
      filenameSpan.title = safeFilename;
      filenameSpan.textContent = ' ' + safeFilename;
      itemFilename.appendChild(filenameSpan);
      
      const itemStatus = document.createElement('div');
      itemStatus.className = 'item-status';
      itemStatus.appendChild(statusIcon);
      
      itemHeader.appendChild(itemFilename);
      itemHeader.appendChild(itemStatus);
      
      // Meta
      const itemMeta = document.createElement('div');
      itemMeta.className = 'item-meta';
      
      const itemDate = document.createElement('div');
      itemDate.className = 'item-date';
      const clockIcon = VTIcons.clock(12);
      itemDate.appendChild(clockIcon);
      itemDate.appendChild(document.createTextNode(' ' + safeDate));
      
      const detectionBadge = document.createElement('div');
      detectionBadge.className = `detection-badge ${badgeClass}`;
      detectionBadge.textContent = `${detections}/${totalEngines} ${VTUtils.t('detections')}`;
      
      itemMeta.appendChild(itemDate);
      itemMeta.appendChild(detectionBadge);
      
      itemDiv.appendChild(itemHeader);
      itemDiv.appendChild(itemMeta);
      
      // Details par moteur
      if (r.perEngine && typeof r.perEngine === 'object') {
        const details = document.createElement('details');
        
        const summary = document.createElement('summary');
        const searchIcon = VTIcons.search(12);
        summary.appendChild(searchIcon);
        summary.appendChild(document.createTextNode(' ' + VTUtils.t('detailsEngines')));
        details.appendChild(summary);
        
        const engineTableDiv = document.createElement('div');
        engineTableDiv.className = 'engine-table';
        
        const table = document.createElement('table');
        
        // Thead
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        
        const thEngine = document.createElement('th');
        thEngine.textContent = VTUtils.t('tableEngine');
        const thResult = document.createElement('th');
        thResult.textContent = VTUtils.t('tableResult');
        const thStatus = document.createElement('th');
        thStatus.textContent = VTUtils.t('tableStatus');
        
        headerRow.appendChild(thEngine);
        headerRow.appendChild(thResult);
        headerRow.appendChild(thStatus);
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        // Tbody
        const tbody = document.createElement('tbody');
        
        for (const [engine, result] of Object.entries(r.perEngine)) {
          if (!result || typeof result !== 'object') continue;
          
          const safeEngine = VTUtils.escapeHtml(String(engine).substring(0, 50));
          const safeCategory = VTUtils.escapeHtml(String(result.category || 'unknown').substring(0, 30));
          const safeResult = VTUtils.escapeHtml(String(result.result || '-').substring(0, 100));
          
          let statusIcon;
          if (safeCategory === 'malicious') {
            statusIcon = VTIcons.shieldAlert(12);
            statusIcon.classList.add('status-icon-malicious');
          } else if (safeCategory === 'suspicious') {
            statusIcon = VTIcons.alertTriangle(12);
            statusIcon.classList.add('status-icon-suspicious');
          } else if (safeCategory === 'undetected') {
            statusIcon = VTIcons.check(12);
            statusIcon.classList.add('status-icon-safe');
          } else {
            statusIcon = VTIcons.helpCircle(12);
            statusIcon.classList.add('status-icon-unknown');
          }
          
          const row = document.createElement('tr');
          
          const tdEngine = document.createElement('td');
          const strongEngine = document.createElement('strong');
          strongEngine.textContent = safeEngine;
          tdEngine.appendChild(strongEngine);
          
          const tdResult = document.createElement('td');
          tdResult.textContent = safeResult;
          
          const tdStatus = document.createElement('td');
          tdStatus.appendChild(statusIcon);
          tdStatus.appendChild(document.createTextNode(' ' + safeCategory));
          
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
    errorDiv.textContent = VTUtils.t('errorLoadHistory');
    out.appendChild(errorDiv);
  }
}

// === INIT ===
document.addEventListener('DOMContentLoaded', async () => {
  console.log('Popup initialisation...');
  
  if (typeof VTUtils === 'undefined') {
    console.error('VTUtils non chargé - arrêt');
    document.getElementById('result').textContent = 'Erreur de chargement (VTUtils)';
    return;
  }
  
  if (typeof VTIcons === 'undefined') {
    console.error('VTIcons non chargé - arrêt');
    document.getElementById('result').textContent = 'Erreur de chargement (VTIcons)';
    return;
  }
  
  VTUtils.translatePage();
  await updateThemeUI();
  await updateUI();
  await renderLast();
  console.log('Popup initialisé');
});
