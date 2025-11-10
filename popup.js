// === SÉCURITÉ : Échappement HTML strict (CRITIQUE) ===
function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(text);
  return div.innerHTML;
}

// Validation des nombres
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

// === NAVIGATION ===
document.getElementById('options').addEventListener('click', () => {
  try { 
    browser.runtime.openOptionsPage(); 
  } catch (e) { 
    console.error('Erreur ouverture options:', e);
    window.open('options.html'); 
  }
});

// === FILE PICKER ===
const filepicker = document.getElementById('filepicker');
document.getElementById('pick').addEventListener('click', () => filepicker.click());

// === CLEAR HISTORY ===
document.getElementById('clear-history').addEventListener('click', async () => {
  if (!confirm("⚠️ Effacer l'historique des scans ?\n\nCette action est irréversible.")) return;
  
  try {
    await browser.storage.local.remove(["scan_history", "last_scan_result"]);
    await renderLast();
  } catch (err) {
    console.error('Erreur suppression historique:', err);
    alert('❌ Erreur lors de la suppression de l\'historique.');
  }
});

// === FILE UPLOAD ===
filepicker.addEventListener('change', async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  
  // Validation du nom de fichier (sécurité)
  const safeName = String(f.name).substring(0, 255).replace(/[<>:"/\\|?*\x00-\x1F]/g, '_');
  
  // Validation de la taille
  const maxSize = 32 * 1024 * 1024; // 32MB
  if (f.size > maxSize) {
    alert(`❌ Fichier trop volumineux (${(f.size / 1024 / 1024).toFixed(2)} MB)\n\nLimite : 32 MB pour l'API gratuite VirusTotal.`);
    filepicker.value = ''; // Reset
    return;
  }
  
  if (f.size === 0) {
    alert('❌ Le fichier est vide (0 bytes).');
    filepicker.value = '';
    return;
  }

  if (!confirm(`📤 Upload vers VirusTotal\n\nFichier : ${safeName}\nTaille : ${(f.size / 1024).toFixed(2)} KB\n\n⚠️ ATTENTION : Le fichier deviendra PUBLIC sur VirusTotal.\n\nContinuer ?`)) {
    filepicker.value = '';
    return;
  }

  // Récupération de la clé API
  let apiKey;
  try {
    const result = await browser.storage.local.get('vt_api_key');
    apiKey = result.vt_api_key;
    
    if (!apiKey || !/^[a-f0-9]{64}$/i.test(apiKey)) {
      alert("❌ Clé API manquante ou invalide.\n\nVa dans les options (⚙️) pour configurer ta clé VirusTotal."); 
      filepicker.value = '';
      return; 
    }
  } catch (err) {
    console.error('Erreur récupération clé:', err);
    alert('❌ Erreur lors de la récupération de la clé API.');
    filepicker.value = '';
    return;
  }

  const fd = new FormData();
  fd.append('file', f, safeName);

  // Affichage du chargement
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = '<div class="loading">📤 Upload en cours...</div>';

  // Upload avec timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 minutes timeout

  try {
    const resp = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: fd,
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({}));
      const errorMsg = errorData?.error?.message || `Erreur HTTP ${resp.status}`;
      alert(`❌ Échec de l'upload (${resp.status})\n\n${errorMsg}`);
      await renderLast();
      filepicker.value = '';
      return;
    }
    
    const j = await resp.json();
    
    // Sauvegarde du résultat
    await browser.storage.local.set({ 
      last_scan_result: { 
        uploaded: true, 
        response: j, 
        filename: safeName, 
        timestamp: Date.now() 
      }
    });
    
    resultDiv.innerHTML = '<div class="success-upload">✅ Upload réussi ! Le scan peut prendre quelques secondes...</div>';
    
    // Rafraîchit l'affichage après 2 secondes
    setTimeout(() => renderLast(), 2000);
    
  } catch (err) {
    clearTimeout(timeoutId);
    console.error('Erreur upload:', err);
    
    if (err.name === 'AbortError') {
      alert('⏱️ Timeout : L\'upload a pris trop de temps. Réessaie avec une connexion plus rapide.');
    } else {
      alert('❌ Erreur réseau : ' + err.message);
    }
    
    await renderLast();
  } finally {
    filepicker.value = ''; // Reset pour permettre re-upload du même fichier
  }
});

// === RENDER HISTORY ===
async function renderLast() {
  const out = document.getElementById('result');
  
  try {
    const s = await browser.storage.local.get('scan_history');
    const history = s.scan_history || [];

    if (history.length === 0) {
      out.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📭</div>
          <div class="empty-state-text">Aucun scan enregistré</div>
          <div class="empty-state-subtext">Clique sur "Scanner un fichier" pour commencer</div>
        </div>
      `;
      return;
    }

    out.innerHTML = '<div class="history-list"></div>';
    const listContainer = out.querySelector('.history-list');
    
    for (const r of history) {
      // Échappement et validation de TOUTES les données
      const safeFilename = escapeHtml(r.filename || "fichier_inconnu");
      const safeDate = escapeHtml(new Date(r.timestamp || Date.now()).toLocaleString('fr-FR'));
      const detections = sanitizeNumber(r.detections, 0);
      const totalEngines = sanitizeNumber(r.totalEngines, 0);
      
      // Détermination du statut
      let statusClass = 'safe';
      let statusEmoji = '✅';
      let statusText = 'Sûr';
      let badgeClass = 'safe';
      
      if (totalEngines > 0) {
        const detectionRate = (detections / totalEngines) * 100;
        
        if (detectionRate >= 10) {
          statusClass = 'malicious';
          statusEmoji = '🚨';
          statusText = 'Dangereux';
          badgeClass = 'malicious';
        } else if (detectionRate > 0) {
          statusClass = 'suspicious';
          statusEmoji = '⚠️';
          statusText = 'Suspect';
          badgeClass = 'suspicious';
        }
      }

      const itemDiv = document.createElement('div');
      itemDiv.className = `history-item ${statusClass}`;
      
      let itemHTML = `
        <div class="item-header">
          <div class="item-filename">
            📄 <span title="${safeFilename}">${safeFilename}</span>
          </div>
          <div class="item-status">${statusEmoji}</div>
        </div>
        <div class="item-meta">
          <div class="item-date">
            🕒 ${safeDate}
          </div>
          <div class="detection-badge ${badgeClass}">
            ${detections}/${totalEngines} détections
          </div>
        </div>
      `;
      
      // Détails des moteurs (sécurisé)
      if (r.perEngine && typeof r.perEngine === 'object') {
        itemHTML += '<details><summary>🔍 Détails par moteur antivirus</summary>';
        itemHTML += '<div class="engine-table"><table><thead><tr><th>Moteur</th><th>Résultat</th><th>Statut</th></tr></thead><tbody>';
        
        for (const [engine, result] of Object.entries(r.perEngine)) {
          if (!result || typeof result !== 'object') continue;
          
          const safeEngine = escapeHtml(String(engine).substring(0, 50));
          const safeCategory = escapeHtml(String(result.category || 'unknown').substring(0, 30));
          const safeResult = escapeHtml(String(result.result || '-').substring(0, 100));
          
          const statusEmoji = safeCategory === 'malicious' ? '🚨' : 
                             safeCategory === 'suspicious' ? '⚠️' : 
                             safeCategory === 'undetected' ? '✅' : '❓';
          
          itemHTML += `<tr>
            <td><strong>${safeEngine}</strong></td>
            <td>${safeResult}</td>
            <td>${statusEmoji} ${safeCategory}</td>
          </tr>`;
        }
        
        itemHTML += '</tbody></table></div></details>';
      }
      
      itemDiv.innerHTML = itemHTML;
      listContainer.appendChild(itemDiv);
    }
    
  } catch (err) {
    console.error('Erreur renderLast:', err);
    out.innerHTML = '<div class="error-state">❌ Erreur lors du chargement de l\'historique</div>';
  }
}

// === INIT ===
(async () => {
  await loadTheme();
  await renderLast();
})();
