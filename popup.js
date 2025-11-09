// === Fonction d'échappement HTML (CRITIQUE) ===
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

document.getElementById('options').addEventListener('click', () => {
  try { 
    browser.runtime.openOptionsPage(); 
  } catch (e) { 
    window.open('options.html'); 
  }
});

const filepicker = document.getElementById('filepicker');
document.getElementById('pick').addEventListener('click', () => filepicker.click());

document.getElementById('clear-history').addEventListener('click', async () => {
  if (!confirm("Effacer l'historique des scans ?")) return;
  await browser.storage.local.remove(["scan_history", "last_scan_result"]);
  renderLast();
});

filepicker.addEventListener('change', async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  
  // Validation du nom de fichier
  const safeName = f.name.substring(0, 255); // Limite la longueur
  
  if (!confirm(`Tu t'apprêtes à uploader "${safeName}" vers VirusTotal. Continuer ?`)) return;

  const apiKey = (await browser.storage.local.get('vt_api_key')).vt_api_key;
  if (!apiKey) { 
    alert("Clé API manquante — ouvre les options."); 
    return; 
  }

  // Vérification taille
  if (f.size > 32 * 1024 * 1024) {
    alert("Fichier trop volumineux (max 32MB pour l'API gratuite).");
    return;
  }

  const fd = new FormData();
  fd.append('file', f, safeName);

  try {
    const resp = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: fd
    });
    
    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({}));
      alert(`Erreur upload (${resp.status}): ${errorData?.error?.message || 'Erreur inconnue'}`);
      return;
    }
    
    const j = await resp.json();
    await browser.storage.local.set({ 
      last_scan_result: { 
        uploaded: true, 
        response: j, 
        filename: safeName, 
        timestamp: Date.now() 
      }
    });
    
    document.getElementById('result').textContent = 'Upload envoyé, le scan peut prendre quelques secondes.';
    renderLast();
  } catch (err) {
    console.error('Erreur upload:', err);
    alert('Erreur réseau: ' + err.message);
  }
});

async function renderLast() {
  const s = await browser.storage.local.get('scan_history');
  const history = s.scan_history || [];
  const out = document.getElementById('result');

  if (history.length === 0) {
    out.innerHTML = '<em>Aucun scan enregistré pour le moment.</em>';
    return;
  }

  let html = '<div style="max-height:360px; overflow:auto;">';
  
  for (const r of history) {
    // Échappement de TOUTES les données utilisateur
    const safeFilename = escapeHtml(r.filename || "inconnu");
    const safeDate = escapeHtml(new Date(r.timestamp).toLocaleString());
    const detections = parseInt(r.detections) || 0; // Validation numérique
    
    let color = "#4CAF50", emoji = "✅";
    if (detections > 0 && detections <= 3) { 
      color = "#FF9800"; 
      emoji = "⚠️"; 
    } else if (detections > 3) { 
      color = "#F44336"; 
      emoji = "🚨"; 
    }

    html += `
      <div class="history-item" style="border-left:6px solid ${color};">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>${emoji} ${safeFilename}</strong><br>
            <span class="small">${safeDate}</span>
          </div>
          <div style="text-align:right;">
            <strong>${detections}</strong><br>
            <span class="small">détections</span>
          </div>
        </div>
    `;
    
    // Détails des moteurs (sécurisé)
    if (r.perEngine) {
      html += '<details style="margin-top:8px;">';
      html += '<summary>Voir les résultats par moteur</summary>';
      html += '<div style="max-height:200px; overflow:auto;"><table style="width:100%; font-size:0.85em;">';
      
      for (const [engine, result] of Object.entries(r.perEngine)) {
        const safeEngine = escapeHtml(engine);
        const safeCategory = escapeHtml(result.category || 'unknown');
        const safeResult = escapeHtml(result.result || '-');
        
        const statusEmoji = safeCategory === 'malicious' ? '🚨' : 
                           safeCategory === 'suspicious' ? '⚠️' : 
                           safeCategory === 'undetected' ? '✅' : '❓';
        
        html += `<tr>
          <td>${statusEmoji} ${safeEngine}</td>
          <td>${safeResult}</td>
        </tr>`;
      }
      
      html += '</table></div></details>';
    } else if (r.analysisJson) {
      // Affichage JSON sécurisé
      const safeJson = escapeHtml(JSON.stringify(r.analysisJson, null, 2));
      html += `<pre style="margin-top:8px;">${safeJson}</pre>`;
    }
    
    html += '</div>';
  }
  
  html += '</div>';
  out.innerHTML = html;
}

renderLast();
