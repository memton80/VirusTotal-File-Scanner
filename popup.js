document.getElementById('options').addEventListener('click', () => {
  try { browser.runtime.openOptionsPage(); } catch (e) { window.open('options.html'); }
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
  if (!confirm(`Tu t'apprêtes à uploader "${f.name}" vers VirusTotal. Continuer ?`)) return;

  const apiKey = (await browser.storage.local.get('vt_api_key')).vt_api_key;
  if (!apiKey) { alert("Clé API manquante — ouvre les options."); return; }

  const fd = new FormData();
  fd.append('file', f, f.name);

  const resp = await fetch('https://www.virustotal.com/api/v3/files', {
    method: 'POST',
    headers: { 'x-apikey': apiKey },
    body: fd
  });
  if (!resp.ok) {
    alert('Erreur upload: ' + resp.status);
    return;
  }
  const j = await resp.json();
  await browser.storage.local.set({ last_scan_result: { uploaded: true, response: j, filename: f.name, timestamp: Date.now() }});
  document.getElementById('result').textContent = 'Upload envoyé, le scan peut prendre quelques secondes.';
  renderLast();
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
    let color = "#4CAF50", emoji = "✅";
    if (r.detections > 0 && r.detections <= 3) { color = "#FF9800"; emoji = "⚠️"; }
    else if (r.detections > 3) { color = "#F44336"; emoji = "🚨"; }

    html += `
      <div class="history-item" style="border-left:6px solid ${color};">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div><strong>${emoji} ${r.filename || "inconnu"}</strong><br><span class="small">${new Date(r.timestamp).toLocaleString()}</span></div>
          <div style="text-align:right;"><strong>${r.detections ?? 0}</strong><br><span class="small">détections</span></div>
        </div>
        ${r.perEngine ? `<details style="margin-top:8px;"><summary>Voir les résultats par moteur</summary><pre>${JSON.stringify(r.perEngine, null, 2)}</pre></details>` : (r.analysisJson ? `<pre style="margin-top:8px;">${JSON.stringify(r.analysisJson, null, 2)}</pre>` : '')}
      </div>
    `;
  }
  html += '</div>';
  out.innerHTML = html;
}

renderLast();
