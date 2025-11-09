// === VirusTotal Auto Scanner - CORS FIX ===

const VT_UPLOAD_ENDPOINT = "https://www.virustotal.com/api/v3/files";
const VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses";
const VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files";

console.log("VirusTotal Scanner loaded (CORS fixed)");

// Rate limiting (API gratuite VirusTotal : 4 req/min)
const rateLimiter = {
  requests: [],
  maxRequests: 4,
  timeWindow: 60000,
  
  async checkAndWait() {
    try {
      const now = Date.now();
      this.requests = this.requests.filter(t => now - t < this.timeWindow);
      
      if (this.requests.length >= this.maxRequests) {
        const oldestReq = this.requests[0];
        const waitTime = this.timeWindow - (now - oldestReq) + 1000;
        console.warn(`Rate limit atteint. Attente de ${Math.ceil(waitTime/1000)}s`);
        await new Promise(r => setTimeout(r, waitTime));
        this.requests = this.requests.filter(t => Date.now() - t < this.timeWindow);
      }
      
      this.requests.push(now);
    } catch (e) {
      console.error("Erreur rate limiter:", e);
    }
  }
};

// --- 🔐 Récupère la clé API ---
async function getApiKey() {
  const r = await browser.storage.local.get("vt_api_key");
  return r.vt_api_key || null;
}

// --- 🔔 Notification ---
function notify(id, title, message) {
  try {
    browser.notifications.create(id, {
      type: "basic",
      iconUrl: browser.runtime.getURL("icons/icon-48.png"),
      title: title || "VT Scan",
      message: message || ""
    }).catch(e => console.warn("Erreur notification:", e));
  } catch(e) {
    console.warn("Erreur notification globale:", e);
  }
}

// --- 🧾 Sauvegarde dans l'historique ---
async function saveResult(result) {
  const s = await browser.storage.local.get('scan_history');
  const history = s.scan_history || [];
  history.unshift(result);
  if (history.length > 20) history.length = 20;
  await browser.storage.local.set({ 
    scan_history: history, 
    last_scan_result: result 
  });
}

// --- 🎯 Détecte les téléchargements terminés ---
browser.downloads.onChanged.addListener(async (delta) => {
  try {
    if (!delta.state || delta.state.current !== "complete") return;

    const dl = await browser.downloads.search({ id: delta.id });
    if (!dl || dl.length === 0) return;
    const item = dl[0];

    const apiKey = await getApiKey();
    if (!apiKey) {
      notify(
        `vt-no-api-${item.id}`, 
        "⚠️ Clé API manquante", 
        "Configure ta clé VirusTotal dans les options."
      );
      return;
    }

    notify(
      `vt-start-${item.id}`, 
      "🔄 Scan démarré",
      `Upload de "${item.filename || "fichier inconnu"}" vers VirusTotal...`
    );

    const url = item.url;
    console.log("URL du fichier:", url);
    
    if (url && /^https?:\/\//i.test(url)) {
      try {
        console.log("Tentative de fetch du fichier...");
        const resp = await fetch(url, { credentials: 'include' });
        console.log("Fetch response:", resp.status, resp.ok);
        
        if (!resp.ok) {
          throw new Error(`Échec téléchargement (${resp.status}): ${resp.statusText}`);
        }
        
        const blob = await resp.blob();
        console.log("Blob récupéré, taille:", blob.size);
        
        // Vérification taille (max 32MB pour l'API gratuite)
        if (blob.size > 32 * 1024 * 1024) {
          notify(
            `vt-size-${item.id}`,
            "❌ Fichier trop volumineux",
            "Les fichiers > 32MB nécessitent un compte Premium VirusTotal."
          );
          return;
        }
        
        await uploadBlobToVT(blob, apiKey, item);
        return;
      } catch (e) {
        console.error("Échec du fetch:", e);
        notify(
          `vt-fetch-error-${item.id}`,
          "❌ Erreur de récupération",
          e.message
        );
      }
    }

    notify(
      `vt-manual-${item.id}`, 
      "📋 Scan manuel requis",
      "Impossible de récupérer le fichier automatiquement. Ouvre le popup."
    );

  } catch (err) {
    console.error("Erreur background onChanged:", err);
  }
});

// --- 📤 Upload vers VirusTotal (depuis un Blob) ---
async function uploadBlobToVT(blob, apiKey, itemMeta = {}) {
  console.log("Upload vers VT:", blob.size, "bytes");
  
  await rateLimiter.checkAndWait();
  
  const fd = new FormData();
  fd.append("file", blob, itemMeta.filename || "upload.bin");

  try {
    const resp = await fetch(VT_UPLOAD_ENDPOINT, {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: fd
    });

    console.log("Response status:", resp.status);

    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({}));
      const errorMsg = errorData?.error?.message || `Erreur HTTP ${resp.status}`;
      
      notify(
        `vt-error-${itemMeta.id || Date.now()}`, 
        "❌ Échec de l'upload",
        errorMsg
      );
      
      console.error("Upload failed:", resp.status, errorData);
      return;
    }

    const data = await resp.json();
    const analysisId = data?.data?.id;
    
    if (!analysisId) {
      notify(
        `vt-error2-${itemMeta.id || Date.now()}`, 
        "❌ Erreur VirusTotal",
        "Réponse inattendue du service."
      );
      return;
    }

    console.log("Analysis ID:", analysisId);
    await pollAndShowReport(analysisId, apiKey, itemMeta);
  } catch(e) {
    console.error("Erreur uploadBlobToVT:", e);
    notify(
      `vt-error-${itemMeta.id || Date.now()}`, 
      "❌ Erreur d'upload", 
      e.message
    );
  }
}

// --- 🔁 Polling du scan ---
async function pollAndShowReport(id, apiKey, itemMeta) {
  console.log("Polling scan:", id);
  const analysesUrl = `${VT_ANALYSIS_ENDPOINT}/${id}`;
  let delay = 2000;
  const maxDelay = 15000;
  const maxAttempts = 20;
  
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      await rateLimiter.checkAndWait();
      
      const r = await fetch(analysesUrl, { 
        headers: { "x-apikey": apiKey } 
      });
      
      if (r.ok) {
        const j = await r.json();
        const status = j?.data?.attributes?.status;
        
        console.log(`Tentative ${attempt + 1}: ${status}`);
        
        if (status === "completed") {
          const sha256 = j?.meta?.file_info?.sha256 || 
                        j?.data?.id || 
                        j?.data?.attributes?.sha256;
          
          if (sha256) {
            await fetchFileReportBySha(sha256, apiKey, itemMeta);
            return;
          } else {
            await saveResult({
              filename: itemMeta.filename,
              detections: 0,
              analysisJson: j,
              timestamp: Date.now()
            });
            
            notify(
              `vt-result-analysis-${id}`, 
              "✅ Scan terminé",
              "Résultats disponibles dans le popup."
            );
            return;
          }
        }
      } else {
        console.warn("Poll response error:", r.status);
      }
    } catch(e) {
      console.warn("Erreur pendant le polling:", e);
    }
    
    await new Promise(resolve => setTimeout(resolve, delay));
    delay = Math.min(delay * 1.5, maxDelay);
  }

  notify(
    `vt-timeout-${id}`, 
    "⏱️ Scan en attente",
    "L'analyse prend plus de temps que prévu."
  );
}

// --- 📊 Rapport final ---
async function fetchFileReportBySha(sha256, apiKey, itemMeta) {
  console.log("Fetch rapport:", sha256);
  try {
    await rateLimiter.checkAndWait();
    
    const r = await fetch(`${VT_FILE_ENDPOINT}/${sha256}`, { 
      headers: { "x-apikey": apiKey } 
    });
    
    if (!r.ok) {
      const errorData = await r.json().catch(() => ({}));
      
      notify(
        `vt-err-report-${sha256}`, 
        "❌ Erreur rapport", 
        errorData?.error?.message || `Erreur ${r.status}`
      );
      
      console.error("fetchFileReportBySha failed:", r.status, errorData);
      return;
    }

    const j = await r.json();
    const stats = j?.data?.attributes?.last_analysis_stats || {};
    const results = j?.data?.attributes?.last_analysis_results || {};
    const detections = stats.malicious || 0;
    const totalEngines = Object.keys(results).length;

    console.log(`Détections: ${detections}/${totalEngines}`);

    const lastResult = {
      sha256,
      detections,
      totalEngines,
      perEngine: results,
      timestamp: Date.now(),
      filename: itemMeta.filename
    };

    await saveResult(lastResult);

    let emoji = "✅", title = "Fichier sûr";
    const detectionRate = totalEngines > 0 ? (detections / totalEngines) * 100 : 0;
    
    if (detections > 0 && detectionRate < 10) { 
      emoji = "⚠️"; 
      title = "Fichier suspect";
    } else if (detectionRate >= 10) { 
      emoji = "🚨"; 
      title = "Fichier dangereux !";
    }

    notify(
      `vt-result-${sha256}`,
      `${emoji} ${title}`,
      `${itemMeta.filename || "fichier inconnu"}\n${detections}/${totalEngines} détections (${detectionRate.toFixed(1)}%)`
    );

  } catch(e) {
    console.error("Erreur fetchFileReportBySha:", e);
    notify(
      `vt-error-final-${sha256}`,
      "❌ Erreur",
      e.message
    );
  }
}

// Export pour utilisation depuis popup.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { uploadBlobToVT };
}
