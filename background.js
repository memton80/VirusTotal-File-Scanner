// === VirusTotal Auto Scanner - SÉCURISÉ ===

const VT_UPLOAD_ENDPOINT = "https://www.virustotal.com/api/v3/files";
const VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses";
const VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files";

console.log("VirusTotal Scanner loaded (Secured version)");

// === VALIDATION STRICTE ===
function isValidApiKey(key) {
  return typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key);
}

function sanitizeFilename(filename) {
  if (!filename || typeof filename !== 'string') return 'unknown_file';
  // Supprime les caractères dangereux
  return filename.substring(0, 255).replace(/[<>:"/\\|?*\x00-\x1F]/g, '_');
}

function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
    return parsed.href;
  } catch {
    return null;
  }
}

// === RATE LIMITING (API gratuite VirusTotal : 4 req/min) ===
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

// === 🔐 Récupère la clé API (avec validation) ===
async function getApiKey() {
  try {
    const r = await browser.storage.local.get("vt_api_key");
    const key = r.vt_api_key;
    if (!isValidApiKey(key)) {
      console.error("Clé API invalide ou manquante");
      return null;
    }
    return key;
  } catch (err) {
    console.error("Erreur récupération clé API:", err);
    return null;
  }
}

// === 🔔 Notification sécurisée ===
function notify(id, title, message) {
  try {
    // Validation des entrées
    const safeId = String(id).substring(0, 100);
    const safeTitle = String(title).substring(0, 100);
    const safeMessage = String(message).substring(0, 200);
    
    browser.notifications.create(safeId, {
      type: "basic",
      iconUrl: browser.runtime.getURL("icons/icon-48.png"),
      title: safeTitle,
      message: safeMessage
    }).catch(e => console.warn("Erreur notification:", e));
  } catch(e) {
    console.warn("Erreur notification globale:", e);
  }
}

// === 🧾 Sauvegarde sécurisée dans l'historique ===
async function saveResult(result) {
  try {
    // Validation des données avant sauvegarde
    const safeResult = {
      filename: sanitizeFilename(result.filename),
      detections: parseInt(result.detections) || 0,
      totalEngines: parseInt(result.totalEngines) || 0,
      sha256: (result.sha256 && /^[a-f0-9]{64}$/i.test(result.sha256)) ? result.sha256 : null,
      timestamp: Date.now(),
      perEngine: result.perEngine || null
    };
    
    const s = await browser.storage.local.get('scan_history');
    const history = Array.isArray(s.scan_history) ? s.scan_history : [];
    
    history.unshift(safeResult);
    if (history.length > 20) history.length = 20;
    
    await browser.storage.local.set({ 
      scan_history: history, 
      last_scan_result: safeResult 
    });
  } catch (err) {
    console.error("Erreur sauvegarde résultat:", err);
  }
}

// === 🎯 Détecte les téléchargements terminés ===
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
        "Configure ta clé VirusTotal dans les options (⚙️)."
      );
      return;
    }

    const safeFilename = sanitizeFilename(item.filename);
    
    notify(
      `vt-start-${item.id}`, 
      "🔄 Scan démarré",
      `Upload de "${safeFilename}" vers VirusTotal...`
    );

    const url = sanitizeUrl(item.url);
    
    if (url) {
      try {
        console.log("Tentative de fetch du fichier:", url);
        
        // Fetch avec timeout de sécurité
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout
        
        const resp = await fetch(url, { 
          credentials: 'include',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        console.log("Fetch response:", resp.status, resp.ok);
        
        if (!resp.ok) {
          throw new Error(`Échec téléchargement (${resp.status}): ${resp.statusText}`);
        }
        
        const blob = await resp.blob();
        console.log("Blob récupéré, taille:", blob.size);
        
        // Vérification taille (max 32MB pour l'API gratuite)
        const maxSize = 32 * 1024 * 1024;
        if (blob.size > maxSize) {
          notify(
            `vt-size-${item.id}`,
            "❌ Fichier trop volumineux",
            `${(blob.size / 1024 / 1024).toFixed(2)} MB > 32 MB (limite API gratuite)`
          );
          return;
        }
        
        if (blob.size === 0) {
          notify(
            `vt-empty-${item.id}`,
            "❌ Fichier vide",
            "Le fichier téléchargé est vide (0 bytes)."
          );
          return;
        }
        
        await uploadBlobToVT(blob, apiKey, item);
        return;
        
      } catch (e) {
        console.error("Échec du fetch:", e);
        
        if (e.name === 'AbortError') {
          notify(
            `vt-timeout-${item.id}`,
            "⏱️ Timeout",
            "Le téléchargement du fichier a pris trop de temps."
          );
        } else if (e.message.includes('NetworkError') || e.message.includes('CORS')) {
          // Erreur CORS/Réseau : impossible de fetch directement
          console.log("Impossible de fetch automatiquement (CORS/Network). Passage en mode manuel.");
          notify(
            `vt-manual-${item.id}`, 
            "📋 Scan manuel requis",
            `Ouvre le popup pour scanner "${safeFilename}" manuellement.`
          );
          return; // Évite le double notify
        } else {
          notify(
            `vt-fetch-error-${item.id}`,
            "❌ Erreur de récupération",
            e.message.substring(0, 100)
          );
        }
      }
    }

    // Si on arrive ici, le fetch auto a échoué
    // Ne pas afficher de notification car déjà gérée dans le catch

  } catch (err) {
    console.error("Erreur background onChanged:", err);
  }
});

// === 📤 Upload sécurisé vers VirusTotal ===
async function uploadBlobToVT(blob, apiKey, itemMeta = {}) {
  console.log("Upload vers VT:", blob.size, "bytes");
  
  await rateLimiter.checkAndWait();
  
  const safeFilename = sanitizeFilename(itemMeta.filename || 'upload.bin');
  const fd = new FormData();
  fd.append("file", blob, safeFilename);

  // Timeout de sécurité
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 min timeout

  try {
    const resp = await fetch(VT_UPLOAD_ENDPOINT, {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: fd,
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    console.log("Response status:", resp.status);

    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({}));
      const errorMsg = errorData?.error?.message || `Erreur HTTP ${resp.status}`;
      
      notify(
        `vt-error-${itemMeta.id || Date.now()}`, 
        "❌ Échec de l'upload",
        errorMsg.substring(0, 100)
      );
      
      console.error("Upload failed:", resp.status, errorData);
      return;
    }

    const data = await resp.json();
    const analysisId = data?.data?.id;
    
    if (!analysisId || typeof analysisId !== 'string') {
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
    clearTimeout(timeoutId);
    console.error("Erreur uploadBlobToVT:", e);
    
    const errorMsg = e.name === 'AbortError' 
      ? "Timeout: l'upload a pris trop de temps" 
      : e.message;
    
    notify(
      `vt-error-${itemMeta.id || Date.now()}`, 
      "❌ Erreur d'upload", 
      errorMsg.substring(0, 100)
    );
  }
}

// === 🔁 Polling sécurisé du scan ===
async function pollAndShowReport(id, apiKey, itemMeta) {
  console.log("Polling scan:", id);
  
  // Validation de l'ID
  if (!id || typeof id !== 'string') {
    console.error("ID d'analyse invalide");
    return;
  }
  
  const analysesUrl = `${VT_ANALYSIS_ENDPOINT}/${encodeURIComponent(id)}`;
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
          
          if (sha256 && /^[a-f0-9]{64}$/i.test(sha256)) {
            await fetchFileReportBySha(sha256, apiKey, itemMeta);
            return;
          } else {
            await saveResult({
              filename: itemMeta.filename,
              detections: 0,
              totalEngines: 0,
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
    "L'analyse prend plus de temps que prévu. Consulte le popup."
  );
}

// === 📊 Rapport final sécurisé ===
async function fetchFileReportBySha(sha256, apiKey, itemMeta) {
  console.log("Fetch rapport:", sha256);
  
  // Validation SHA256
  if (!sha256 || !/^[a-f0-9]{64}$/i.test(sha256)) {
    console.error("SHA256 invalide");
    return;
  }
  
  try {
    await rateLimiter.checkAndWait();
    
    const r = await fetch(`${VT_FILE_ENDPOINT}/${encodeURIComponent(sha256)}`, { 
      headers: { "x-apikey": apiKey } 
    });
    
    if (!r.ok) {
      const errorData = await r.json().catch(() => ({}));
      
      notify(
        `vt-err-report-${sha256}`, 
        "❌ Erreur rapport", 
        (errorData?.error?.message || `Erreur ${r.status}`).substring(0, 100)
      );
      
      console.error("fetchFileReportBySha failed:", r.status, errorData);
      return;
    }

    const j = await r.json();
    const stats = j?.data?.attributes?.last_analysis_stats || {};
    const results = j?.data?.attributes?.last_analysis_results || {};
    
    const detections = parseInt(stats.malicious) || 0;
    const totalEngines = Object.keys(results).length;

    console.log(`Détections: ${detections}/${totalEngines}`);

    const lastResult = {
      sha256,
      detections,
      totalEngines,
      perEngine: results,
      timestamp: Date.now(),
      filename: sanitizeFilename(itemMeta.filename)
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
      `${sanitizeFilename(itemMeta.filename)}\n${detections}/${totalEngines} détections (${detectionRate.toFixed(1)}%)`
    );

  } catch(e) {
    console.error("Erreur fetchFileReportBySha:", e);
    notify(
      `vt-error-final-${sha256}`,
      "❌ Erreur",
      e.message.substring(0, 100)
    );
  }
}

// Export pour utilisation depuis popup.js (si nécessaire)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { uploadBlobToVT };
}
