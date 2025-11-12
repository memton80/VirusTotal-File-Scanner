// === VirusTotal Auto Scanner - SÉCURISÉ avec i18n et icône dynamique ===

const VT_UPLOAD_ENDPOINT = "https://www.virustotal.com/api/v3/files";
const VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses";
const VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files";

console.log("🚀 VirusTotal Scanner loaded (v1.8.0)");

// === i18n Helper ===
function t(key) {
  return browser.i18n.getMessage(key) || key;
}

// === VALIDATION STRICTE ===
function isValidApiKey(key) {
  return typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key);
}

function sanitizeFilename(filename) {
  if (!filename || typeof filename !== 'string') return 'unknown_file';
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

// === EXTRACTION NOM DE FICHIER ===
function extractFilename(fullPath) {
  if (!fullPath || typeof fullPath !== 'string') return 'unknown_file';
  
  // Extrait uniquement le nom du fichier, pas le chemin complet
  let filename = fullPath;
  
  // Gère les chemins Unix/Linux (/)
  if (filename.includes('/')) {
    filename = filename.split('/').pop();
  }
  
  // Gère les chemins Windows (\)
  if (filename.includes('\\')) {
    filename = filename.split('\\').pop();
  }
  
  return filename || 'unknown_file';
}

// === RATE LIMITING ===
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
        console.warn(`⏱️ Rate limit atteint. Attente de ${Math.ceil(waitTime/1000)}s`);
        await new Promise(r => setTimeout(r, waitTime));
        this.requests = this.requests.filter(t => Date.now() - t < this.timeWindow);
      }
      
      this.requests.push(now);
      console.log(`📊 Rate limiter: ${this.requests.length}/${this.maxRequests} requêtes`);
    } catch (e) {
      console.error("❌ Erreur rate limiter:", e);
    }
  }
};

// === 🔐 Récupère la clé API ===
async function getApiKey() {
  try {
    console.log("🔑 Récupération de la clé API...");
    const r = await browser.storage.local.get("vt_api_key");
    const key = r.vt_api_key;
    
    if (!isValidApiKey(key)) {
      console.error("❌ Clé API invalide ou manquante");
      return null;
    }
    
    console.log(`✅ Clé API valide: ${key.substring(0, 8)}...${key.substring(56)}`);
    return key;
  } catch (err) {
    console.error("❌ Erreur récupération clé API:", err);
    return null;
  }
}

// === 🔔 Notification sécurisée ===
function notify(id, title, message) {
  try {
    const safeId = String(id).substring(0, 100);
    const safeTitle = String(title).substring(0, 100);
    const safeMessage = String(message).substring(0, 200);
    
    console.log(`🔔 Notification: ${safeTitle} - ${safeMessage}`);
    
    browser.notifications.create(safeId, {
      type: "basic",
      iconUrl: browser.runtime.getURL("icons/icon-48.png"),
      title: safeTitle,
      message: safeMessage
    }).catch(e => console.warn("⚠️ Erreur notification:", e));
  } catch(e) {
    console.warn("⚠️ Erreur notification globale:", e);
  }
}

// === 🧾 Sauvegarde sécurisée dans l'historique ===
async function saveResult(result) {
  try {
    console.log("💾 Sauvegarde du résultat:", result);
    
    const safeResult = {
      filename: sanitizeFilename(extractFilename(result.filename)),
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
    
    console.log("✅ Résultat sauvegardé avec succès");
  } catch (err) {
    console.error("❌ Erreur sauvegarde résultat:", err);
  }
}

// === 🔄 Vérifie si la surveillance est active ===
async function isScanningEnabled() {
  try {
    const result = await browser.storage.local.get('scanning_enabled');
    const enabled = result.scanning_enabled !== false;
    console.log(`🔍 Surveillance: ${enabled ? '✅ ACTIVE' : '⏸️ EN PAUSE'}`);
    return enabled;
  } catch (err) {
    console.error("❌ Erreur vérification état:", err);
    return true;
  }
}

// === 🎨 Met à jour l'icône de l'extension ===
async function updateIcon() {
  try {
    const enabled = await isScanningEnabled();
    
    if (enabled) {
      await browser.browserAction.setIcon({
        path: {
          48: "icons/icon-48.png",
          128: "icons/icon-128.png"
        }
      });
      await browser.browserAction.setTitle({ title: t('popupTitle') });
      console.log("🎨 Icône mise à jour: ACTIVE");
    } else {
      await browser.browserAction.setIcon({
        path: {
          48: "icons/icon-48-paused.png",
          128: "icons/icon-128-paused.png"
        }
      });
      await browser.browserAction.setTitle({ title: `${t('popupTitle')} (⏸️)` });
      console.log("🎨 Icône mise à jour: EN PAUSE");
    }
  } catch (err) {
    console.error("❌ Erreur mise à jour icône:", err);
  }
}

// === 📡 Écoute les changements d'état de surveillance ===
browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.scanning_enabled) {
    console.log("🔄 État de surveillance changé:", changes.scanning_enabled.newValue);
    updateIcon();
  }
});

// === 🎯 Détecte les téléchargements terminés ===
browser.downloads.onChanged.addListener(async (delta) => {
  try {
    console.log("📥 Download event:", delta);
    
    const enabled = await isScanningEnabled();
    if (!enabled) {
      console.log("⏸️ Surveillance en pause, scan ignoré");
      return;
    }

    if (!delta.state || delta.state.current !== "complete") {
      console.log("⏭️ État non-complete, ignoré:", delta.state);
      return;
    }

    console.log("✅ Téléchargement terminé, ID:", delta.id);

    const dl = await browser.downloads.search({ id: delta.id });
    if (!dl || dl.length === 0) {
      console.log("❌ Téléchargement introuvable");
      return;
    }
    
    const item = dl[0];
    const cleanFilename = extractFilename(item.filename);
    
    console.log("📄 Fichier téléchargé:", item.filename);
    console.log("📝 Nom nettoyé:", cleanFilename);
    console.log("🔗 URL:", item.url);
    console.log("📊 Item complet:", item);

    const apiKey = await getApiKey();
    if (!apiKey) {
      console.log("❌ Pas de clé API, arrêt du scan");
      notify(
        `vt-no-api-${item.id}`, 
        t('notifNoApiKey'), 
        t('notifNoApiKeyMsg')
      );
      return;
    }

    const safeFilename = sanitizeFilename(cleanFilename);
    console.log("📝 Filename sanitized:", safeFilename);
    
    notify(
      `vt-start-${item.id}`, 
      t('notifScanStartTitle'),
      `${t('notifScanStartMsg')}\n"${safeFilename}"`
    );

    const url = sanitizeUrl(item.url);
    console.log("🔗 URL sanitized:", url);
    
    if (url) {
      try {
        console.log("🌐 Tentative de fetch du fichier:", url);
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000);
        
        const resp = await fetch(url, { 
          credentials: 'include',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        console.log("📡 Fetch response:", resp.status, resp.ok);
        
        if (!resp.ok) {
          throw new Error(`Échec téléchargement (${resp.status}): ${resp.statusText}`);
        }
        
        const blob = await resp.blob();
        console.log(`📦 Blob récupéré, taille: ${blob.size} bytes (${(blob.size/1024/1024).toFixed(2)} MB)`);
        
        const maxSize = 32 * 1024 * 1024;
        if (blob.size > maxSize) {
          console.log("❌ Fichier trop gros");
          notify(
            `vt-size-${item.id}`,
            t('notifFileTooLarge'),
            `${(blob.size / 1024 / 1024).toFixed(2)} ${t('notifFileTooLargeMsg')}`
          );
          return;
        }
        
        if (blob.size === 0) {
          console.log("❌ Fichier vide");
          notify(
            `vt-empty-${item.id}`,
            t('notifFileEmpty'),
            t('notifFileEmptyMsg')
          );
          return;
        }
        
        console.log("🚀 Lancement de l'upload vers VirusTotal...");
        await uploadBlobToVT(blob, apiKey, { 
          ...item, 
          filename: cleanFilename 
        });
        return;
        
      } catch (e) {
        console.error("❌ Échec du fetch:", e);
        
        if (e.name === 'AbortError') {
          console.log("⏱️ Timeout du fetch");
          notify(
            `vt-timeout-${item.id}`,
            t('notifTimeout'),
            t('notifTimeoutMsg')
          );
        } else if (e.message.includes('NetworkError') || e.message.includes('CORS')) {
          console.log("🚫 Erreur CORS/Network");
          notify(
            `vt-manual-${item.id}`, 
            t('notifManualScan'),
            `"${safeFilename}"`
          );
          return;
        } else {
          console.error("❌ Erreur inconnue:", e);
          notify(
            `vt-fetch-error-${item.id}`,
            t('notifFetchError'),
            e.message.substring(0, 100)
          );
        }
      }
    } else {
      console.log("❌ URL invalide ou non sanitizable");
    }

  } catch (err) {
    console.error("❌ Erreur background onChanged:", err);
  }
});

// === 📤 Upload sécurisé vers VirusTotal ===
async function uploadBlobToVT(blob, apiKey, itemMeta = {}) {
  console.log(`📤 Upload vers VT: ${blob.size} bytes`);
  
  try {
    await rateLimiter.checkAndWait();
  } catch (e) {
    console.error("❌ Erreur rate limiter:", e);
    notify(
      `vt-rate-error-${Date.now()}`,
      t('notifRateLimiterError'),
      t('notifRateLimiterError')
    );
    return;
  }
  
  const cleanFilename = extractFilename(itemMeta.filename || 'upload.bin');
  const safeFilename = sanitizeFilename(cleanFilename);
  
  const fd = new FormData();
  fd.append("file", blob, safeFilename);
  
  console.log("📦 FormData créé avec le fichier:", safeFilename);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000);
  
  let uploadStartTime = Date.now();

  try {
    console.log("🌐 Envoi de la requête vers VirusTotal...");
    const resp = await fetch(VT_UPLOAD_ENDPOINT, {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: fd,
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    const uploadDuration = ((Date.now() - uploadStartTime) / 1000).toFixed(1);
    console.log(`📡 Response status: ${resp.status} ${resp.statusText} (${uploadDuration}s)`);

    if (resp.status === 401) {
      console.error("❌ Clé API invalide lors de l'upload");
      notify(
        `vt-auth-error-${itemMeta.id || Date.now()}`,
        t('notifUploadError'),
        t('errorApiKeyUnauthorized')
      );
      return;
    }
    
    if (resp.status === 403) {
      console.error("❌ Accès interdit (403)");
      notify(
        `vt-forbidden-${itemMeta.id || Date.now()}`,
        t('notifUploadError'),
        t('errorApiKeyForbidden')
      );
      return;
    }
    
    if (resp.status === 429) {
      console.error("❌ Rate limit dépassé");
      notify(
        `vt-ratelimit-${itemMeta.id || Date.now()}`,
        t('notifRateLimitError'),
        t('notifRateLimitMsg')
      );
      return;
    }
    
    if (resp.status === 413) {
      console.error("❌ Fichier trop volumineux pour l'API");
      notify(
        `vt-toolarge-${itemMeta.id || Date.now()}`,
        t('notifFileTooLargeApi'),
        `${safeFilename}\n${t('notifFileTooLargeApiMsg')}`
      );
      return;
    }

    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({}));
      const errorMsg = errorData?.error?.message || `HTTP ${resp.status}`;
      
      console.error("❌ Upload failed:", {
        status: resp.status,
        statusText: resp.statusText,
        error: errorData
      });
      
      notify(
        `vt-error-${itemMeta.id || Date.now()}`, 
        t('notifUploadError'),
        `${safeFilename}\n${errorMsg.substring(0, 80)}`
      );
      
      return;
    }

    let data;
    try {
      data = await resp.json();
    } catch (parseError) {
      console.error("❌ Erreur parsing JSON:", parseError);
      notify(
        `vt-parse-error-${itemMeta.id || Date.now()}`,
        t('notifParseError'),
        t('notifParseErrorMsg')
      );
      return;
    }
    
    console.log("📊 Response data:", data);
    
    const analysisId = data?.data?.id;
    
    if (!analysisId || typeof analysisId !== 'string') {
      console.error("❌ Analysis ID manquant ou invalide:", data);
      notify(
        `vt-error2-${itemMeta.id || Date.now()}`, 
        t('notifVTError'),
        `${safeFilename}\n${t('notifVTErrorMsg')}`
      );
      return;
    }

    console.log("✅ Analysis ID reçu:", analysisId);
    console.log(`✅ Upload réussi en ${uploadDuration}s`);
    
    await pollAndShowReport(analysisId, apiKey, itemMeta);
    
  } catch(e) {
    clearTimeout(timeoutId);
    console.error("❌ Erreur uploadBlobToVT:", e);
    
    let errorTitle = t('notifUploadError');
    let errorMsg = e.message.substring(0, 80);
    
    if (e.name === 'AbortError') {
      errorTitle = t('notifUploadTimeout');
      errorMsg = `${safeFilename}\n${t('notifUploadTimeoutMsg')}`;
    } else if (e.message.includes('NetworkError') || e.message.includes('Failed to fetch')) {
      errorTitle = t('notifNetworkError');
      errorMsg = `${safeFilename}\n${t('notifNetworkErrorMsg')}`;
    }
    
    notify(
      `vt-error-${itemMeta.id || Date.now()}`, 
      errorTitle, 
      errorMsg
    );
  }
}

// === 🔁 Polling sécurisé du scan ===
async function pollAndShowReport(id, apiKey, itemMeta) {
  console.log("🔄 Démarrage du polling pour:", id);
  
  if (!id || typeof id !== 'string') {
    console.error("❌ ID d'analyse invalide");
    notify(
      `vt-error-invalid-id-${Date.now()}`,
      t('notifError'),
      t('notifInvalidId')
    );
    return;
  }
  
  const analysesUrl = `${VT_ANALYSIS_ENDPOINT}/${encodeURIComponent(id)}`;
  let delay = 2000;
  const maxDelay = 15000;
  const maxAttempts = 30;
  let notifiedSlowScan = false;
  let consecutiveErrors = 0;
  const maxConsecutiveErrors = 3;
  
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      console.log(`🔄 Polling tentative ${attempt + 1}/${maxAttempts}`);
      
      // Notification si l'analyse prend du temps (après 5 tentatives, ~15-20 secondes)
      if (attempt === 5 && !notifiedSlowScan) {
        const cleanFilename = extractFilename(itemMeta.filename);
        const safeFilename = sanitizeFilename(cleanFilename);
        notify(
          `vt-slow-${id}`,
          t('notifScanSlow'),
          `${safeFilename}\n${t('notifScanSlowMsg')}`
        );
        notifiedSlowScan = true;
      }
      
      await rateLimiter.checkAndWait();
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);
      
      const r = await fetch(analysesUrl, { 
        headers: { "x-apikey": apiKey },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      console.log(`📡 Polling response: ${r.status}`);
      
      // Réinitialise le compteur d'erreurs en cas de succès
      consecutiveErrors = 0;
      
      if (r.status === 401) {
        console.error("❌ Clé API invalide pendant le polling");
        notify(
          `vt-auth-error-${id}`,
          t('notifError'),
          t('errorApiKeyUnauthorized')
        );
        return;
      }
      
      if (r.status === 429) {
        console.warn("⚠️ Rate limit atteint, attente prolongée");
        notify(
          `vt-ratelimit-polling-${id}`,
          t('notifRateLimitError'),
          t('notifRateLimitMsg')
        );
        await new Promise(resolve => setTimeout(resolve, 30000));
        continue;
      }
      
      if (r.ok) {
        const j = await r.json();
        const status = j?.data?.attributes?.status;
        
        console.log(`📊 Status: ${status}`);
        
        if (status === "completed") {
          console.log("✅ Scan terminé!");
          const sha256 = j?.meta?.file_info?.sha256 || 
                        j?.data?.id || 
                        j?.data?.attributes?.sha256;
          
          console.log("🔑 SHA256:", sha256);
          
          if (sha256 && /^[a-f0-9]{64}$/i.test(sha256)) {
            await fetchFileReportBySha(sha256, apiKey, itemMeta);
            return;
          } else {
            console.log("⚠️ Pas de SHA256, sauvegarde basique");
            await saveResult({
              filename: itemMeta.filename,
              detections: 0,
              totalEngines: 0,
              timestamp: Date.now()
            });
            
            notify(
              `vt-result-analysis-${id}`, 
              t('notifScanComplete'),
              t('notifScanCompleteMsg')
            );
            return;
          }
        } else if (status === "queued" || status === "in-progress") {
          console.log(`⏳ Scan en cours: ${status}`);
        } else {
          console.warn(`⚠️ Statut inattendu: ${status}`);
        }
      } else {
        console.warn(`⚠️ Poll response error: ${r.status}`);
        consecutiveErrors++;
        
        if (consecutiveErrors >= maxConsecutiveErrors) {
          console.error("❌ Trop d'erreurs consécutives, abandon du polling");
          notify(
            `vt-polling-failed-${id}`,
            t('notifPollingFailed'),
            `${t('notifPollingFailedMsg')} (HTTP ${r.status})`
          );
          return;
        }
      }
    } catch(e) {
      console.warn("⚠️ Erreur pendant le polling:", e);
      consecutiveErrors++;
      
      if (e.name === 'AbortError') {
        console.warn("⏱️ Timeout de la requête de polling");
      }
      
      if (consecutiveErrors >= maxConsecutiveErrors) {
        console.error("❌ Trop d'erreurs consécutives, abandon");
        const cleanFilename = extractFilename(itemMeta.filename);
        const safeFilename = sanitizeFilename(cleanFilename);
        notify(
          `vt-polling-error-${id}`,
          t('notifConsecutiveErrors'),
          `${safeFilename}\n${t('notifConsecutiveErrorsMsg')}`
        );
        return;
      }
    }
    
    console.log(`⏱️ Attente de ${delay}ms avant nouvelle tentative...`);
    await new Promise(resolve => setTimeout(resolve, delay));
    delay = Math.min(delay * 1.5, maxDelay);
  }

  console.log("⏱️ Timeout du polling après max tentatives");
  const cleanFilename = extractFilename(itemMeta.filename);
  const safeFilename = sanitizeFilename(cleanFilename);
  notify(
    `vt-timeout-${id}`, 
    t('notifScanPending'),
    `${safeFilename}\n${t('notifScanPendingMsg')}`
  );
}

// === 📊 Rapport final sécurisé ===
async function fetchFileReportBySha(sha256, apiKey, itemMeta) {
  console.log("📊 Fetch rapport pour SHA256:", sha256);
  
  if (!sha256 || !/^[a-f0-9]{64}$/i.test(sha256)) {
    console.error("❌ SHA256 invalide");
    notify(
      `vt-error-invalid-sha-${Date.now()}`,
      t('notifError'),
      "SHA256 invalide reçu de VirusTotal"
    );
    return;
  }
  
  let retries = 0;
  const maxRetries = 3;
  
  while (retries < maxRetries) {
    try {
      await rateLimiter.checkAndWait();
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);
      
      const r = await fetch(`${VT_FILE_ENDPOINT}/${encodeURIComponent(sha256)}`, { 
        headers: { "x-apikey": apiKey },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      console.log(`📡 Report response: ${r.status}`);
      
      if (r.status === 401) {
        console.error("❌ Clé API invalide");
        notify(
          `vt-auth-error-${sha256}`,
          t('notifError'),
          t('errorApiKeyUnauthorized')
        );
        return;
      }
      
      if (r.status === 429) {
        console.warn("⚠️ Rate limit atteint, nouvelle tentative dans 30s");
        await new Promise(resolve => setTimeout(resolve, 30000));
        retries++;
        continue;
      }
      
      if (r.status === 404) {
        console.warn("⚠️ Rapport non trouvé (404), nouvelle tentative");
        if (retries < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          retries++;
          continue;
        } else {
          notify(
            `vt-not-found-${sha256}`,
            t('notifReportError'),
            "Rapport non disponible sur VirusTotal"
          );
          return;
        }
      }
      
      if (!r.ok) {
        const errorData = await r.json().catch(() => ({}));
        const errorMsg = errorData?.error?.message || `Erreur HTTP ${r.status}`;
        console.error("❌ fetchFileReportBySha failed:", errorData);
        
        if (retries < maxRetries - 1) {
          console.log(`⏱️ Nouvelle tentative (${retries + 1}/${maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, 3000));
          retries++;
          continue;
        }
        
        notify(
          `vt-err-report-${sha256}`, 
          t('notifReportError'), 
          errorMsg.substring(0, 100)
        );
        return;
      }

      const j = await r.json();
      
      if (!j?.data?.attributes) {
        console.error("❌ Format de réponse invalide");
        notify(
          `vt-invalid-response-${sha256}`,
          t('notifVTError'),
          "Format de réponse VirusTotal invalide"
        );
        return;
      }
      
      const stats = j.data.attributes.last_analysis_stats || {};
      const results = j.data.attributes.last_analysis_results || {};
      
      const detections = parseInt(stats.malicious) || 0;
      const totalEngines = Object.keys(results).length;

      console.log(`📊 Détections: ${detections}/${totalEngines}`);

      const lastResult = {
        sha256,
        detections,
        totalEngines,
        perEngine: results,
        timestamp: Date.now(),
        filename: itemMeta.filename
      };

      await saveResult(lastResult);

      let title = t('notifFileSafe');
      const detectionRate = totalEngines > 0 ? (detections / totalEngines) * 100 : 0;
      
      if (detections > 0 && detectionRate < 10) { 
        title = t('notifFileSuspicious');
      } else if (detectionRate >= 10) { 
        title = t('notifFileDangerous');
      }

      console.log(`✅ Résultat final: ${title} (${detectionRate.toFixed(1)}%)`);

      const cleanFilename = extractFilename(itemMeta.filename);
      const safeFilename = sanitizeFilename(cleanFilename);
      
      notify(
        `vt-result-${sha256}`,
        title,
        `${safeFilename}\n${detections}/${totalEngines} ${t('detections')} (${detectionRate.toFixed(1)}%)`
      );
      
      return;

    } catch(e) {
      console.error("❌ Erreur fetchFileReportBySha:", e);
      
      if (e.name === 'AbortError') {
        console.warn("⏱️ Timeout de la requête");
      }
      
      if (retries < maxRetries - 1) {
        console.log(`⏱️ Nouvelle tentative après erreur (${retries + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 3000));
        retries++;
        continue;
      }
      
      const errorMsg = e.name === 'AbortError' 
        ? "Timeout lors de la récupération du rapport"
        : e.message;
      
      notify(
        `vt-error-final-${sha256}`,
        t('notifError'),
        errorMsg.substring(0, 100)
      );
      return;
    }
  }
  
  console.error("❌ Échec après toutes les tentatives");
  notify(
    `vt-all-retries-failed-${sha256}`,
    t('notifError'),
    "Impossible de récupérer le rapport après plusieurs tentatives"
  );
}

// === 🚀 INITIALISATION ===
(async () => {
  console.log("🚀 Initialisation de l'extension...");
  await updateIcon();
  console.log("✅ Extension initialisée, icône mise à jour");
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { uploadBlobToVT };
}