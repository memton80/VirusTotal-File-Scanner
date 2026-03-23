// === VirusTotal Auto Scanner - Optimisé ===
// Version: 1.7.8

const VT_UPLOAD_ENDPOINT = "https://www.virustotal.com/api/v3/files";
const VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses";
const VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files";

console.log("VirusTotal Scanner loaded (v1.7.8)");

// === FICHERS SENSIBLES - MOTS-CLÉS À FILTRER ===
const SENSITIVE_KEYWORDS = [
  'id', 'identity', 'identifiant', 'passport', 'passeport', 'ssn', 'social security',
  'carte identite', 'cni', 'permis', 'license', 'insurance', 'assurance', 'rib', 'iban',
  'bank', 'bancaire', 'compte', 'account', 'credit', 'card', 'cb', 'credit card',
  'health', 'sante', 'medical', 'medical', 'ordonnance', 'prescription',
  'facture', 'invoice', 'tax', 'impot', 'declar', 'dgi', 'fiscal',
  'private', 'prive', 'confidential', 'confidentiel', 'secret', 'personal', 'personnel'
];

// === VÉRIFICATION FICHIER SENSIBLE ===
function containsSensitiveKeywords(filename) {
  const lowerName = filename.toLowerCase();
  return SENSITIVE_KEYWORDS.some(keyword => lowerName.includes(keyword.toLowerCase()));
}

// === LOOKUP SHA-256 sur VirusTotal ===
async function lookupFileBySHA256(sha256, apiKey) {
  console.log(`Lookup du fichier par SHA-256: ${sha256}`);
  
  try {
    await rateLimiter.checkAndWait();
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    
    const response = await fetch(`${VT_FILE_ENDPOINT}/${encodeURIComponent(sha256)}`, {
      headers: { "x-apikey": apiKey },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (response.status === 404) {
      console.log("Fichier non trouvé sur VirusTotal (nouveau fichier)");
      return null;
    }
    
    if (response.status === 401) {
      console.error("Clé API invalide");
      return null;
    }
    
    if (response.status === 429) {
      console.warn("Rate limit atteint lors du lookup");
      return null;
    }
    
    if (!response.ok) {
      console.warn(`Lookup failed: ${response.status}`);
      return null;
    }
    
    const data = await response.json();
    console.log("Fichier déjà connu sur VirusTotal!");
    
    return { exists: true, data };
    
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn("Timeout du lookup");
    } else {
      console.error("Erreur lookup:", e);
    }
    return null;
  }
}

// === Mise à jour de l'icône ===
async function updateIcon() {
  try {
    const enabled = await VTUtils.isScanningEnabled();
    
    if (enabled) {
      await browser.action.setIcon({
        path: { 48: "icons/icon-48.png", 128: "icons/icon-128.png" }
      });
      await browser.action.setTitle({ title: VTUtils.t('popupTitle') });
      console.log("Icône mise à jour: ACTIVE");
    } else {
      await browser.action.setIcon({
        path: { 48: "icons/icon-48-paused.png", 128: "icons/icon-128-paused.png" }
      });
      await browser.action.setTitle({ title: `${VTUtils.t('popupTitle')} [PAUSE]` });
      console.log("Icône mise à jour: EN PAUSE");
    }
  } catch (err) {
    console.error("Erreur mise à jour icône:", err);
  }
}

// === Écoute les changements d'état ===
browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.scanning_enabled) {
    console.log("État de surveillance changé:", changes.scanning_enabled.newValue);
    updateIcon();
  }
});

// === Détecte les téléchargements terminés ===
browser.downloads.onChanged.addListener(async (delta) => {
  try {
    console.log("Download event:", delta);
    
    const enabled = await VTUtils.isScanningEnabled();
    if (!enabled) {
      console.log("Surveillance en pause, scan ignoré");
      return;
    }

    if (!delta.state || delta.state.current !== "complete") {
      console.log("État non-complete, ignoré:", delta.state);
      return;
    }

    console.log("Téléchargement terminé, ID:", delta.id);

    const dl = await browser.downloads.search({ id: delta.id });
    if (!dl || dl.length === 0) {
      console.log("Téléchargement introuvable");
      return;
    }
    
    const item = dl[0];
    const cleanFilename = VTUtils.extractFilename(item.filename);
    
    console.log("Fichier téléchargé:", item.filename);
    console.log("Nom nettoyé:", cleanFilename);
    console.log("URL:", item.url);

    const apiKey = await VTUtils.getApiKey();
    if (!apiKey) {
      console.log("Pas de clé API, arrêt du scan");
      VTUtils.notify(
        `vt-no-api-${item.id}`, 
        VTUtils.t('notifNoApiKey'), 
        VTUtils.t('notifNoApiKeyMsg')
      );
      return;
    }

    const safeFilename = VTUtils.sanitizeFilename(cleanFilename);
    const url = VTUtils.sanitizeUrl(item.url);
    
    if (!url) {
      console.log("URL invalide ou non sanitizable");
      return;
    }

    // === VÉRIFICATION FICHIER SENSIBLE ===
    if (containsSensitiveKeywords(cleanFilename)) {
      console.log("[FILTRE] Fichier sensible détecté, scan annulé:", cleanFilename);
      VTUtils.notify(
        `vt-sensitive-${item.id}`,
        VTUtils.t('notifSensitiveFile'),
        `${VTUtils.t('notifSensitiveFileMsg')}: "${safeFilename}"`
      );
      
      // Sauvegarder dans l'historique comme ignoré
      await scanHistory.save({
        filename: cleanFilename,
        detections: -1,
        totalEngines: 0,
        timestamp: Date.now(),
        skipped: true,
        reason: 'sensitive'
      });
      return;
    }

    try {
      console.log("Tentative de fetch du fichier:", url);
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 60000);
      
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
      console.log(`Blob récupéré, taille: ${blob.size} bytes (${(blob.size/1024/1024).toFixed(2)} MB)`);
      
      const maxSize = 32 * 1024 * 1024;
      if (blob.size > maxSize) {
        console.log("Fichier trop gros");
        VTUtils.notify(
          `vt-size-${item.id}`,
          VTUtils.t('notifFileTooLarge'),
          `${(blob.size / 1024 / 1024).toFixed(2)} ${VTUtils.t('notifFileTooLargeMsg')}`
        );
        return;
      }
      
      if (blob.size === 0) {
        console.log("Fichier vide");
        VTUtils.notify(
          `vt-empty-${item.id}`,
          VTUtils.t('notifFileEmpty'),
          VTUtils.t('notifFileEmptyMsg')
        );
        return;
      }
      
      // Calcul SHA-256 et vérification cache
      const sha256 = await VTUtils.calculateSHA256(blob);
      
      if (sha256) {
        // Vérifier le cache local d'abord
        const cached = await scanCache.get(sha256);
        if (cached) {
          console.log("Utilisation du résultat en cache");
          
          await scanHistory.save({
            filename: cleanFilename,
            detections: cached.detections,
            totalEngines: cached.totalEngines,
            sha256: sha256,
            perEngine: cached.perEngine
          });
          
          const detectionRate = cached.totalEngines > 0 ? 
            (cached.detections / cached.totalEngines) * 100 : 0;
          
          let title = VTUtils.t('notifFileSafe');
          if (cached.detections > 0 && detectionRate < 10) {
            title = VTUtils.t('notifFileSuspicious');
          } else if (detectionRate >= 10) {
            title = VTUtils.t('notifFileDangerous');
          }
          
          VTUtils.notify(
            `vt-cached-${sha256}`,
            `${title} [Cache]`,
            `${safeFilename}\n${cached.detections}/${cached.totalEngines} ${VTUtils.t('detections')} (${detectionRate.toFixed(1)}%)`
          );
          
          return;
        }
        
        // Vérifier si le fichier existe déjà sur VirusTotal
        console.log("Vérification si le fichier existe sur VirusTotal...");
        const lookup = await lookupFileBySHA256(sha256, apiKey);
        
        if (lookup && lookup.exists) {
          console.log("Fichier trouvé sur VirusTotal, pas besoin d'upload!");
          
          const stats = lookup.data?.data?.attributes?.last_analysis_stats || {};
          const results = lookup.data?.data?.attributes?.last_analysis_results || {};
          const detections = parseInt(stats.malicious) || 0;
          const totalEngines = Object.keys(results).length;
          
          const resultData = {
            filename: cleanFilename,
            detections: detections,
            totalEngines: totalEngines,
            sha256: sha256,
            perEngine: results
          };
          
          await scanHistory.save(resultData);
          await scanCache.set(sha256, resultData);
          
          const detectionRate = totalEngines > 0 ? (detections / totalEngines) * 100 : 0;
          
          let title = VTUtils.t('notifFileSafe');
          if (detections > 0 && detectionRate < 10) {
            title = VTUtils.t('notifFileSuspicious');
          } else if (detectionRate >= 10) {
            title = VTUtils.t('notifFileDangerous');
          }
          
          VTUtils.notify(
            `vt-existing-${sha256}`,
            `${title} [Existant]`,
            `${safeFilename}\n${detections}/${totalEngines} ${VTUtils.t('detections')} (${detectionRate.toFixed(1)}%)`
          );
          
          return;
        }
      }
      
      // Si pas en cache et pas trouvé sur VT, upload normal
      console.log("Fichier non trouvé, upload nécessaire...");
      VTUtils.notify(
        `vt-start-${item.id}`, 
        VTUtils.t('notifScanStartTitle'),
        `${VTUtils.t('notifScanStartMsg')}\n"${safeFilename}"`
      );
      
      await uploadBlobToVT(blob, apiKey, { 
        ...item, 
        filename: cleanFilename,
        sha256: sha256
      });
      
    } catch (e) {
      console.error("Échec du fetch:", e);
      
      if (e.name === 'AbortError') {
        console.log("Timeout du fetch");
        VTUtils.notify(
          `vt-timeout-${item.id}`,
          VTUtils.t('notifTimeout'),
          VTUtils.t('notifTimeoutMsg')
        );
      } else if (e.message.includes('NetworkError') || e.message.includes('CORS')) {
        console.log("Erreur CORS/Network");
        VTUtils.notify(
          `vt-manual-${item.id}`, 
          VTUtils.t('notifManualScan'),
          `"${safeFilename}"`
        );
      } else {
        console.error("Erreur inconnue:", e);
        VTUtils.notify(
          `vt-fetch-error-${item.id}`,
          VTUtils.t('notifFetchError'),
          e.message.substring(0, 100)
        );
      }
    }

  } catch (err) {
    console.error("Erreur background onChanged:", err);
  }
});

// === Upload vers VirusTotal ===
async function uploadBlobToVT(blob, apiKey, itemMeta = {}) {
  console.log(`Upload vers VT: ${blob.size} bytes`);
  
  try {
    await rateLimiter.checkAndWait();
  } catch (e) {
    console.error("Erreur rate limiter:", e);
    VTUtils.notify(
      `vt-rate-error-${Date.now()}`,
      VTUtils.t('notifRateLimiterError'),
      VTUtils.t('notifRateLimiterError')
    );
    return;
  }
  
  const cleanFilename = VTUtils.extractFilename(itemMeta.filename || 'upload.bin');
  const safeFilename = VTUtils.sanitizeFilename(cleanFilename);
  
  const fd = new FormData();
  fd.append("file", blob, safeFilename);
  
  console.log("FormData créé avec le fichier:", safeFilename);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000);
  
  const uploadStartTime = Date.now();

  try {
    console.log("Envoi de la requête vers VirusTotal...");
    const resp = await fetch(VT_UPLOAD_ENDPOINT, {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: fd,
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    const uploadDuration = ((Date.now() - uploadStartTime) / 1000).toFixed(1);
    console.log(`Response status: ${resp.status} ${resp.statusText} (${uploadDuration}s)`);

    if (resp.status === 401) {
      console.error("Clé API invalide lors de l'upload");
      VTUtils.notify(
        `vt-auth-error-${itemMeta.id || Date.now()}`,
        VTUtils.t('notifUploadError'),
        VTUtils.t('errorApiKeyUnauthorized')
      );
      return;
    }
    
    if (resp.status === 403) {
      console.error("Accès interdit (403)");
      VTUtils.notify(
        `vt-forbidden-${itemMeta.id || Date.now()}`,
        VTUtils.t('notifUploadError'),
        VTUtils.t('errorApiKeyForbidden')
      );
      return;
    }
    
    if (resp.status === 429) {
      console.error("Rate limit dépassé");
      VTUtils.notify(
        `vt-ratelimit-${itemMeta.id || Date.now()}`,
        VTUtils.t('notifRateLimitError'),
        VTUtils.t('notifRateLimitMsg')
      );
      return;
    }
    
    if (resp.status === 413) {
      console.error("Fichier trop volumineux pour l'API");
      VTUtils.notify(
        `vt-toolarge-${itemMeta.id || Date.now()}`,
        VTUtils.t('notifFileTooLargeApi'),
        `${safeFilename}\n${VTUtils.t('notifFileTooLargeApiMsg')}`
      );
      return;
    }

    if (!resp.ok) {
      const errorData = await resp.json().catch(() => ({}));
      const errorMsg = errorData?.error?.message || `HTTP ${resp.status}`;
      
      console.error("Upload failed:", { status: resp.status, error: errorData });
      
      VTUtils.notify(
        `vt-error-${itemMeta.id || Date.now()}`, 
        VTUtils.t('notifUploadError'),
        `${safeFilename}\n${errorMsg.substring(0, 80)}`
      );
      
      return;
    }

    let data;
    try {
      data = await resp.json();
    } catch (parseError) {
      console.error("Erreur parsing JSON:", parseError);
      VTUtils.notify(
        `vt-parse-error-${itemMeta.id || Date.now()}`,
        VTUtils.t('notifParseError'),
        VTUtils.t('notifParseErrorMsg')
      );
      return;
    }
    
    console.log("Response data:", data);
    
    const analysisId = data?.data?.id;
    
    if (!analysisId || typeof analysisId !== 'string') {
      console.error("Analysis ID manquant ou invalide:", data);
      VTUtils.notify(
        `vt-error2-${itemMeta.id || Date.now()}`, 
        VTUtils.t('notifVTError'),
        `${safeFilename}\n${VTUtils.t('notifVTErrorMsg')}`
      );
      return;
    }

    console.log("Analysis ID reçu:", analysisId);
    console.log(`Upload réussi en ${uploadDuration}s`);
    
    await pollAndShowReport(analysisId, apiKey, itemMeta);
    
  } catch(e) {
    clearTimeout(timeoutId);
    console.error("Erreur uploadBlobToVT:", e);
    
    let errorTitle = VTUtils.t('notifUploadError');
    let errorMsg = e.message.substring(0, 80);
    
    if (e.name === 'AbortError') {
      errorTitle = VTUtils.t('notifUploadTimeout');
      errorMsg = `${safeFilename}\n${VTUtils.t('notifUploadTimeoutMsg')}`;
    } else if (e.message.includes('NetworkError') || e.message.includes('Failed to fetch')) {
      errorTitle = VTUtils.t('notifNetworkError');
      errorMsg = `${safeFilename}\n${VTUtils.t('notifNetworkErrorMsg')}`;
    }
    
    VTUtils.notify(
      `vt-error-${itemMeta.id || Date.now()}`, 
      errorTitle, 
      errorMsg
    );
  }
}

// === Polling du scan ===
async function pollAndShowReport(id, apiKey, itemMeta) {
  console.log("Démarrage du polling pour:", id);
  
  if (!id || typeof id !== 'string') {
    console.error("ID d'analyse invalide");
    VTUtils.notify(
      `vt-error-invalid-id-${Date.now()}`,
      VTUtils.t('notifError'),
      VTUtils.t('notifInvalidId')
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
      console.log(`Polling tentative ${attempt + 1}/${maxAttempts}`);
      
      if (attempt === 5 && !notifiedSlowScan) {
        const cleanFilename = VTUtils.extractFilename(itemMeta.filename);
        const safeFilename = VTUtils.sanitizeFilename(cleanFilename);
        VTUtils.notify(
          `vt-slow-${id}`,
          VTUtils.t('notifScanSlow'),
          `${safeFilename}\n${VTUtils.t('notifScanSlowMsg')}`
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
      console.log(`Polling response: ${r.status}`);
      
      consecutiveErrors = 0;
      
      if (r.status === 401) {
        console.error("Clé API invalide pendant le polling");
        VTUtils.notify(
          `vt-auth-error-${id}`,
          VTUtils.t('notifError'),
          VTUtils.t('errorApiKeyUnauthorized')
        );
        return;
      }
      
      if (r.status === 429) {
        console.warn("Rate limit atteint, attente prolongée");
        VTUtils.notify(
          `vt-ratelimit-polling-${id}`,
          VTUtils.t('notifRateLimitError'),
          VTUtils.t('notifRateLimitMsg')
        );
        await new Promise(resolve => setTimeout(resolve, 30000));
        continue;
      }
      
      if (r.ok) {
        const j = await r.json();
        const status = j?.data?.attributes?.status;
        
        console.log(`Status: ${status}`);
        
        if (status === "completed") {
          console.log("Scan terminé!");
          const sha256FromAnalysisId = j?.data?.id?.match(/u-([a-f0-9]{64})-/i)?.[1] || null;

          const sha256 = j?.meta?.file_info?.sha256 ||
               sha256FromAnalysisId ||      
               j?.data?.attributes?.sha256 ||
               itemMeta.sha256;
          
          console.log("SHA256:", sha256);
          
          if (sha256 && /^[a-f0-9]{64}$/i.test(sha256)) {
            await fetchFileReportBySha(sha256, apiKey, itemMeta);
            return;
          } else {
            console.log("Pas de SHA256, sauvegarde basique");
            await scanHistory.save({
              filename: itemMeta.filename,
              detections: 0,
              totalEngines: 0,
              timestamp: Date.now()
            });
            
            VTUtils.notify(
              `vt-result-analysis-${id}`, 
              VTUtils.t('notifScanComplete'),
              VTUtils.t('notifScanCompleteMsg')
            );
            return;
          }
        } else if (status === "queued" || status === "in-progress") {
          console.log(`Scan en cours: ${status}`);
        } else {
          console.warn(`Statut inattendu: ${status}`);
        }
      } else {
        console.warn(`Poll response error: ${r.status}`);
        consecutiveErrors++;
        
        if (consecutiveErrors >= maxConsecutiveErrors) {
          console.error("Trop d'erreurs consécutives, abandon du polling");
          VTUtils.notify(
            `vt-polling-failed-${id}`,
            VTUtils.t('notifPollingFailed'),
            `${VTUtils.t('notifPollingFailedMsg')} (HTTP ${r.status})`
          );
          return;
        }
      }
    } catch(e) {
      console.warn("Erreur pendant le polling:", e);
      consecutiveErrors++;
      
      if (e.name === 'AbortError') {
        console.warn("Timeout de la requête de polling");
      }
      
      if (consecutiveErrors >= maxConsecutiveErrors) {
        console.error("Trop d'erreurs consécutives, abandon");
        const cleanFilename = VTUtils.extractFilename(itemMeta.filename);
        const safeFilename = VTUtils.sanitizeFilename(cleanFilename);
        VTUtils.notify(
          `vt-polling-error-${id}`,
          VTUtils.t('notifConsecutiveErrors'),
          `${safeFilename}\n${VTUtils.t('notifConsecutiveErrorsMsg')}`
        );
        return;
      }
    }
    
    console.log(`Attente de ${delay}ms avant nouvelle tentative...`);
    await new Promise(resolve => setTimeout(resolve, delay));
    delay = Math.min(delay * 1.5, maxDelay);
  }

  console.log("Timeout du polling après max tentatives");
  const cleanFilename = VTUtils.extractFilename(itemMeta.filename);
  const safeFilename = VTUtils.sanitizeFilename(cleanFilename);
  VTUtils.notify(
    `vt-timeout-${id}`, 
    VTUtils.t('notifScanPending'),
    `${safeFilename}\n${VTUtils.t('notifScanPendingMsg')}`
  );
}

// === Rapport final ===
async function fetchFileReportBySha(sha256, apiKey, itemMeta) {
  console.log("Fetch rapport pour SHA256:", sha256);
  
  if (!sha256 || !/^[a-f0-9]{64}$/i.test(sha256)) {
    console.error("SHA256 invalide");
    VTUtils.notify(
      `vt-error-invalid-sha-${Date.now()}`,
      VTUtils.t('notifError'),
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
      console.log(`Report response: ${r.status}`);
      
      if (r.status === 401) {
        console.error("Clé API invalide");
        VTUtils.notify(
          `vt-auth-error-${sha256}`,
          VTUtils.t('notifError'),
          VTUtils.t('errorApiKeyUnauthorized')
        );
        return;
      }
      
      if (r.status === 429) {
        console.warn("Rate limit atteint, nouvelle tentative dans 30s");
        await new Promise(resolve => setTimeout(resolve, 30000));
        retries++;
        continue;
      }
      
      if (r.status === 404) {
        console.warn("Rapport non trouvé (404), nouvelle tentative");
        if (retries < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          retries++;
          continue;
        } else {
          VTUtils.notify(
            `vt-not-found-${sha256}`,
            VTUtils.t('notifReportError'),
            "Rapport non disponible sur VirusTotal"
          );
          return;
        }
      }
      
      if (!r.ok) {
        const errorData = await r.json().catch(() => ({}));
        const errorMsg = errorData?.error?.message || `Erreur HTTP ${r.status}`;
        console.error("fetchFileReportBySha failed:", errorData);
        
        if (retries < maxRetries - 1) {
          console.log(`Nouvelle tentative (${retries + 1}/${maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, 3000));
          retries++;
          continue;
        }
        
        VTUtils.notify(
          `vt-err-report-${sha256}`, 
          VTUtils.t('notifReportError'), 
          errorMsg.substring(0, 100)
        );
        return;
      }

      const j = await r.json();
      
      if (!j?.data?.attributes) {
        console.error("Format de réponse invalide");
        VTUtils.notify(
          `vt-invalid-response-${sha256}`,
          VTUtils.t('notifVTError'),
          "Format de réponse VirusTotal invalide"
        );
        return;
      }
      
      const stats = j.data.attributes.last_analysis_stats || {};
      const results = j.data.attributes.last_analysis_results || {};
      
      const detections = parseInt(stats.malicious) || 0;
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

      await scanHistory.save(lastResult);
      await scanCache.set(sha256, lastResult);

      const detectionRate = totalEngines > 0 ? (detections / totalEngines) * 100 : 0;
      
      let title = VTUtils.t('notifFileSafe');
      if (detections > 0 && detectionRate < 10) { 
        title = VTUtils.t('notifFileSuspicious');
      } else if (detectionRate >= 10) { 
        title = VTUtils.t('notifFileDangerous');
      }

      console.log(`Résultat final: ${title} (${detectionRate.toFixed(1)}%)`);

      const cleanFilename = VTUtils.extractFilename(itemMeta.filename);
      const safeFilename = VTUtils.sanitizeFilename(cleanFilename);
      
      VTUtils.notify(
        `vt-result-${sha256}`,
        title,
        `${safeFilename}\n${detections}/${totalEngines} ${VTUtils.t('detections')} (${detectionRate.toFixed(1)}%)`
      );
      
      return;

    } catch(e) {
      console.error("Erreur fetchFileReportBySha:", e);
      
      if (e.name === 'AbortError') {
        console.warn("Timeout de la requête");
      }
      
      if (retries < maxRetries - 1) {
        console.log(`Nouvelle tentative après erreur (${retries + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 3000));
        retries++;
        continue;
      }
      
      const errorMsg = e.name === 'AbortError' 
        ? "Timeout lors de la récupération du rapport"
        : e.message;
      
      VTUtils.notify(
        `vt-error-final-${sha256}`,
        VTUtils.t('notifError'),
        errorMsg.substring(0, 100)
      );
      return;
    }
  }
  
  console.error("Échec après toutes les tentatives");
  VTUtils.notify(
    `vt-all-retries-failed-${sha256}`,
    VTUtils.t('notifError'),
    "Impossible de récupérer le rapport après plusieurs tentatives"
  );
}

// === INITIALISATION ===
(async () => {
  console.log("Initialisation de l'extension...");
  await updateIcon();
  console.log("Extension initialisée, icône mise à jour");
})();

// === PREMIÈRE INSTALLATION - Ouvrir les options ===
browser.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    console.log('[onInstalled] Première installation détectée, ouverture du guide...');
    
    // Marquer que c'est la première installation pour afficher le guide
    await browser.storage.local.set({ 
      first_install: true,
      install_date: Date.now()
    });
    
    // Ouvrir la page d'options
    browser.runtime.openOptionsPage();
  }
});

// Export pour les tests Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { uploadBlobToVT, lookupFileBySHA256 };
}
