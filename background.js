// === VirusTotal Auto Scanner (Firefox) ===
// Analyse automatique des fichiers téléchargés via VirusTotal v3

const VT_UPLOAD_ENDPOINT = "https://www.virustotal.com/api/v3/files";

// --- 🔐 Récupère la clé API ---
async function getApiKey() {
  const r = await browser.storage.local.get("vt_api_key");
  return r.vt_api_key || null;
}

// --- 🔔 Notification safe ---
function notify(id, title, message) {
  try {
    browser.notifications.create(id, {
      type: "basic",
      iconUrl: browser.extension.getURL("icons/icon-48.png"),
      title: title || "VT Scan",
      message: message || ""
    }).catch(e => console.warn("Erreur notif :", e));
  } catch(e) {
    console.warn("Erreur notif globale :", e);
  }
}

// --- 🧾 Sauvegarde dans l'historique ---
async function saveResult(result) {
  const s = await browser.storage.local.get('scan_history');
  const history = s.scan_history || [];
  history.unshift(result);
  if (history.length > 10) history.length = 10;
  await browser.storage.local.set({ scan_history: history, last_scan_result: result });
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
      notify(`vt-no-api-${item.id}`, "VT Scanner — Clé manquante", "Configure ta clé API dans les options.");
      return;
    }

    notify(`vt-start-${item.id}`, "Scan démarré",
           `Upload de "${item.filename || "fichier inconnu"}" vers VirusTotal...`);

    const url = item.url;
    if (url && /^https?:\/\//i.test(url)) {
      try {
        const resp = await fetch(url, { credentials: 'include' });
        if (!resp.ok) throw new Error("fetch failed");
        const blob = await resp.blob();
        await uploadBlobToVT(blob, apiKey, item);
        return;
      } catch (e) {
        console.warn("Échec du fetch :", e);
      }
    }

    notify(`vt-manual-${item.id}`, "Scan manuel requis",
           "Impossible de récupérer le fichier automatiquement. Ouvre le popup et choisis le fichier pour le scanner.");
  } catch (err) {
    console.error("Erreur background onChanged:", err);
  }
});

// --- 📤 Upload vers VirusTotal ---
async function uploadBlobToVT(blob, apiKey, itemMeta = {}) {
  const fd = new FormData();
  fd.append("file", blob, itemMeta.filename || "upload.bin");

  try {
    const resp = await fetch(VT_UPLOAD_ENDPOINT, {
      method: "POST",
      headers: { "x-apikey": apiKey },
      body: fd
    });

    if (!resp.ok) {
      let txt = await resp.text().catch(()=> "");
      notify(`vt-error-${itemMeta.id || Date.now()}`, "Erreur d'upload VT",
             `Code: ${resp.status}`);
      console.warn("Upload failed", resp.status, txt);
      return;
    }

    const data = await resp.json();
    const analysisId = data?.data?.id;
    if (!analysisId) {
      notify(`vt-error2-${itemMeta.id || Date.now()}`, "Erreur VT",
             "Réponse inattendue du service.");
      return;
    }

    await pollAndShowReport(analysisId, apiKey, itemMeta);
  } catch(e) {
    console.error("Erreur uploadBlobToVT:", e);
    notify(`vt-error-${itemMeta.id || Date.now()}`, "Erreur d'upload", e.message);
  }
}

// --- 🔁 Polling du scan ---
async function pollAndShowReport(id, apiKey, itemMeta) {
  const analysesUrl = `https://www.virustotal.com/api/v3/analyses/${id}`;
  for (let i = 0; i < 18; i++) { // 18*5s = 90s
    try {
      const r = await fetch(analysesUrl, { headers: { "x-apikey": apiKey } });
      if (r.ok) {
        const j = await r.json();
        const status = j?.data?.attributes?.status;
        if (status === "completed") {
          const sha256 = j?.meta?.file_info?.sha256 || j?.data?.id || j?.data?.attributes?.sha256;
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
            notify(`vt-result-analysis-${id}`, "Scan terminé",
                   "Résultats disponibles dans le popup.");
            return;
          }
        }
      } else {
        const txt = await r.text().catch(()=> "");
        console.warn("poll response not ok", r.status, txt);
      }
    } catch(e) {
      console.warn("Erreur pendant le polling:", e);
    }
    await new Promise(r => setTimeout(r, 5000));
  }

  notify(`vt-timeout-${id}`, "Scan en attente",
         "L'analyse prend plus de temps que prévu. Vérifie le popup.");
}

// --- 📊 Rapport final ---
async function fetchFileReportBySha(sha256, apiKey, itemMeta) {
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, { headers: { "x-apikey": apiKey } });
    if (!r.ok) {
      const txt = await r.text().catch(()=> "");
      console.warn("fetchFileReportBySha failed", r.status, txt);
      notify(`vt-err-report-${sha256}`, "Erreur rapport", `Code: ${r.status}`);
      return;
    }

    const j = await r.json();
    const stats = j?.data?.attributes?.last_analysis_stats || {};
    const results = j?.data?.attributes?.last_analysis_results || {};
    const detections = stats.malicious || 0;

    const lastResult = {
      sha256,
      detections,
      perEngine: results,
      timestamp: Date.now(),
      filename: itemMeta.filename
    };

    await saveResult(lastResult);

    let emoji = "✅", title = "Fichier sûr";
    if (detections > 0 && detections <= 3) { emoji="⚠️"; title="Fichier suspect"; }
    else if (detections > 3) { emoji="🚨"; title="Fichier dangereux !"; }

    notify(
      `vt-result-${sha256}`,
      `${emoji} ${title}`,
      `${itemMeta.filename || "fichier inconnu"} — ${detections} détection(s)`
    );

  } catch(e) {
    console.error("Erreur fetchFileReportBySha:", e);
  }
}

// --- 🧾 Fallback analyse ---
function showReportSummaryFromAnalysis(analysisJson, itemMeta) {
  saveResult({
    filename: itemMeta.filename,
    analysisJson,
    timestamp: Date.now(),
    detections: 0
  });
  notify(`vt-result-analysis-${itemMeta.id || Date.now()}`, "Scan terminé",
         "Résultats disponibles dans le popup.");
}
