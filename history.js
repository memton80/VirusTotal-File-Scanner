// === History - Gestion de l'historique des scans ===

console.log('[history.js] Chargé');

const scanHistory = {
  MAX_HISTORY: 20,

  async save(result) {
    try {
      console.log("[History] Sauvegarde du résultat:", result);
      
      const safeResult = {
        filename: VTUtils.sanitizeFilename(VTUtils.extractFilename(result.filename)),
        detections: VTUtils.sanitizeNumber(result.detections, 0),
        totalEngines: VTUtils.sanitizeNumber(result.totalEngines, 0),
        sha256: (result.sha256 && /^[a-f0-9]{64}$/i.test(result.sha256)) ? result.sha256 : null,
        timestamp: Date.now(),
        perEngine: result.perEngine || null,
        skipped: result.skipped || false,
        reason: result.reason || null
      };
      
      const s = await browser.storage.local.get('scan_history');
      const history = Array.isArray(s.scan_history) ? s.scan_history : [];
      
      history.unshift(safeResult);
      if (history.length > this.MAX_HISTORY) history.length = this.MAX_HISTORY;
      
      await browser.storage.local.set({ 
        scan_history: history, 
        last_scan_result: safeResult 
      });
      
      console.log("[History] Résultat sauvegardé");
    } catch (err) {
      console.error("[History] Erreur sauvegarde:", err);
    }
  },

  async getAll() {
    try {
      const s = await browser.storage.local.get('scan_history');
      return Array.isArray(s.scan_history) ? s.scan_history : [];
    } catch (err) {
      console.error("[History] Erreur récupération:", err);
      return [];
    }
  },

  async getLast() {
    try {
      const s = await browser.storage.local.get('last_scan_result');
      return s.last_scan_result || null;
    } catch (err) {
      console.error("[History] Erreur récupération dernier scan:", err);
      return null;
    }
  },

  async clear() {
    try {
      await browser.storage.local.remove(["scan_history", "last_scan_result"]);
      console.log("[History] Historique effacé");
    } catch (err) {
      console.error("[History] Erreur suppression:", err);
      throw err;
    }
  }
};

// Export pour les tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { scanHistory };
}
