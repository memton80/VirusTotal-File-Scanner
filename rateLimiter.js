// === RateLimiter - Gestion des limites de requêtes API ===
// Les timestamps sont persistés dans storage pour survivre aux redémarrages du background script (MV3).

console.log('[rateLimiter.js] Chargé');

const rateLimiter = {
  maxRequests: 4,
  timeWindow: 60000, // 1 minute
  STORAGE_KEY: 'vt_ratelimiter_timestamps',

  async _load() {
    try {
      const r = await browser.storage.local.get(this.STORAGE_KEY);
      const raw = r[this.STORAGE_KEY];
      const now = Date.now();
      return Array.isArray(raw) ? raw.filter(t => now - t < this.timeWindow) : [];
    } catch (e) {
      return [];
    }
  },

  async _save(requests) {
    try {
      await browser.storage.local.set({ [this.STORAGE_KEY]: requests });
    } catch (e) {
      console.error("[RateLimiter] Erreur sauvegarde:", e);
    }
  },

  async checkAndWait() {
    try {
      let requests = await this._load();

      if (requests.length >= this.maxRequests) {
        const oldestReq = requests[0];
        const waitTime = this.timeWindow - (Date.now() - oldestReq) + 1000;
        console.warn(`[RateLimiter] Limite atteinte. Attente de ${Math.ceil(waitTime/1000)}s`);
        await new Promise(r => setTimeout(r, waitTime));
        requests = await this._load();
      }

      requests.push(Date.now());
      await this._save(requests);
      console.log(`[RateLimiter] ${requests.length}/${this.maxRequests} requêtes`);
    } catch (e) {
      console.error("[RateLimiter] Erreur:", e);
    }
  },

  async reset() {
    await browser.storage.local.remove(this.STORAGE_KEY);
    console.log("[RateLimiter] Réinitialisé");
  },

  async getStatus() {
    const requests = await this._load();
    return {
      current: requests.length,
      max: this.maxRequests,
      remaining: Math.max(0, this.maxRequests - requests.length)
    };
  }
};

// Export pour les tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { rateLimiter };
}
