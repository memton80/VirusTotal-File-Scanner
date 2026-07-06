// === Cache - Gestion du cache SHA-256 local ===

console.log('[cache.js] Chargé');

const scanCache = {
  MAX_AGE: 7 * 24 * 60 * 60 * 1000, // 7 jours

  _getKey(sha256) {
    return `cache_${sha256}`;
  },

  async get(sha256) {
    try {
      const cacheKey = this._getKey(sha256);
      const result = await browser.storage.local.get(cacheKey);
      const cached = result[cacheKey];
      
      if (cached && cached.timestamp) {
        const age = Date.now() - cached.timestamp;
        
        if (age < this.MAX_AGE) {
          console.log(`[Cache] Résultat trouvé (${Math.floor(age / 1000 / 60 / 60)}h)`);
          return cached;
        } else {
          console.log("[Cache] Entrée expirée");
          await this.remove(sha256);
        }
      }
      return null;
    } catch (e) {
      console.error("[Cache] Erreur lecture:", e);
      return null;
    }
  },

  async set(sha256, data) {
    try {
      const cacheData = {
        ...data,
        timestamp: Date.now()
      };
      await browser.storage.local.set({ [this._getKey(sha256)]: cacheData });
      console.log("[Cache] Résultat mis en cache");
    } catch (e) {
      console.error("[Cache] Erreur écriture:", e);
    }
  },

  async remove(sha256) {
    try {
      await browser.storage.local.remove(this._getKey(sha256));
    } catch (e) {
      console.error("[Cache] Erreur suppression:", e);
    }
  },

  async clearAll() {
    try {
      const all = await browser.storage.local.get();
      const cacheKeys = Object.keys(all).filter(k => k.startsWith('cache_'));
      if (cacheKeys.length > 0) {
        await browser.storage.local.remove(cacheKeys);
        console.log(`[Cache] ${cacheKeys.length} entrées supprimées`);
      }
    } catch (e) {
      console.error("[Cache] Erreur nettoyage:", e);
    }
  }
};

// Export pour les tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { scanCache };
}
