// === RateLimiter - Gestion des limites de requêtes API ===

console.log('[rateLimiter.js] Chargé');

const rateLimiter = {
  requests: [],
  maxRequests: 4,
  timeWindow: 60000, // 1 minute

  async checkAndWait() {
    try {
      const now = Date.now();
      this.requests = this.requests.filter(t => now - t < this.timeWindow);
      
      if (this.requests.length >= this.maxRequests) {
        const oldestReq = this.requests[0];
        const waitTime = this.timeWindow - (now - oldestReq) + 1000;
        console.warn(`[RateLimiter] Limite atteinte. Attente de ${Math.ceil(waitTime/1000)}s`);
        await new Promise(r => setTimeout(r, waitTime));
        this.requests = this.requests.filter(t => Date.now() - t < this.timeWindow);
      }
      
      this.requests.push(now);
      console.log(`[RateLimiter] ${this.requests.length}/${this.maxRequests} requêtes`);
    } catch (e) {
      console.error("[RateLimiter] Erreur:", e);
    }
  },

  reset() {
    this.requests = [];
    console.log("[RateLimiter] Réinitialisé");
  },

  getStatus() {
    const now = Date.now();
    const validRequests = this.requests.filter(t => now - t < this.timeWindow);
    return {
      current: validRequests.length,
      max: this.maxRequests,
      remaining: Math.max(0, this.maxRequests - validRequests.length)
    };
  }
};

// Export pour les tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { rateLimiter };
}
