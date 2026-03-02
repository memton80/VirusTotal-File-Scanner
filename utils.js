// === Utils - Helpers communs pour VirusTotal Scanner ===

console.log('[utils.js] Chargé');

const VTUtils = {
  // === i18n Helper ===
  t(key) {
    return browser.i18n.getMessage(key) || key;
  },

  translatePage() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const translation = this.t(key);
      
      if (el.tagName === 'INPUT' && el.type === 'text') {
        el.placeholder = translation;
      } else {
        el.textContent = translation;
      }
    });
    
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      el.title = this.t(key);
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      el.placeholder = this.t(key);
    });
  },

  // === SÉCURITÉ ===
  escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
  },

  isValidApiKey(key) {
    return typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key);
  },

  sanitizeFilename(filename) {
    if (!filename || typeof filename !== 'string') return 'unknown_file';
    return filename.substring(0, 255).replace(/[<>:"/\\|?*\x00-\x1F]/g, '_');
  },

  sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return null;
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
      return parsed.href;
    } catch {
      return null;
    }
  },

  extractFilename(fullPath) {
    if (!fullPath || typeof fullPath !== 'string') return 'unknown_file';
    let filename = fullPath;
    if (filename.includes('/')) filename = filename.split('/').pop();
    if (filename.includes('\\')) filename = filename.split('\\').pop();
    return filename || 'unknown_file';
  },

  sanitizeNumber(value, defaultValue = 0) {
    const num = parseInt(value, 10);
    return isNaN(num) ? defaultValue : Math.max(0, num);
  },

  // === SHA-256 ===
  async calculateSHA256(blob) {
    try {
      console.log("[SHA256] Calcul du hash...");
      const arrayBuffer = await blob.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      console.log(`[SHA256] Hash calculé: ${hashHex.substring(0, 16)}...`);
      return hashHex;
    } catch (e) {
      console.error("[SHA256] Erreur calcul:", e);
      return null;
    }
  },

  // === THEMES ===
  async loadTheme() {
    const result = await browser.storage.local.get('darkMode');
    const isDark = result.darkMode || false;
    document.body.classList.toggle('dark-mode', isDark);
    return isDark;
  },

  async toggleTheme() {
    const isDark = document.body.classList.toggle('dark-mode');
    await browser.storage.local.set({ darkMode: isDark });
    return isDark;
  },

  // === NOTIFICATIONS ===
  notify(id, title, message) {
    try {
      const safeId = String(id).substring(0, 100);
      const safeTitle = String(title).substring(0, 100);
      const safeMessage = String(message).substring(0, 200);
      
      console.log(`[Notification] ${safeTitle} - ${safeMessage}`);
      
      browser.notifications.create(safeId, {
        type: "basic",
        iconUrl: browser.runtime.getURL("icons/icon-48.png"),
        title: safeTitle,
        message: safeMessage
      }).catch(e => console.warn("[Notification] Erreur:", e));
    } catch(e) {
      console.warn("[Notification] Erreur globale:", e);
    }
  },

  // === SCANNING STATE ===
  async isScanningEnabled() {
    try {
      const result = await browser.storage.local.get('scanning_enabled');
      const enabled = result.scanning_enabled !== false;
      console.log(`[Scan] Surveillance: ${enabled ? 'ACTIVE' : 'EN PAUSE'}`);
      return enabled;
    } catch (err) {
      console.error("[Scan] Erreur vérification état:", err);
      return true;
    }
  },

  async setScanningState(enabled) {
    await browser.storage.local.set({ scanning_enabled: enabled });
  },

  // === API KEY ===
  async getApiKey() {
    try {
      console.log("[API] Récupération de la clé...");
      const r = await browser.storage.local.get("vt_api_key");
      const key = r.vt_api_key;
      
      if (!this.isValidApiKey(key)) {
        console.error("[API] Clé invalide ou manquante");
        return null;
      }
      
      console.log(`[API] Clé valide: ${key.substring(0, 8)}...${key.substring(56)}`);
      return key;
    } catch (err) {
      console.error("[API] Erreur récupération:", err);
      return null;
    }
  }
};

// Pour compatibilité avec le code existant
const t = VTUtils.t.bind(VTUtils);
const escapeHtml = VTUtils.escapeHtml.bind(VTUtils);
const isValidApiKey = VTUtils.isValidApiKey.bind(VTUtils);
const sanitizeFilename = VTUtils.sanitizeFilename.bind(VTUtils);
const sanitizeUrl = VTUtils.sanitizeUrl.bind(VTUtils);
const extractFilename = VTUtils.extractFilename.bind(VTUtils);
const sanitizeNumber = VTUtils.sanitizeNumber.bind(VTUtils);
const calculateSHA256 = VTUtils.calculateSHA256.bind(VTUtils);
const loadTheme = VTUtils.loadTheme.bind(VTUtils);
const toggleTheme = VTUtils.toggleTheme.bind(VTUtils);
const notify = VTUtils.notify.bind(VTUtils);
const isScanningEnabled = VTUtils.isScanningEnabled.bind(VTUtils);
const setScanningState = VTUtils.setScanningState.bind(VTUtils);
const getApiKey = VTUtils.getApiKey.bind(VTUtils);
const translatePage = VTUtils.translatePage.bind(VTUtils);

// Export pour les tests Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VTUtils };
}
