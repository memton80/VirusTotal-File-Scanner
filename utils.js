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

  // === MODE VÉRIFICATION SEULE (lookup par hash, jamais d'upload) ===
  async isLookupOnlyEnabled() {
    try {
      const r = await browser.storage.local.get('lookup_only');
      return r.lookup_only === true;
    } catch (err) {
      console.error("[Scan] Erreur lecture mode vérification seule:", err);
      return false;
    }
  },

  async setLookupOnlyState(enabled) {
    await browser.storage.local.set({ lookup_only: enabled === true });
  },

  // === CHIFFREMENT DE LA CLÉ API (AES-256-GCM) ===
  // La clé API n'est plus stockée en clair dans storage.local : elle est
  // chiffrée avec un CryptoKey AES-256-GCM NON extractible, rangé dans
  // IndexedDB. Son matériau n'est jamais exposé au JavaScript.
  // Limite honnête : sans mot de passe maître, quelqu'un qui contrôle tout
  // le profil Firefox peut encore déchiffrer. Cela protège contre la lecture
  // directe de storage.local (sauvegardes, inspection du disque, sync).

  _cryptoKeyPromise: null,

  _openKeystore() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('vt_keystore', 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains('keys')) {
          req.result.createObjectStore('keys');
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('keystore bloqué'));
    });
  },

  _idbGet(db, key) {
    return new Promise((resolve, reject) => {
      const req = db.transaction('keys', 'readonly').objectStore('keys').get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },

  _idbAdd(db, key, value) {
    // add() (et non put()) : échoue si la clé existe déjà, ce qui rend la
    // création atomique quand deux pages démarrent en même temps
    return new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').add(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('transaction annulée'));
    });
  },

  async _keyFromIndexedDB() {
    const db = await this._openKeystore();
    try {
      let key = await this._idbGet(db, 'aes-gcm-v1');
      if (key) return key;
      const fresh = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false, // non extractible
        ['encrypt', 'decrypt']
      );
      try {
        await this._idbAdd(db, 'aes-gcm-v1', fresh);
        return fresh;
      } catch (e) {
        // Un autre contexte a créé la clé entre-temps — relire la sienne
        key = await this._idbGet(db, 'aes-gcm-v1');
        if (key) return key;
        throw e;
      }
    } finally {
      db.close();
    }
  },

  // Repli si IndexedDB est indisponible : clé de chiffrement dans
  // storage.local. Moins bon (clé et données au même endroit) mais
  // l'extension reste fonctionnelle.
  async _keyFromStorageFallback() {
    const r = await browser.storage.local.get('vt_kek');
    let raw;
    if (r.vt_kek) {
      raw = this._b64ToBytes(r.vt_kek);
    } else {
      raw = crypto.getRandomValues(new Uint8Array(32));
      await browser.storage.local.set({ vt_kek: this._bytesToB64(raw) });
    }
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  },

  _getCryptoKey() {
    if (!this._cryptoKeyPromise) {
      this._cryptoKeyPromise = this._keyFromIndexedDB().catch((e) => {
        console.warn('[Crypto] IndexedDB indisponible, repli sur storage.local:', e);
        return this._keyFromStorageFallback();
      }).catch((e) => {
        this._cryptoKeyPromise = null;
        throw e;
      });
    }
    return this._cryptoKeyPromise;
  },

  _bytesToB64(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  },

  _b64ToBytes(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },

  async _encryptString(text) {
    const key = await this._getCryptoKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(text)
    );
    return { v: 1, iv: this._bytesToB64(iv), data: this._bytesToB64(new Uint8Array(ct)) };
  },

  async _decryptString(payload) {
    if (!payload || payload.v !== 1 || !payload.iv || !payload.data) {
      throw new Error('format de payload chiffré inconnu');
    }
    const key = await this._getCryptoKey();
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: this._b64ToBytes(payload.iv) },
      key,
      this._b64ToBytes(payload.data)
    );
    return new TextDecoder().decode(pt);
  },

  // === API KEY ===
  async setApiKey(key) {
    if (!this.isValidApiKey(key)) throw new Error('Clé API invalide');
    const payload = await this._encryptString(key);
    await browser.storage.local.set({ vt_api_key_enc: payload });
    // Effacer l'ancien emplacement en clair (versions <= 1.8.7)
    await browser.storage.local.remove('vt_api_key');
  },

  async clearApiKey() {
    await browser.storage.local.remove(['vt_api_key', 'vt_api_key_enc']);
  },

  async getApiKey() {
    try {
      console.log("[API] Récupération de la clé...");
      const r = await browser.storage.local.get(['vt_api_key', 'vt_api_key_enc']);

      // Migration : clé encore en clair (installée avec une version <= 1.8.7)
      if (this.isValidApiKey(r.vt_api_key)) {
        try {
          await this.setApiKey(r.vt_api_key);
          console.log('[API] Clé migrée vers le stockage chiffré');
        } catch (e) {
          // Si le chiffrement échoue, on garde la clé en clair plutôt que
          // de casser l'extension — la migration sera retentée au prochain appel
          console.warn('[API] Migration impossible, clé conservée en clair:', e);
        }
        console.log('[API] Clé valide: ********');
        return r.vt_api_key;
      }

      if (r.vt_api_key_enc) {
        const key = await this._decryptString(r.vt_api_key_enc);
        if (!this.isValidApiKey(key)) {
          console.error('[API] Clé déchiffrée invalide');
          return null;
        }
        console.log('[API] Clé valide: ********');
        return key;
      }

      console.error("[API] Clé invalide ou manquante");
      return null;
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
const isLookupOnlyEnabled = VTUtils.isLookupOnlyEnabled.bind(VTUtils);
const setLookupOnlyState = VTUtils.setLookupOnlyState.bind(VTUtils);
const getApiKey = VTUtils.getApiKey.bind(VTUtils);
const setApiKey = VTUtils.setApiKey.bind(VTUtils);
const clearApiKey = VTUtils.clearApiKey.bind(VTUtils);
const translatePage = VTUtils.translatePage.bind(VTUtils);

// Export pour les tests Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VTUtils };
}
