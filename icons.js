// === Icônes SVG - Style moderne (inspiré Lucide/itshover) ===

const VTIcons = {
  // Helper pour créer un élément SVG
  createSVGElement(tag, attrs = {}) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.entries(attrs).forEach(([key, value]) => {
      el.setAttribute(key, value);
    });
    return el;
  },

  // Base SVG avec attributs communs
  createBaseSVG(size = 16, strokeWidth = 2) {
    const svg = this.createSVGElement('svg', {
      width: size,
      height: size,
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': strokeWidth,
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round'
    });
    return svg;
  },

  // Play (lecture)
  play(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('polygon', {
      points: '5 3 19 12 5 21 5 3'
    }));
    return svg;
  },

  // Pause
  pause(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('line', { x1: 10, y1: 15, x2: 10, y2: 9 }));
    svg.appendChild(this.createSVGElement('line', { x1: 14, y1: 15, x2: 14, y2: 9 }));
    return svg;
  },

  // Check (validation/sûr)
  check(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('polyline', { points: '20 6 9 17 4 12' }));
    return svg;
  },

  // Alert-triangle (avertissement/suspect)
  alertTriangle(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('path', {
      d: 'm21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z'
    }));
    svg.appendChild(this.createSVGElement('line', { x1: 12, y1: 9, x2: 12, y2: 13 }));
    svg.appendChild(this.createSVGElement('line', { x1: 12, y1: 17, x2: 12.01, y2: 17 }));
    return svg;
  },

  // Shield-alert (malveillant/dangereux)
  shieldAlert(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('path', {
      d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'
    }));
    svg.appendChild(this.createSVGElement('line', { x1: 12, y1: 8, x2: 12, y2: 12 }));
    svg.appendChild(this.createSVGElement('line', { x1: 12, y1: 16, x2: 12.01, y2: 16 }));
    return svg;
  },

  // File-text (fichier)
  fileText(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('path', {
      d: 'M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z'
    }));
    svg.appendChild(this.createSVGElement('polyline', { points: '14 2 14 8 20 8' }));
    svg.appendChild(this.createSVGElement('line', { x1: 16, y1: 13, x2: 8, y2: 13 }));
    svg.appendChild(this.createSVGElement('line', { x1: 16, y1: 17, x2: 8, y2: 17 }));
    svg.appendChild(this.createSVGElement('line', { x1: 10, y1: 9, x2: 8, y2: 9 }));
    return svg;
  },

  // Clock (heure/date)
  clock(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('circle', { cx: 12, cy: 12, r: 10 }));
    svg.appendChild(this.createSVGElement('polyline', { points: '12 6 12 12 16 14' }));
    return svg;
  },

  // Search (détails)
  search(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('circle', { cx: 11, cy: 11, r: 8 }));
    svg.appendChild(this.createSVGElement('line', { x1: 21, y1: 21, x2: 16.65, y2: 16.65 }));
    return svg;
  },

  // Inbox (boîte vide)
  inbox(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('polyline', { points: '22 12 16 12 14 15 10 15 8 12 2 12' }));
    svg.appendChild(this.createSVGElement('path', {
      d: 'M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z'
    }));
    return svg;
  },

  // Database (cache)
  database(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('ellipse', { cx: 12, cy: 5, rx: 9, ry: 3 }));
    svg.appendChild(this.createSVGElement('path', { d: 'M3 5V19A9 3 0 0 0 21 19V5' }));
    svg.appendChild(this.createSVGElement('path', { d: 'M3 12A9 3 0 0 0 21 12' }));
    return svg;
  },

  // X (erreur/fermer)
  x(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('line', { x1: 18, y1: 6, x2: 6, y2: 18 }));
    svg.appendChild(this.createSVGElement('line', { x1: 6, y1: 6, x2: 18, y2: 18 }));
    return svg;
  },

  // Settings (options)
  settings(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('path', {
      d: 'M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.47a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z'
    }));
    svg.appendChild(this.createSVGElement('circle', { cx: 12, cy: 12, r: 3 }));
    return svg;
  },

  // Trash (supprimer)
  trash(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('polyline', { points: '3 6 5 6 21 6' }));
    svg.appendChild(this.createSVGElement('path', {
      d: 'M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2'
    }));
    return svg;
  },

  // Refresh (recharger)
  refresh(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('path', {
      d: 'M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8'
    }));
    svg.appendChild(this.createSVGElement('path', {
      d: 'M21 3v5h-5'
    }));
    svg.appendChild(this.createSVGElement('path', {
      d: 'M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16'
    }));
    svg.appendChild(this.createSVGElement('path', {
      d: 'M8 16H3v5'
    }));
    return svg;
  },

  // Help-circle (question)
  helpCircle(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('circle', { cx: 12, cy: 12, r: 10 }));
    svg.appendChild(this.createSVGElement('path', { d: 'M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3' }));
    svg.appendChild(this.createSVGElement('line', { x1: 12, y1: 17, x2: 12.01, y2: 17 }));
    return svg;
  },

  // Shield-check (sécurisé/protégé)
  shieldCheck(size = 16) {
    const svg = this.createBaseSVG(size);
    svg.appendChild(this.createSVGElement('path', {
      d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'
    }));
    svg.appendChild(this.createSVGElement('polyline', { points: '9 12 12 15 16 10' }));
    return svg;
  },

  // === Helper pour insérer une icône avec du texte ===
  
  // Crée un span contenant l'icône + texte optionnel
  createIconSpan(iconName, options = {}) {
    const {
      size = 16,
      className = 'vt-icon',
      text = '',
      textAfter = true
    } = options;

    const span = document.createElement('span');
    span.className = className;
    
    if (typeof iconName === 'string' && this[iconName]) {
      const icon = this[iconName](size);
      span.appendChild(icon);
    }
    
    if (text) {
      if (textAfter) {
        span.appendChild(document.createTextNode(' ' + text));
      } else {
        span.insertBefore(document.createTextNode(text + ' '), span.firstChild);
      }
    }
    
    return span;
  },

  // Raccourcis pratiques pour le popup
  iconWithText(iconName, text, size = 16) {
    return this.createIconSpan(iconName, { size, text, textAfter: true });
  },

  textWithIcon(text, iconName, size = 16) {
    return this.createIconSpan(iconName, { size, text, textAfter: false });
  }
};

// Export pour utilisation dans les modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = VTIcons;
}
