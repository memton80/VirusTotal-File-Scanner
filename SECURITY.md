# 🔒 Politique de sécurité — VirusTotal-Scanner

---

## 📦 Versions prises en charge / Supported Versions

| Version | Supportée / Supported |
|--------:|:---------------------:|
| 1.3.x   | ✅ Oui / Yes          |
| 1.2.x   | ❌ Non / No           |
| < 1.0   | ❌ Non / No           |

Les correctifs de sécurité sont appliqués uniquement sur les branches **stables et récentes** (`main`, `1.x`).  
Security fixes are only applied to **stable, recent** branches (`main`, `1.x`).

---

## 🐛 Signaler une vulnérabilité / Reporting a Vulnerability

### 🇫🇷 En français
Si tu découvres une faille dans **VirusTotal-Scanner**, **n’ouvre pas d’issue publique** contenant des détails exploitables ou des données sensibles (clés API, échantillons, tokens). Utilise plutôt une des méthodes suivantes :

- 📬 Via le **formulaire de sécurité GitHub** du dépôt : [Security Advisory](https://github.com/memton80/VirusTotal-Scanner/security/advisories)  
- 🔗 Ou contacte directement le mainteneur : **[@memton80](https://github.com/memton80)**

#### ⏱ Délais attendus :
- Réponse initiale sous **72 heures**
- Analyse complète sous **7 jours**
- Correctif publié sous **14 jours** (généralement)

---

### 🇬🇧 In English
If you find a vulnerability in **VirusTotal-Scanner**, **please do not open a public issue** exposing exploit details or sensitive data (API keys, samples, tokens). Use one of the following channels:

- 📬 Through the repository’s **GitHub Security Advisory form**: [Security Advisory](https://github.com/memton80/VirusTotal-Scanner/security/advisories)  
- 🔗 Or contact the maintainer directly: **[@memton80](https://github.com/memton80)**

#### ⏱ Expected response time:
- Initial reply within **72 hours**
- Full investigation within **7 days**
- Patch released within **14 days** (typically)

---

## 🧩 Processus après signalement / After-Report Process

| Étape / Step | Description |
|-------------:|:-----------|
| 🔍 Analyse / Review | Reproduction et évaluation en interne. Impact sur les utilisateurs et les clés API vérifié. |
| 🧱 Correctif / Fix | Développement du correctif sur une branche privée si nécessaire. |
| 🚀 Publication / Release | Publication d’une release / advisory publique une fois le correctif prêt. |
| 💬 Crédits / Credits | Le reporter peut être crédité s’il le souhaite. |

---

## 🧱 Bonnes pratiques / Best Practices

### 🇫🇷 Pour les contributeurs & utilisateurs
- 🔐 **Ne publie jamais de clés API, tokens ou secrets** dans un issue, PR ou code accessible publiquement.  
- 🧪 **Teste dans un environnement isolé** (VM, conteneur, sandbox). Ne teste pas en production avec des clés réelles.  
- 🚫 **Ne partage pas publiquement d’échantillons malveillants** — utilise des canaux privés et sécurisés pour l’échange si nécessaire.  
- 🔄 Utilise des **pull requests** pour les améliorations fonctionnelles ; n’utilise pas une PR pour divulguer une vulnérabilité.  
- 📝 Fournis des **logs minimalistes** lors du signalement : seulement ce qui est nécessaire pour reproduire le problème, en supprimant toute donnée sensible.  
- ⚖️ Respecte les conditions d’utilisation de l’API VirusTotal et les lois applicables quand tu testes des fichiers ou des URL.

### 🇬🇧 For contributors & users
- 🔐 **Never publish API keys, tokens or secrets** in issues, PRs or public code.  
- 🧪 **Test in an isolated environment** (VM, container, sandbox). Avoid running tests in production with live keys.  
- 🚫 **Do not share malware samples publicly** — use secure private channels if sample exchange is necessary.  
- 🔄 Use **pull requests** for feature fixes; don’t disclose vulnerabilities through PRs.  
- 📝 Provide **minimal supporting logs** when reporting — remove any sensitive data.  
- ⚖️ Follow VirusTotal’s API terms of service and applicable laws when scanning files or URLs.

---

© 2025 [memton80](https://github.com/memton80) — **VirusTotal-Scanner**
