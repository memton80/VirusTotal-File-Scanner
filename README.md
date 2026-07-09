# VirusTotal File Scanner

[![Version Firefox](https://img.shields.io/amo/v/virustotal-file-scanner?label=Firefox&style=for-the-badge&logo=firefox)](https://addons.mozilla.org/fr/firefox/addon/virustotal-file-scanner/)
[![Licence](https://img.shields.io/github/license/memton80/VirusTotal-File-Scanner?style=for-the-badge&label=Licence)](https://github.com/memton80/VirusTotal-File-Scanner/blob/main/LICENSE)
[![Statut](https://img.shields.io/badge/Statut-Stable-orange?style=for-the-badge)](https://github.com/memton80/VirusTotal-File-Scanner)

**Chaque fichier que vous téléchargez, passé au crible de plus de 70 antivirus. Automatiquement, sans rien faire.**

*(An English summary is available [at the end of this page](#english).)*

---

## L'idée

Télécharger un fichier, c'est toujours un petit acte de confiance. Ce programme d'installation est-il vraiment celui qu'il prétend être ? Cette archive contient-elle autre chose que ce qu'on vous a promis ?

VirusTotal répond à cette question depuis des années : un service qui fait analyser un même fichier par plus de 70 moteurs antivirus (Kaspersky, BitDefender, ESET et bien d'autres) et croise leurs verdicts. Encore faut-il penser à s'en servir.

C'est là qu'intervient cette extension Firefox : elle s'en souvient pour vous. Dès qu'un téléchargement se termine, le fichier est vérifié sur VirusTotal et le verdict arrive en notification. Vous n'avez rien à lancer, rien à copier-coller, rien à retenir.

## Ce qu'elle fait pour vous

**Elle surveille, vous décidez.** Chaque téléchargement terminé est analysé en arrière-plan. Fichier sain, suspect ou malveillant : une notification vous donne le verdict, et l'historique complet reste accessible d'un clic sur l'icône de la barre d'outils.

**Elle vous montre le détail.** Pour chaque fichier analysé, vous pouvez déplier le rapport moteur par moteur : qui a détecté quoi, et sous quel nom. Un lien ouvre le rapport complet sur le site de VirusTotal (avis de la communauté, analyse comportementale). Pas de verdict opaque.

**Elle protège vos documents personnels.** Un fichier envoyé sur VirusTotal devient consultable publiquement. Pour éviter les accidents, l'extension repère les noms de fichiers sensibles (relevés bancaires, documents d'identité, dossiers médicaux...) et refuse de les envoyer. Et pour une tranquillité totale, un mode « vérification seule » interroge VirusTotal uniquement par empreinte SHA-256 : rien n'est jamais envoyé, les fichiers inconnus sont simplement signalés.

**Elle sait se faire oublier.** Un bouton pause suspend la surveillance quand vous en avez besoin, et l'extension respecte d'elle-même les limites de l'API gratuite de VirusTotal. Pas de configuration, pas d'entretien.

**Elle parle votre langue.** Interface disponible en français, anglais, allemand, espagnol, italien, polonais, portugais et russe.

## Une interface pixel art

Depuis la version 1.8.5, l'extension arbore une interface rétro assumée : orange et blanc en mode clair, orange et noir en mode sombre. Coins carrés, cadres crantés façon 8-bit, ombres franches et notifications qui clignotent comme sur une borne d'arcade. La sécurité, c'est sérieux ; l'interface n'est pas obligée de l'être.

## Démarrer en trois minutes

1. **Installez l'extension** depuis le [catalogue officiel Mozilla Add-ons](https://addons.mozilla.org/fr/firefox/addon/virustotal-file-scanner/).
2. **Créez un compte gratuit** sur [VirusTotal.com](https://www.virustotal.com/) et récupérez votre clé API personnelle.
3. **Collez la clé** dans la page d'options de l'extension. Un guide pas à pas vous accompagne au premier lancement.

C'est tout. Votre prochain téléchargement sera analysé automatiquement.

## Vos données restent chez vous

- Votre clé API est chiffrée (AES-256-GCM) et stockée localement dans votre navigateur, jamais transmise à un tiers.
- L'extension ne communique qu'avec VirusTotal, en HTTPS. Aucune télémétrie, aucune collecte.
- Le code source est entièrement ouvert, dans ce dépôt, sous licence Mozilla Public License 2.0.

**Une chose à garder en tête :** tout fichier envoyé sur VirusTotal devient public et consultable par n'importe qui. Le filtre de fichiers sensibles est un garde-fou, pas une garantie absolue. Ne comptez que sur vous pour les documents confidentiels.

## Bon à savoir

L'extension s'appuie sur l'API publique et gratuite de VirusTotal : 4 requêtes par minute, 500 par jour, fichiers jusqu'à 32 Mo. Ces limites sont gérées automatiquement, mais elles s'appliquent. Pour un usage intensif, VirusTotal propose des [offres payantes](https://support.virustotal.com/hc/en-us/articles/115002100149).

Ce projet est indépendant : il n'est affilié ni à VirusTotal, ni à Google.

## Envie de participer ?

Un bug, une idée, une traduction à améliorer ? Les [issues](https://github.com/memton80/VirusTotal-File-Scanner/issues) et les pull requests sont les bienvenues. Le projet évolue régulièrement, et une version 2 est dans les cartons.

---

## English

**VirusTotal File Scanner** is a Firefox extension that automatically checks every file you download against more than 70 antivirus engines through the public [VirusTotal](https://www.virustotal.com/) API. As soon as a download finishes, the file is analyzed in the background and the verdict arrives as a notification, with a full per-engine report available from the toolbar popup.

It keeps your privacy in mind: your API key is encrypted and stored locally, the extension only ever talks to VirusTotal, and a built-in filter refuses to upload files whose names look sensitive (bank statements, ID documents, medical records...) since anything uploaded to VirusTotal becomes publicly searchable. A strict hash-check only mode goes further and never uploads anything at all: files are checked by their SHA-256 hash, and unknown ones are simply flagged.

Setup takes three minutes: install it from [Mozilla Add-ons](https://addons.mozilla.org/en-US/firefox/addon/virustotal-file-scanner/), grab a free API key from VirusTotal, and paste it into the options page, where a step-by-step guide walks you through it. The interface is available in eight languages, with a retro pixel art look in both light (orange and white) and dark (orange and black) modes.

The project is open source under the Mozilla Public License 2.0 and is affiliated with neither VirusTotal nor Google. Issues and pull requests are welcome.
