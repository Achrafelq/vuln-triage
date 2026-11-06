# Backlog

Idées volontairement laissées hors du périmètre de P1.

- **Cache disque des CSAF** : `collect` tourne en moins d'une minute, inutile pour un run quotidien.
- **Historique complet des avis** : les RSS ne donnent que les derniers avis (~15 Palo Alto, ~50 Fortinet). Piste : `provider-metadata.json`, inaccessible au 06/11/2026.
- **NVD** : non branché, le CVSS vient directement des vendeurs.
- **CVE multi-vendeurs** (ex. CVE-2026-109618, PHP, chez Palo Alto et Fortinet) : éviter les doublons dans le rapport.
- **KEV + composant tiers** (PHP, Node.js) : P0 ou P1 ? À trancher dans `rules.yaml`.
- **Avis Fortinet multi-CVE** : le drapeau « exploité » s'applique à toutes les CVE de l'avis, approximation à affiner.
- **Autres vendeurs** : F5 en premier (présent chez Airbus), puis Cisco, Ivanti, Citrix.
