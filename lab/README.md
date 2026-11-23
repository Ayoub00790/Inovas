# Laboratoire INOVA

Applications volontairement vulnérables, choisies pour ce que les outils d'INOVA savent
détecter : **des CVE connues et des erreurs de configuration** (nuclei), avec des scores
CVSS / EPSS élevés et souvent présentes dans le catalogue CISA KEV. Elles alimentent donc
toute la chaîne : priorisation SSVC (décisions ACT), enchaînements entre failles, validation
humaine des re-tests.

| Port | Application | Faille attendue (modèle nuclei) | Gravité |
|---|---|---|---|
| 3000 | OWASP Juice Shop | `prometheus-metrics` | moyenne |
| 8081 | Apache 2.4.49 | `CVE-2021-41773`, `CVE-2021-42013` | haute / critique |
| 8082 | phpMyAdmin 4.8.1 | `CVE-2018-12613` | haute |
| 8083 | Tomcat 8 | `tomcat-default-login` | haute |
| 8084 | ThinkPHP 5.0.23 | `thinkphp-5023-rce` | critique |
| 9200 | Elasticsearch 1.4.2 | `CVE-2015-1427` | haute |

## Démarrer / arrêter
```powershell
cd lab
docker compose up -d --build
docker compose ps
# … mission INOVA …
docker compose down
```
Premier lancement : quelques minutes (téléchargement des images, ~2 Go).
Copier `scope.lab.yaml` dans `config\scope.yaml` (ou saisir les URL dans l'onglet Périmètre).

## Sécurité
- Tout écoute sur **127.0.0.1** : rien n'est joignable depuis le réseau. Ne pas modifier.
- Plusieurs services permettent une **exécution de code** : arrêter le labo après chaque séance.
- Ne jamais réutiliser ces images ailleurs qu'en laboratoire.

Images et configurations : [Vulhub](https://github.com/vulhub/vulhub), licence MIT (`LICENSE.vulhub`).

## Mesurer la détection (rappel et précision)
`attendu.yaml` est la vérité terrain du laboratoire : les failles réellement présentes.
Après une mission sur les outils réels :
```powershell
python -m inova.main eval-detection
```
- **rappel** : failles attendues trouvées / failles attendues ;
- **précision** : constats justes / constats annoncés, en fourchette tant que des constats restent
  « à qualifier » (ajoute-les dans `aussi_valides` ou `faux_positifs` après vérification manuelle).
Les doublons signalés par INOVA ne comptent qu'une fois. Le résultat est aussi écrit dans
`runs/<mission>/detection.json`.

## Élargir la détection (réglages de `config/settings.yaml`, section `tools`)
```yaml
tools:
  allowlist: ["nmap", "whatweb", "nuclei", "katana"]
  crawl: true                # exploration katana, puis nuclei -as sur les répertoires découverts
  crawl_max_urls: 25
  network_scan: true         # services non web vus par nmap (MySQL, SMB…) : modèles réseau de nuclei
  nuclei_rate_limit: 50      # requêtes/s : évite de saturer une cible fragile (Elasticsearch)
```
katana s'installe comme nuclei : `katana_..._windows_amd64.zip` sur
https://github.com/projectdiscovery/katana/releases, décompressé dans `C:\Tools`.
