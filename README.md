# INOVA — Pentest assisté par IA, confidentialité maîtrisée

> Comment bénéficier des capacités des modèles IA pour réaliser des tests d'intrusion,
> tout en maîtrisant les données auxquelles ils ont accès et les actions qu'ils peuvent proposer ?

INOVA orchestre un pentest web en 7 phases. Dès le départ, un **SLM local (l'aiguilleur)**
décide du chemin :

| | données peu sensibles | données très sensibles |
|---|---|---|
| **pentest simple** | `LOCAL` | `LOCAL` |
| **pentest lourd** | `CLOUD` via la passerelle | `LOCAL_RESTRICTED` (local + validation humaine) |

Sur le chemin `CLOUD`, seule la phase d'**exploitation** (et la synthèse du rapport) passe
par un LLM externe — après masquage par la **passerelle Presidio**. Si le masquage n'est
pas sûr, la passerelle refuse et l'étape retombe en local (**fail-closed**).

---

## Arborescence

```
inova/
├── README.md                    ← ce fichier
├── requirements.txt             ← dépendances Python
├── .env.example                 ← clés (vault, API cloud) — copier en .env
├── config/
│   ├── settings.yaml            ← modèles, seuils de l'aiguilleur, passerelle, outils
│   └── scope.example.yaml       ← périmètre signé : cibles, exclusions, sensibilité
├── docs/
│   └── ROADMAP.md               ← étapes pour terminer le projet
├── inova/
│   ├── main.py                  ← ligne de commande (run / route / mask)
│   ├── orchestrator.py          ← enchaîne les 7 phases selon la route
│   ├── core/
│   │   ├── models.py            ← Route, Finding, MaskResult, SafePrompt…
│   │   ├── config.py            ← lecture YAML, construction du profil
│   │   ├── context.py           ← état partagé d'une mission
│   │   └── audit.py             ← journal des décisions (jamais de valeurs réelles)
│   ├── router/
│   │   ├── aiguilleur.py        ← ★ décision LOCAL / CLOUD / LOCAL_RESTRICTED
│   │   └── reasoner.py          ← exécute une étape IA sur la bonne route (+ fail-closed)
│   ├── gateway/
│   │   ├── recognizers.py       ← ★ détecteurs pentest ajoutés à Presidio
│   │   ├── vault.py             ← table de correspondance chiffrée, par mission
│   │   └── passerelle.py        ← ★ détecter → masquer → contrôler → réinjecter
│   ├── llm/
│   │   └── client.py            ← SLM local / LLM cloud (LiteLLM), refuse le texte brut
│   ├── guardrails/
│   │   ├── scope.py             ← aucune action hors périmètre ni hors mandat
│   │   └── approval.py          ← l'IA propose, l'humain valide
│   ├── tools/
│   │   └── runner.py            ← nmap / whatweb / nuclei en liste blanche, sans shell
│   ├── web/
│   │   ├── server.py            ← serveur local (127.0.0.1), bibliothèque standard
│   │   ├── api.py               ← logique des écrans (testable sans navigateur)
│   │   └── static/index.html    ← ★ interface aux couleurs AXA (aucune ressource externe)
│   └── phases/
│       ├── p1_config.py         ← profil + aiguillage
│       ├── p2_recon.py          ← services et versions (IA légère, locale)
│       ├── p3_vulnscan.py       ← détection (outils seuls)
│       ├── p4_priorisation.py   ← arbre de décision type SSVC (EPSS, exposition, impact)
│       ├── p5_exploitation.py   ← ★ raisonnement lourd (cloud masqué) + validation humaine
│       ├── p6_preuves.py        ← index des preuves scellé (SHA-256)
│       └── p7_rapport.py        ← rapport Markdown (local, vraies valeurs)
└── tests/
    ├── test_passerelle.py       ← tests de NON-FUITE
    ├── test_aiguilleur.py       ← la matrice de décision
    ├── test_scope.py            ← périmètre, mandat, priorisation
    ├── test_web.py              ← API de l'interface (dont non-fuite)
    └── fixtures/                ← sorties nmap/nuclei d'exemple + 10 cas de fuite
```

Chaque mission produit `runs/<mission>_<date>/` :
`rapport.md`, `audit.jsonl`, `evidence_index.json`, `evidence/` et — seulement si la route
est `CLOUD` — `cloud_outbox.jsonl`, **copie exacte de tout ce qui a quitté la machine**.

---

## Installation

```bash
python -m venv .venv && source .venv/bin/activate      # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download fr_core_news_sm
python -m spacy download en_core_web_sm
```

## Interface graphique (recommandé pour la démo)

```bash
python -m inova.web
```
Le navigateur s'ouvre sur **http://127.0.0.1:8000**. Aucune installation supplémentaire n'est nécessaire : le serveur fait partie de Python. Quatre écrans :

1. **Aiguillage** — modifie le profil du pentest et vois la décision LOCAL / CLOUD / LOCAL_RESTRICTED sur la matrice, avec ses justifications.
2. **Passerelle** — colle un constat : texte réel → ce que reçoit le cloud → réponse en jetons → réponse réinjectée, avec la table de correspondance et le verdict (autorisé, ou repli local).
3. **Mission** — les 7 phases en démo, les vulnérabilités priorisées et chaque échange avec l'IA (local ou cloud).
4. **Rapport & journal** — le rapport, `cloud_outbox.jsonl` (tout ce qui est sorti) et `audit.jsonl`.

L'interface n'écoute que sur `127.0.0.1`, c'est-à-dire ta propre machine : c'est pour cela qu'elle peut afficher les valeurs réelles. Arrêt : `Ctrl+C`.

## Utilisation en ligne de commande

```bash
# 1) Voir la décision de l'aiguilleur pour un périmètre
python -m inova.main route --scope config/scope.example.yaml

# 2) Démontrer la passerelle sur un texte
python -m inova.main mask --scope config/scope.example.yaml \
  "Injection SQL sur https://demo.inova-lab.local/login (10.10.0.20), password=Adm1n2026"

# 3) Mission complète en démo (données d'exemple, aucun outil lancé, aucun modèle requis)
python -m inova.main run --scope config/scope.example.yaml --demo --auto-approve

# 4) Tests
python -m pytest -q
```

Passer en conditions réelles : voir `docs/ROADMAP.md` (étape 1).

## Règles de sécurité intégrées au code

1. **Périmètre** — `ScopeGuard` bloque toute cible hors liste ou exclue, et tout lancement hors des dates du mandat.
2. **Passerelle obligatoire** — `LLMClient.cloud()` n'accepte qu'un `SafePrompt` créé par la passerelle ; un texte brut lève `UnsafePromptError`.
3. **Fail-closed** — détection incertaine ou donnée résiduelle ⇒ pas d'envoi, repli local.
4. **Validation humaine** — toute vérification active d'une faille attend un « oui » explicite.
5. **Non destructif** — l'exploitation se limite à un re-test ciblé du test déjà détecté ; aucune charge malveillante.
6. **Traçabilité** — `audit.jsonl` (décisions) + `cloud_outbox.jsonl` (ce qui est sorti) ; la table de correspondance reste chiffrée et locale.

> À utiliser uniquement sur des systèmes pour lesquels un mandat écrit a été signé.
