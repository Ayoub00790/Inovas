# INOVA — Pentest assisté par IA, confidentialité maîtrisée

> Comment bénéficier des capacités des modèles IA pour réaliser des tests d'intrusion,
> tout en maîtrisant les données auxquelles ils ont accès et les actions qu'ils peuvent proposer ?

INOVA orchestre un pentest web en 7 phases. Dès le départ, un **SLM local (l'aiguilleur)**
décide du chemin :

| | données peu sensibles | données très sensibles |
|---|---|---|
| **pentest simple** | `LOCAL` | `LOCAL` |
| **pentest lourd** | `CLOUD` via la passerelle | `LOCAL_RESTRICTED` (local + validation humaine) |

- **Maîtriser les données** : sur le chemin `CLOUD`, seule l'exploitation (et la synthèse du rapport)
  passe par un LLM externe, après masquage par la **passerelle Presidio**. Au moindre doute,
  la passerelle refuse et l'étape retombe en local (**fail-closed**).
- **Maîtriser les actions** : le texte de l'IA n'est jamais exécuté. La seule action possible
  (re-test ciblé d'un test déjà détecté) attend une **validation humaine** ; les propositions
  dangereuses et les instructions piégées venues de la cible sont signalées et neutralisées.

---

## Démarrage rapide

```bash
python -m venv .venv && source .venv/bin/activate      # Windows : .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download fr_core_news_md               # ou fr_core_news_sm (plus léger)
python -m spacy download en_core_web_sm
python -m inova.main web                               # ouvre http://127.0.0.1:8000
```

Le mode démo fonctionne sans aucun modèle d'IA installé : les réponses sont simulées, tout le
reste (masquage, contrôles, garde-fous, rapport) est réel.
Passage aux vrais modèles et au laboratoire : **[docs/CHECKLIST_REEL.md](docs/CHECKLIST_REEL.md)**.

## L'interface (7 onglets)

| Onglet | Rôle |
|---|---|
| **1 · Périmètre** | saisir le mandat, les cibles, les exclusions et les termes sensibles (validé, enregistré dans `config/scope.yaml`) |
| **2 · Aiguillage** | voir la décision LOCAL / CLOUD / LOCAL_RESTRICTED sur la matrice, avec ses justifications |
| **3 · Passerelle** | texte réel → ce que reçoit le cloud → réponse en jetons → réponse réinjectée, table de correspondance, verdict |
| **4 · Mission** | les 7 phases en direct ; **validation humaine Autoriser / Refuser** avant chaque action ; échanges avec l'IA, pièges neutralisés, coût |
| **5 · Rapport** | rapport, **export PDF** (version direction ou technique), `cloud_outbox.jsonl` et contrôle automatique de fuite, journal d'audit |
| **6 · Historique** | toutes les missions, comparables ligne à ligne (route, appels cloud, replis, pièges, tokens, fuites) |
| **7 · Évaluation** | taux de fuite de la passerelle sur un corpus de 56 cas |

L'interface n'écoute que sur `127.0.0.1` (ta machine), refuse les requêtes venant d'un autre site
et ne charge aucune ressource externe.

## Ligne de commande

```bash
python -m inova.main web                  # interface graphique
python -m inova.main check                # diagnostic : SLM local, passerelle, LLM cloud
python -m inova.main run --demo           # mission complète en console
python -m inova.main route                # décision de l'aiguilleur
python -m inova.main mask "texte"         # démonstration de la passerelle
python -m inova.main eval-leaks           # taux de fuite sur le corpus
python -m pytest -q                       # tests
```
`--scope` est facultatif : `config/scope.yaml` s'il existe, sinon `config/scope.example.yaml`.

---

## Arborescence

```
inova/
├── README.md · requirements.txt · requirements-live.txt · .env.example · pytest.ini
├── config/
│   ├── settings.yaml            ← modes local/cloud, plafonds, tarifs, seuils, passerelle, outils
│   └── scope.example.yaml       ← périmètre d'exemple (le tien : scope.yaml, non versionné)
├── docs/
│   ├── CHECKLIST_REEL.md        ← passage aux vrais modèles et au laboratoire
│   ├── EVALUATION.md            ← mesure du taux de fuite, résultats et limites
│   └── ROADMAP.md               ← étapes pour terminer le projet
├── inova/
│   ├── main.py · orchestrator.py · diagnostic.py
│   ├── core/        models · config (+ .env, validation du périmètre) · context · audit · budget · results
│   ├── router/      aiguilleur.py ★ (LOCAL / CLOUD / LOCAL_RESTRICTED) · reasoner.py (route, replis, revue)
│   ├── gateway/     recognizers.py ★ · vault.py (table chiffrée) · passerelle.py ★ (fail-closed)
│   ├── llm/         client.py (SLM local / cloud via LiteLLM, refuse le texte brut, mesure les tokens)
│   ├── guardrails/  scope.py · approval.py · injection.py ★ · actions.py ★
│   ├── tools/       runner.py (nmap / whatweb / nuclei, liste blanche, sans shell)
│   ├── phases/      p1_config … p7_rapport
│   ├── eval/        leak_eval.py (taux de fuite) · outbox_audit.py (contrôle après mission)
│   └── web/         server.py · api.py · static/index.html (interface aux couleurs AXA)
└── tests/           non-fuite · garde-fous · chemin LiteLLM réel (faux serveur) · aiguillage · interface
    └── fixtures/    sorties nmap/nuclei d'exemple (dont une page piégée) + corpus de 56 cas
```

Chaque mission produit `runs/<mission>/` : `rapport.md`, `audit.jsonl`, `usage.jsonl`,
`evidence_index.json`, `mission.json`, `summary.json` et — seulement si la route est `CLOUD` —
`cloud_outbox.jsonl`, **copie exacte de tout ce qui a quitté la machine**.

## Garde-fous intégrés au code

1. **Périmètre** — toute cible hors liste, exclue ou hors des dates du mandat est bloquée.
2. **Passerelle obligatoire** — `LLMClient.cloud()` n'accepte qu'un `SafePrompt` créé par la passerelle.
3. **Fail-closed** — détection incertaine, donnée résiduelle ou plafond atteint ⇒ pas d'envoi, repli local.
4. **Injection de prompt** — les données venues de la cible sont balisées « non fiables » ; les lignes piégées sont retirées avant tout envoi.
5. **Actions** — le texte de l'IA n'est jamais exécuté ; seule action possible : un re-test ciblé, après **validation humaine** ; les propositions dangereuses ou hors périmètre sont signalées.
6. **Plafonds** — nombre d'appels cloud, tokens et durée par mission.
7. **Traçabilité** — `audit.jsonl` (décisions), `usage.jsonl` (coûts), `cloud_outbox.jsonl` (ce qui est sorti) contrôlé automatiquement ; la table de correspondance reste chiffrée et locale.

## Résultat de la mesure de fuite (corpus de 56 cas)

| Modèle | Fuite effective — cas standard | Cas difficiles | Sur-masquage |
|---|---|---|---|
| `fr_core_news_md` | **0,0 %** (0/67) | 29,4 % (5/17) | 0,0 % |
| `fr_core_news_sm` | 3,0 % (2/67) | 29,4 % (5/17) | 0,0 % |

Méthode, itérations et limites (à lire avant de citer ces chiffres) : [docs/EVALUATION.md](docs/EVALUATION.md).

> À utiliser uniquement sur des systèmes pour lesquels un mandat écrit a été signé.
