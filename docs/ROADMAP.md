# INOVA — Feuille de route pour terminer le projet

Le projet a trois livrables : **(1) le prototype**, **(2) le cadre de garde-fous éthiques**,
**(3) l'analyse ROI** face au pentest classique. Ce squelette couvre la structure du
prototype ; voici ce qui est fait et ce qui reste, dans l'ordre conseillé.

Calendrier aligné sur la méthodologie présentée (10 semaines) :
S1-3 passerelle · S4-6 orchestration · S7-8 validation · S9-10 garde-fous & ROI.

---

## ✅ Déjà en place (ce dépôt)

- [x] Arborescence et architecture modulaire (aiguilleur / passerelle / phases / garde-fous)
- [x] Passerelle Presidio étendue : IP, URL, hostnames, secrets (JWT, AWS, Bearer, clés), empreintes, tables SQL, termes du client
- [x] Jetons cohérents + table de correspondance **chiffrée** par mission
- [x] Contrôle après masquage + **fail-closed** + journal `cloud_outbox.jsonl`
- [x] Verrou dans le code : le client cloud refuse tout texte non masqué
- [x] Aiguilleur à double critère (complexité × sensibilité), décisions justifiées
- [x] Orchestrateur des 7 phases, mode démo complet
- [x] Priorisation par arbre de décision (type SSVC) : exploitation, exposition, impact
- [x] Garde-fous : périmètre, dates du mandat, liste blanche d'outils, validation humaine
- [x] 15 tests automatisés (non-fuite, matrice d'aiguillage, périmètre)

---

## Étape 1 — Passer en conditions réelles (S1)

1. **Monter un laboratoire légal** (jamais de cible réelle sans mandat) :
   ```bash
   docker run -d -p 3000:3000 bkimminich/juice-shop     # OWASP Juice Shop
   docker run -d -p 8081:80 vulnerables/web-dvwa        # DVWA
   ```
   Créer `config/scope.yaml` pointant vers ces conteneurs (domaines / IP du lab).
2. **Installer les outils** : `nmap`, `nuclei` (+ `nuclei -update-templates`), `whatweb` ; puis `tools.dry_run: false`.
3. **Installer le SLM local** : [Ollama](https://ollama.com), puis `ollama pull qwen2.5:7b`
   (PC modeste : `qwen2.5:3b` ; sinon GPU loué). Mettre `llm.mode: live`.
4. **Clé du LLM externe** dans `.env`, `pip install litellm`, régler `llm.cloud_model`.
5. Lancer `python -m inova.main run --scope config/scope.yaml` et corriger ce qui casse.

## Étape 2 — Renforcer la passerelle (S2-3)

- [ ] Remplacer `fr_core_news_sm` par `fr_core_news_lg` (ou un NER *transformers*) : moins de faux positifs/négatifs.
- [ ] Porter le jeu `tests/fixtures/leak_cases.json` à **50+ cas** réalistes (sorties nmap, nuclei, sqlmap, en-têtes HTTP, dumps JSON).
- [ ] Mesurer : taux de fuite (objectif **0**), taux de sur-masquage, taux de replis fail-closed.
- [ ] Option : **surrogates réalistes** (`srv-0042.pentest.local` au lieu de `[HOSTNAME_1]`) et comparer la qualité des réponses du cloud.
- [ ] Masquage des captures d'écran : `presidio-image-redactor` (OCR) pour la phase 6.

## Étape 3 — Rendre l'aiguilleur « intelligent » (S4)

- [ ] Activer `router.use_slm_refinement: true` (le SLM affine les scores ; la sensibilité ne peut qu'augmenter).
- [ ] **Calibrer les seuils** (`complexity_threshold`, `sensitivity_threshold`) sur 10-15 profils de pentest du lab ; documenter chaque choix.
- [ ] Ajouter la sensibilité **observée** en cours de mission (ex. beaucoup de secrets trouvés ⇒ rebasculer en local).

## Étape 4 — Compléter les phases (S5-6)

- [ ] P2 : intégrer `whatweb` (technologies) en plus de nmap.
- [ ] P4 : récupérer l'EPSS en direct (déjà codé) + la liste **CISA KEV** (exploitation avérée ⇒ `active`).
- [ ] P5 : brancher le vrai re-test `nuclei -id` et enregistrer la réponse comme preuve.
- [ ] P6 : captures d'écran automatiques (ex. `gowitness`) puis scellage SHA-256.
- [ ] P7 : export HTML/PDF du rapport, version « direction » et version « technique ».
- [ ] Interface : simple chatbot ou page web pour la phase 1 (saisie du besoin en langage naturel).

## Étape 5 — Validation expérimentale : le cœur du mémoire (S7-8)

Comparer **trois configurations** sur le même laboratoire (données fictives uniquement) :

| Config. | Description | Ce qu'elle prouve |
|---|---|---|
| A | Tout local (SLM seul) | plancher de capacité, fuite nulle |
| B | **INOVA** (aiguillage + passerelle) | la solution |
| C | Cloud sans masquage | plafond de capacité (référence) |

Métriques à relever pour chaque configuration :
- **Fuite** : valeurs sensibles du lab retrouvées dans `cloud_outbox.jsonl` (script de recherche automatique) ;
- **Qualité** : vulnérabilités confirmées et enchaînements identifiés vs vérité terrain du lab ;
- **Robustesse** : nombre de replis fail-closed ;
- **Coût et temps** : durée, tokens consommés.

Résultat attendu à démontrer : **B ≈ C en qualité, B = A en fuite.**
Appui bibliographique : PentestGPT (arXiv 2308.06782), p. 6 (§4.3) et p. 8 (Finding 3).

## Étape 6 — Cadre de garde-fous éthiques (S9) — livrable 2

- [ ] Rédiger le cadre à partir de ce qui est déjà codé : mandat, périmètre, liste blanche, validation humaine, non-destructivité, minimisation des données, traçabilité (`audit` + `outbox`).
- [ ] Matrice des responsabilités (qui valide quoi : pentesteur, client, RSSI).
- [ ] Correspondance réglementaire : RGPD et loi marocaine **09-08** (CNDP) sur les données personnelles.
- [ ] Procédure en cas d'incident (fuite détectée dans l'outbox, cible hors périmètre…).

## Étape 7 — Analyse ROI (S10) — livrable 3

- [ ] Mesurer la durée d'un pentest manuel de référence sur le lab vs INOVA.
- [ ] Coûts INOVA : tokens cloud, matériel/GPU, temps de supervision humaine.
- [ ] ROI = (heures économisées × taux journalier − coûts INOVA) / coûts INOVA.
- [ ] Ajouter la valeur non monétaire : couverture plus large, rapport homogène, confidentialité mesurée.

## Étape 8 — Rédaction et soutenance

- [ ] Mémoire : contexte → problématique → état de l'art (LiteLLM, LLM Guard/Gorget, DontFeedTheAI) → architecture → résultats → garde-fous → ROI.
- [ ] Démo en direct : commande `mask`, puis mission `--demo`, puis lecture de `cloud_outbox.jsonl`.

---

### À ne jamais faire
- Tester une cible sans mandat signé, ou en dehors des dates du mandat.
- Mettre des données réelles d'un client dans le laboratoire ou dans les tests.
- Désactiver la passerelle « pour aller plus vite » : c'est la propriété centrale du projet.
