# INOVA — Feuille de route pour terminer le projet

Le projet a trois livrables : **(1) le prototype**, **(2) le cadre de garde-fous éthiques**,
**(3) l'analyse ROI** face au pentest classique. Voici ce qui est fait et ce qui reste,
dans l'ordre conseillé.

Calendrier aligné sur la méthodologie présentée (10 semaines) :
S1-3 passerelle · S4-6 orchestration · S7-8 validation · S9-10 garde-fous & ROI.

---

## ✅ Déjà en place (ce dépôt)

**Confidentialité (maîtriser les données)**
- [x] Passerelle Presidio étendue au pentest : IP, URL, hostnames, secrets (clé/valeur, JWT, AWS, Bearer, Basic, clés privées, identifiants dans les URI), empreintes, objets SQL, adresses, CIN, IBAN (dont marocain), cartes, téléphones FR/MA, termes et nom du client
- [x] Seule la valeur d'un secret est masquée (`DB_PASSWORD=[SECRET_1]`) ; jetons cohérents ; table de correspondance **chiffrée** par mission
- [x] Contrôle après masquage + **fail-closed** ; verrou dans le code (le cloud refuse tout texte non masqué)
- [x] Contrôle automatique de `cloud_outbox.jsonl` en fin de mission
- [x] Mesure du taux de fuite sur un corpus de 56 cas : **0 % de fuite effective** sur les cas standard avec `fr_core_news_md` (voir `docs/EVALUATION.md`)

**Contrôle des actions**
- [x] Aiguilleur à double critère (complexité × sensibilité), décisions justifiées
- [x] Protection contre l'injection de prompt (balisage, détection, neutralisation ligne à ligne)
- [x] Revue des actions proposées par l'IA (commandes dangereuses, cibles hors périmètre) : signalées, jamais exécutées
- [x] Validation humaine **dans l'interface** (Autoriser / Refuser, refus par défaut au bout de 15 min)
- [x] Périmètre, dates du mandat, liste blanche d'outils, exécution sans shell

**Pilotage et mesure**
- [x] Modes séparés SLM local / LLM cloud ; fichier `.env` ; commande `check` de diagnostic
- [x] Tokens, durée et coût de chaque appel (`usage.jsonl`) ; plafonds par mission
- [x] Orchestrateur des 7 phases ; priorisation par arbre de décision (type SSVC)
- [x] Interface web aux couleurs AXA : périmètre, aiguillage, passerelle, mission, rapport (**PDF direction / technique**), historique, évaluation
- [x] 38 tests automatisés, dont le chemin LiteLLM réel contre un faux serveur cloud

---

## Étape 1 — Passer en conditions réelles (S1)
Suivre **[CHECKLIST_REEL.md](CHECKLIST_REEL.md)** : vrai LLM cloud (étape 1), Ollama (étape 2),
laboratoire Juice Shop + nmap + nuclei (étape 3). Chaque étape a son critère de réussite.

## Étape 2 — Consolider la passerelle (S2-3)
- [ ] Constituer un **jeu de test indépendant** avec de vraies sorties du laboratoire, étiquetées à la main, jamais utilisé pour régler les détecteurs.
- [ ] Mesurer la fuite effective sur ce jeu (`eval-leaks --corpus …`), avec `sm` puis `md`.
- [ ] Traiter, si le temps le permet, les limites documentées : noms d'hôtes Windows (inventaire dans la deny-list), chaînes base64 (décodage puis re-analyse).
- [ ] Option : surrogates réalistes (`srv-0042.pentest.local`) et comparaison de la qualité des réponses.
- [ ] Masquage des captures d'écran : `presidio-image-redactor` (OCR) pour la phase 6.

## Étape 3 — Calibrer l'aiguilleur (S4)
- [ ] Activer `router.use_slm_refinement: true` et comparer avec les règles seules.
- [ ] Calibrer `complexity_threshold` et `sensitivity_threshold` sur 10-15 profils de pentest ; documenter chaque choix.
- [ ] Ajouter la sensibilité **observée** en cours de mission (beaucoup de secrets trouvés ⇒ rebasculer en local).

## Étape 4 — Compléter les phases (S5-6)
- [ ] P2 : intégrer `whatweb` (technologies) en plus de nmap.
- [ ] P4 : ajouter la liste **CISA KEV** (exploitation avérée ⇒ `active`) à l'EPSS déjà récupéré en direct.
- [ ] P6 : captures d'écran automatiques (ex. `gowitness`) puis scellage SHA-256.

## Étape 5 — Validation expérimentale : le cœur du mémoire (S7-8)
Comparer sur le même laboratoire (données fictives uniquement) :

| Config. | Comment l'obtenir | Ce qu'elle prouve |
|---|---|---|
| A — tout local | mission en classification « Secret » (route LOCAL_RESTRICTED) | plancher de capacité, fuite nulle |
| B — **INOVA** | mission en classification « Interne » (route CLOUD) | la solution |
| C — cloud sans masquage | mode « référence » à ajouter, réservé au laboratoire | plafond de capacité |

Relever pour chacune (onglet **Historique**) : vulnérabilités confirmées, enchaînements trouvés,
durée, tokens, coût, fuites dans l'outbox, replis.
Résultat attendu : **B ≈ C en qualité, B = A en fuite.**
Appui bibliographique : PentestGPT (arXiv 2308.06782), p. 6 (§4.3) et p. 8 (Finding 3).

## Étape 6 — Cadre de garde-fous éthiques (S9) — livrable 2
- [ ] Rédiger le cadre à partir de ce qui est déjà codé : mandat, périmètre, liste blanche, validation humaine, non-destructivité, protection contre l'injection, revue des actions, minimisation des données, plafonds, traçabilité (`audit`, `usage`, `outbox`).
- [ ] Matrice des responsabilités (qui valide quoi : pentesteur, client, RSSI).
- [ ] Correspondance réglementaire : RGPD et loi marocaine **09-08** (CNDP) sur les données personnelles.
- [ ] Procédure en cas d'incident (fuite détectée dans l'outbox, cible hors périmètre, piège détecté…).

## Étape 7 — Analyse ROI (S10) — livrable 3
- [ ] Mesurer la durée d'un pentest manuel de référence sur le labo vs INOVA.
- [ ] Coûts INOVA : tokens cloud (déjà mesurés dans `usage.jsonl`), matériel/GPU, temps de supervision humaine.
- [ ] ROI = (heures économisées × taux journalier − coûts INOVA) / coûts INOVA.
- [ ] Ajouter la valeur non monétaire : couverture, rapport homogène, confidentialité **mesurée**.

## Étape 8 — Rédaction et soutenance
- [ ] Mémoire : contexte → problématique → état de l'art (LiteLLM + Presidio, LLM Guard/Gorget, DontFeedTheAI) → architecture → résultats → garde-fous → ROI.
- [ ] Démo en direct dans l'interface : Passerelle (exemple « .env exposé »), Mission avec validation humaine et page piégée, Rapport PDF, Évaluation.

---

### À ne jamais faire
- Tester une cible sans mandat signé, ou en dehors des dates du mandat.
- Mettre des données réelles d'un client dans le laboratoire ou dans les tests.
- Désactiver la passerelle « pour aller plus vite » : c'est la propriété centrale du projet.
