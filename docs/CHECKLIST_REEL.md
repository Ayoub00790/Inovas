# Checklist — passage en conditions réelles

Objectif : remplacer les réponses simulées par de vrais modèles, puis tester sur un vrai
laboratoire, **en vérifiant à chaque étape que rien de sensible ne sort**.
Comptez environ 30 minutes, hors téléchargements. Commandes pour PowerShell (Windows).

> Règle d'or : jamais de cible réelle sans mandat signé, jamais de vraies données client dans le labo.

---

## Étape 0 — Mettre le projet à jour

```powershell
cd $HOME\Documents\GitHub\Inovas
git pull
.venv\Scripts\Activate.ps1
pip install --default-timeout=120 --retries 10 -r requirements.txt
python -m spacy download fr_core_news_md
python -m pytest -q
```
✅ Attendu : tous les tests passent. Ceux du chemin LiteLLM sont « skipped » tant que LiteLLM n'est pas installé.

---

## Étape 1 — Le vrai LLM cloud (sans attendre Ollama)

1. Installer LiteLLM (gros paquet, une seule fois) :
   ```powershell
   pip install --default-timeout=300 --retries 10 -r requirements-live.txt
   ```
2. Créer le fichier de clés : `copy .env.example .env`, puis ouvrir `.env` et renseigner la clé
   du fournisseur (`OPENAI_API_KEY=...` ou `ANTHROPIC_API_KEY=...`).
   Le fichier `.env` est ignoré par git : **la clé ne part jamais sur GitHub**. Ne la colle nulle part ailleurs.
3. Dans `config\settings.yaml` :
   - `cloud_mode: "live"` ;
   - `cloud_model:` le nom exact du modèle au format LiteLLM (ex. `openai/<modèle>` ou
     `anthropic/<modèle>`, à vérifier dans la documentation du fournisseur) ;
   - `pricing:` les tarifs du fournisseur (dollars par million de tokens), pour l'analyse ROI.
4. Diagnostic :
   ```powershell
   python -m inova.main check
   ```
   ✅ Attendu : la section **3. LLM cloud** est `[OK]`, et la ligne « texte qui partirait » ne contient
   que des jetons (`[TARGET_IP_1]`, `[SECRET_1]`…).
5. Interface (`python -m inova.main web`) → onglet **Passerelle** → « Masquer et envoyer au cloud » :
   la colonne 3 contient maintenant une **vraie** réponse du modèle. Le bandeau indique « LLM cloud : … · réel ».
6. Onglet **Mission** → lancer une mission démo, classification « Interne ».
   ✅ Attendu : onglet **Rapport** → « Contrôle automatique : aucune valeur sensible sortie » ; tableau
   « Coût et performance » avec des **tokens réels** et un coût en dollars.

| Erreur affichée | Cause probable |
|---|---|
| `AuthenticationError` / 401 | clé absente ou invalide dans `.env` |
| `NotFoundError` / modèle inconnu | nom de modèle incorrect dans `cloud_model` |
| `RateLimitError` / crédit | quota ou crédit épuisé chez le fournisseur |
| `Timeout` | connexion lente : augmenter `llm.timeout_s` |
| `UnsupportedParamsError … temperature` | le modèle impose sa température (ex. Claude Haiku 5.5) : corrigé depuis le commit « Paramètres imposés » (`git pull`) ; sinon mettre `temperature: 1` |

---

## Étape 2 — Le SLM local (Ollama)

1. Installer Ollama : https://ollama.com (il démarre tout seul en arrière-plan).
2. Télécharger un modèle :
   ```powershell
   ollama pull qwen2.5:3b     # PC modeste (~2 Go)
   # ou : ollama pull qwen2.5:7b   (~4,7 Go, meilleur raisonnement)
   ```
3. Dans `config\settings.yaml` : `local_mode: "live"` et `local_model: "ollama/qwen2.5:3b"`.
4. `python -m inova.main check` → section **1. SLM local** `[OK]` ; noter la latence (utile au mémoire).
5. Optionnel : `router.use_slm_refinement: true` pour que le SLM affine la décision de l'aiguilleur.

✅ Attendu : une mission « Secret » (route LOCAL_RESTRICTED) produit de vraies analyses locales,
et **aucun** fichier `cloud_outbox.jsonl` n'est créé.

---

## Étape 3 — Le laboratoire

1. Installer Docker Desktop, puis lancer une application volontairement vulnérable :
   ```powershell
   docker run -d -p 3000:3000 bkimminich/juice-shop
   ```
2. Installer les outils et les mettre dans le PATH : **nmap** (installeur officiel) et **nuclei**
   (version Windows du projet ProjectDiscovery), puis `nuclei -update-templates`.
3. Onglet **Périmètre** : URL `http://127.0.0.1:3000`, plage IP `127.0.0.1/32`, dates du jour, mandat
   « Laboratoire personnel » → **Enregistrer**.
4. `config\settings.yaml` : `tools.dry_run: false`.
5. Créer `config\secrets_labo.txt` (ignoré par git) et y lister, une par ligne, les valeurs sensibles
   connues du labo (mots de passe, e-mails de test…). Le contrôle de l'outbox les recherchera.
6. Onglet **Mission** → Source « Outils réels », **Validation humaine cochée** → Lancer.
   Valide ou refuse chaque re-test proposé.

✅ Attendu : vraies sorties nmap / nuclei, contrôle de l'outbox ✅, rapport exportable en PDF.

---

## Étape 4 — Les mesures pour le mémoire

1. **Jeu de test indépendant** : copier de vraies sorties d'outils du labo dans
   `tests\fixtures\leak_cases_labo.json` (même format que `leak_cases.json`), en étiquetant les
   valeurs sensibles **à la main**, sans modifier les détecteurs ensuite. Puis :
   ```powershell
   python -m inova.main eval-leaks --corpus tests/fixtures/leak_cases_labo.json
   ```
2. **Comparer les configurations** dans l'onglet **Historique** : la même mission en « Secret »
   (tout local) et en « Interne » (INOVA). Relever : vulnérabilités confirmées, enchaînements
   trouvés, durée, tokens, coût, fuites dans l'outbox.
3. La configuration de référence « cloud **sans** masquage » n'existe volontairement pas dans le
   code (le client cloud refuse tout texte non masqué). Si le protocole l'exige, elle doit être
   ajoutée comme mode explicitement réservé au laboratoire.
4. Reporter les chiffres dans `docs/EVALUATION.md` et dans l'analyse ROI.
