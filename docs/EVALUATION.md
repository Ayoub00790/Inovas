# INOVA — Mesure du taux de fuite de la passerelle

Commande : `python -m inova.main eval-leaks` (ou onglet **Évaluation** de l'interface).
Corpus : `tests/fixtures/leak_cases.json` — **56 cas fictifs**, 84 valeurs sensibles, 41 éléments
à préserver, répartis en sorties nmap, nuclei, sqlmap, en-têtes HTTP, JSON d'API, fichiers de
configuration, journaux, texte libre en français, obfuscations, et cas « à préserver ».
13 cas sont marqués **difficiles** *a priori* (noms d'hôtes Windows, noms en minuscules,
adresses, CIN, données obfusquées).

## Indicateurs

| Indicateur | Définition | Lecture |
|---|---|---|
| **Fuite brute** | valeurs sensibles encore présentes après masquage | qualité de la détection |
| **Fuite effective** | valeurs qui seraient **réellement sorties** : fuite brute dans un texte que la passerelle a accepté d'envoyer | **indicateur de confidentialité** |
| **Taux de repli** | textes refusés pour le cloud (fail-closed) | coût en capacité |
| **Sur-masquage** | éléments utiles (CVE, versions, identifiants de constats) masqués à tort | coût en utilité |

## Résultats

| Itération | Modèle FR | Fuite effective — cas standard | Fuite effective — cas difficiles | Global | Replis | Sur-masquage |
|---|---|---|---|---|---|---|
| 1 — détecteurs initiaux | `fr_core_news_sm` | **20,9 %** (14/67) | 76,5 % (13/17) | 32,1 % (27/84) | 1,8 % | 2,4 % |
| 2 — détecteurs améliorés | `fr_core_news_sm` | **3,0 %** (2/67) | 29,4 % (5/17) | 8,3 % (7/84) | 0,0 % | 0,0 % |
| 2 — détecteurs améliorés | `fr_core_news_md` | **0,0 %** (0/67) | 29,4 % (5/17) | 6,0 % (5/84) | 0,0 % | 0,0 % |

### Ce que l'itération 1 a révélé (et ce qui a été corrigé)
- Secrets au format `.env` (`DB_PASSWORD=…`), JSON (`"password": "…"`), PHP `define('DB_PASSWORD', '…')`,
  mot de passe dans une URL de base de données, authentification HTTP `Basic`, corps d'une clé privée.
  → motifs clé/valeur généralisés ; **seule la valeur est masquée** (`DB_PASSWORD=[SECRET_1]`), la clé
  reste lisible pour le raisonnement.
- **Cartes bancaires non détectées en français** (le détecteur Presidio n'était actif qu'en anglais) et
  **IBAN marocain** non reconnu → détecteurs ajoutés.
- Sorties sqlmap `Database: x` / `Table: y`, IP et domaines « neutralisés » (`10[.]10[.]0[.]5`),
  adresses postales, CIN marocaine (score bas sans contexte, confirmé par « CIN », « CNIE »…).
- Téléphones français et marocains (régions FR/MA, mots de contexte français).
- Faux nom de personne sur un identifiant technique (`default-admin-login`) → filtré.

### Ce que le modèle `md` apporte
Les **noms de personnes dans un tableau** (sortie sqlmap) échappaient au petit modèle `sm` ; le modèle
`md` les détecte, ainsi que des noms écrits en minuscules et des adresses. C'est ce qui fait passer la
fuite effective standard de 3,0 % à **0 %**. Coût : ~40 Mo à télécharger.

## Constat de la première mission réelle (Claude Haiku 5.5) : le masquage peut gêner le raisonnement

Lors de la première mission avec un vrai LLM, le modèle a écrit : « *les jetons [TARGET_URL_n] sont
différents, donc la corrélation n'est pas établie* ». En masquant chaque URL **entière**, la passerelle
cachait que `/index.php`, `/admin` et `/.git/config` étaient sur le **même serveur** : la
confidentialité était assurée, mais au prix d'une perte de raisonnement (les enchaînements entre failles).

Correction : **masquage structurel des URL**. L'hôte reçoit un jeton cohérent partout
(`https://[HOSTNAME_1]/admin`, `http://[TARGET_IP_1]:8080/cgi-bin/` et « SSH sur [TARGET_IP_1] »),
le chemin reste lisible, et ce qu'il contient de sensible (identifiants, `token=`, termes du client)
est masqué à son tour. Mesure après correction : **toujours 0 % de fuite effective** sur les cas
standard, sur-masquage 0 %.

Enseignement pour le mémoire : le compromis n'est pas seulement « masquer plus = plus sûr ». Un
masquage trop grossier détruit les **relations** dont le modèle a besoin ; un bon masquage cache les
**valeurs** mais préserve la **structure** (même hôte, même IP, même chemin).

## Limites restantes (assumées, à présenter dans le mémoire)

| Cas | Pourquoi il fuit encore | Piste |
|---|---|---|
| Nom d'hôte Windows sans domaine (`SRV-PAIE-01`) | indiscernable d'un code produit sans contexte ; un motif large masquerait aussi les CVE | inventaire des hôtes du client dans la deny-list du périmètre |
| Identifiants encodés en base64 sans préfixe `Basic` | une chaîne base64 isolée ressemble à n'importe quel jeton | décodage + re-analyse des chaînes base64 |
| Mot de passe épelé (`A-d-m-1-n…`), IP en hexadécimal | obfuscation volontaire | hors de portée d'un masquage par motifs : relève de la vigilance humaine |

Ces limites renforcent l'intérêt de l'**aiguillage** : pour un périmètre très sensible, la route
`LOCAL_RESTRICTED` n'envoie rien, quelle que soit la qualité du masquage.

## Mise en garde méthodologique (importante)
Le corpus et les détecteurs ont été écrits par la même équipe, et les détecteurs de l'itération 2 ont
été conçus **après** avoir vu les échecs de l'itération 1. Le score de 0 % mesure donc la couverture des
formats connus ; il **surestime probablement** la performance sur des données jamais vues.

Protocole recommandé pour le mémoire :
1. Constituer un **jeu de test séparé** à partir de vraies sorties d'outils sur le laboratoire
   (Juice Shop, DVWA), étiquetées à la main, **sans jamais s'en servir pour régler les détecteurs**.
2. Mesurer la fuite effective sur ce jeu, avec `sm` puis `md`.
3. Compléter par le contrôle automatique de l'outbox en fin de mission réelle
   (`cloud_outbox.jsonl` comparé à la table de correspondance et aux secrets du labo listés dans
   `config/secrets_labo.txt`).
