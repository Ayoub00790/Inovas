# -*- coding: utf-8 -*-
"""Détecteurs spécifiques au pentest, branchés sur Presidio.

Presidio connaît les données personnelles (noms, e-mails, cartes...).
On lui apprend ici les données sensibles d'un pentest : IP et URL de la
cible, noms d'hôtes internes, secrets, empreintes, objets de base de
données, adresses, identifiants nationaux, et les termes propres au client
(deny-list issue du périmètre).

Presidio utilise le moteur `regex` : les « lookbehind » de longueur variable
permettent de masquer la VALEUR d'un secret en laissant visible sa clé
(« DB_PASSWORD=[SECRET_1] »), ce qui aide le modèle à raisonner.

Historique : les motifs marqués « itération 2 » ont été ajoutés après la
première mesure sur le corpus (voir docs/EVALUATION.md).
"""
from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer.predefined_recognizers import CreditCardRecognizer, PhoneRecognizer

OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
TLDS = r"(?:com|net|org|fr|ma|io|eu|local|lan|corp|internal|intra|priv)"
SECRET_KEYS = (r"(?:password|passwd|pwd|mdp|mot_de_passe|secret|token|api[_-]?key|"
               r"access[_-]?key|private[_-]?key|client[_-]?secret)")
VALUE = r"[^\s\"',;]*[^\s\"',;.)\]]"


def _patterns() -> dict[str, list[Pattern]]:
    return {
        "TARGET_IP": [
            Pattern("ipv4", rf"\b{OCTET}(?:\.{OCTET}){{3}}(?:/\d{{1,2}})?\b", 0.90),
            # itération 2 : IP « neutralisées » des rapports de sécurité (10[.]10[.]0[.]5)
            Pattern("ipv4_defanged", rf"\b{OCTET}(?:\[\.\]{OCTET}){{3}}\b", 0.90),
        ],
        "TARGET_URL": [
            Pattern("url", r"\bh(?:tt|xx)ps?://[^\s'\"<>]*[^\s'\"<>.,;:!?)\]]", 0.90),
        ],
        "HOSTNAME": [
            Pattern("fqdn", rf"\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{TLDS}\b", 0.75),
            Pattern("fqdn_defanged", rf"\b(?:[a-z0-9-]+\[\.\])+{TLDS}\b", 0.85),   # itération 2
        ],
        "SECRET": [
            # itération 2 : clé=valeur généralisée (.env, JSON, YAML, properties) -> valeur seule
            Pattern("key_value",
                    rf"(?<=\b[\w.-]*{SECRET_KEYS}[\w.-]*[\"']?\s*[:=]\s*[\"']?){VALUE}", 0.95),
            Pattern("php_define",                                            # itération 2
                    rf"(?<=define\(\s*['\"][\w]*(?:PASSWORD|PASSWD|SECRET|KEY|TOKEN)[\w]*['\"]\s*,\s*['\"])[^'\"]+",
                    0.95),
            Pattern("uri_credentials", r"(?<=\b[a-z][a-z0-9+.-]*://[^\s:/@]{1,64}:)[^\s@/]+(?=@)", 0.95),
            Pattern("basic_auth", r"(?<=\bBasic\s+)[A-Za-z0-9+/]{8,}={0,2}", 0.95),        # itération 2
            Pattern("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b", 0.95),
            Pattern("aws_key", r"\bAKIA[0-9A-Z]{16}\b", 0.95),
            Pattern("bearer", r"(?<=\bBearer\s+)[A-Za-z0-9._~+/-]{16,}=*", 0.95),
            Pattern("private_key",                                            # itération 2 : bloc entier
                    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----", 0.99),
        ],
        "HASH": [
            Pattern("hex_hash", r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", 0.70),
        ],
        # On masque le NOM de l'objet, pas le mot-clé SQL
        "DB_OBJECT": [
            Pattern("sql_keyword", r"(?<=\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+)[A-Za-z_][A-Za-z0-9_]*", 0.70),
            # itération 2 : sorties sqlmap « Database: x », « Table: y »
            Pattern("sqlmap_label", r"(?<=\b(?:Database|Table|Schema|Column)\s?:\s*)[A-Za-z_][A-Za-z0-9_]*", 0.75),
        ],
        "ADDRESS": [                                                      # itération 2
            Pattern("adresse_postale",
                    r"\b\d{1,4}(?:\s?(?:bis|ter))?,?\s+(?:rue|avenue|av\.|boulevard|bd|place|impasse|allée|"
                    r"chemin|route|quartier|lotissement|résidence)\s+[^\n,;]{2,60}", 0.75),
        ],
        "ID_NATIONAL": [                                                  # itération 2 (contexte marocain)
            # CIN : 1-2 lettres + 5-6 chiffres. Score bas sans contexte -> masqué mais
            # jugé incertain (repli local) ; « CIN », « CNIE »... à proximité le confirment.
            Pattern("cin_maroc", r"\b(?-i:[A-Z]{1,2})\d{5,6}\b", 0.40),
        ],
        "IBAN_CODE": [                                                    # itération 2 : IBAN marocain
            Pattern("iban_maroc", r"\b(?-i:MA)\d{2}(?:\s?\d{4}){6}\b", 0.85),
        ],
    }


CONTEXT = {"ID_NATIONAL": ["cin", "cnie", "carte", "nationale", "identité", "identite"]}
PENTEST_ENTITIES = [e for e in _patterns() if e != "IBAN_CODE"] + ["CLIENT_TERM"]
PHONE_CONTEXT = ["phone", "telephone", "téléphone", "tél", "tel", "mobile", "portable",
                 "gsm", "fixe", "contacter", "joindre", "appeler", "numéro"]


def build_pentest_recognizers(languages: list[str], scope: dict) -> list[PatternRecognizer]:
    """Un jeu de détecteurs par langue + la deny-list du client."""
    recognizers: list = []
    for lang in languages:
        for entity, patterns in _patterns().items():
            recognizers.append(PatternRecognizer(
                supported_entity=entity, patterns=patterns, context=CONTEXT.get(entity),
                supported_language=lang, name=f"{entity}_{lang}"))

        # Deny-list : actifs, termes et NOM du client, masqués d'office (score 1.0)
        deny = list(scope.get("sensitive_terms", []))
        deny += scope.get("targets", {}).get("domains", [])
        deny.append(str(scope.get("authorization", {}).get("client", "")))
        deny = [d for d in dict.fromkeys(deny) if d and len(d) >= 3]
        if deny:
            recognizers.append(PatternRecognizer(
                supported_entity="CLIENT_TERM", deny_list=deny,
                supported_language=lang, name=f"CLIENT_TERM_{lang}"))

        # Itération 2 : cartes bancaires aussi en français ; téléphones FR / MA
        recognizers.append(CreditCardRecognizer(supported_language=lang, name=f"CREDIT_CARD_{lang}"))
        recognizers.append(PhoneRecognizer(supported_language=lang, context=PHONE_CONTEXT,
                                           supported_regions=("FR", "MA", "BE", "CH", "US", "GB"),
                                           name=f"PHONE_{lang}"))
    return recognizers
