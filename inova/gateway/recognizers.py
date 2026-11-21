# -*- coding: utf-8 -*-
"""Détecteurs spécifiques au pentest, branchés sur Presidio.

Presidio connaît les données personnelles (noms, e-mails, cartes...).
On lui apprend ici les données sensibles d'un pentest : IP et URL de la
cible, noms d'hôtes internes, secrets, empreintes, objets de base de
données, et les termes propres au client (deny-list issue du périmètre).
"""
from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
TLDS = r"(?:com|net|org|fr|ma|io|eu|local|lan|corp|internal|intra|priv)"


def _patterns() -> dict[str, list[Pattern]]:
    return {
        "TARGET_IP": [
            Pattern("ipv4", rf"\b{OCTET}(?:\.{OCTET}){{3}}(?:/\d{{1,2}})?\b", 0.90),
        ],
        "TARGET_URL": [
            Pattern("url", r"\bhttps?://[^\s'\"<>]*[^\s'\"<>.,;:!?)]", 0.90),
        ],
        "HOSTNAME": [
            Pattern("fqdn",
                    rf"\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{TLDS}\b", 0.75),
        ],
        "SECRET": [
            Pattern("key_value",
                    r"\b(?:password|passwd|pwd|mot_de_passe|api[_-]?key|secret|token)\s*[:=]\s*\S+",
                    0.95),
            Pattern("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b", 0.95),
            Pattern("aws_key", r"\bAKIA[0-9A-Z]{16}\b", 0.95),
            Pattern("bearer", r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*", 0.95),
            Pattern("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 0.99),
        ],
        "HASH": [
            Pattern("hex_hash", r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", 0.70),
        ],
        # Look-behind de largeur fixe : on masque le NOM de la table, pas le mot-clé SQL
        "DB_OBJECT": [
            Pattern("from", r"(?<=FROM )[A-Za-z_][A-Za-z0-9_]*", 0.70),
            Pattern("join", r"(?<=JOIN )[A-Za-z_][A-Za-z0-9_]*", 0.70),
            Pattern("into", r"(?<=INTO )[A-Za-z_][A-Za-z0-9_]*", 0.70),
            Pattern("update", r"(?<=UPDATE )[A-Za-z_][A-Za-z0-9_]*", 0.70),
            Pattern("table", r"(?<=TABLE )[A-Za-z_][A-Za-z0-9_]*", 0.70),
        ],
    }


PENTEST_ENTITIES = list(_patterns().keys()) + ["CLIENT_TERM"]


def build_pentest_recognizers(languages: list[str], scope: dict) -> list[PatternRecognizer]:
    """Un jeu de détecteurs par langue + la deny-list du client."""
    recognizers: list[PatternRecognizer] = []
    for lang in languages:
        for entity, patterns in _patterns().items():
            recognizers.append(PatternRecognizer(
                supported_entity=entity, patterns=patterns,
                supported_language=lang, name=f"{entity}_{lang}"))

        # Deny-list : actifs et termes du client, masqués d'office (score 1.0)
        deny = list(scope.get("sensitive_terms", []))
        deny += scope.get("targets", {}).get("domains", [])
        deny = [d for d in dict.fromkeys(deny) if d]
        if deny:
            recognizers.append(PatternRecognizer(
                supported_entity="CLIENT_TERM", deny_list=deny,
                supported_language=lang, name=f"CLIENT_TERM_{lang}"))
    return recognizers
