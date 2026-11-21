# -*- coding: utf-8 -*-
"""Garde-fou n°4 : maîtriser les ACTIONS que l'IA peut proposer.

C'est la deuxième moitié de la problématique (« ... et les actions qu'ils
peuvent proposer »). Principe :

  - Le texte de l'IA est un CONSEIL, jamais une commande. INOVA n'exécute
    aucune action tirée de ce texte.
  - Les seules actions exécutables sont celles de ALLOWED_ACTIONS, construites
    par le code à partir des résultats des outils (jamais par l'IA), et
    toujours après validation humaine.
  - Chaque réponse est relue : une proposition dangereuse ou visant une
    cible hors périmètre est signalée à l'humain et journalisée.
"""
from __future__ import annotations

import re

ALLOWED_ACTIONS = {
    "retest_template": "re-test ciblé d'un test déjà détecté par le scanner (nuclei -id), dans le périmètre",
}

# Signatures de propositions dangereuses (détection défensive)
DANGEROUS: list[tuple[str, re.Pattern]] = [(n, re.compile(rx, re.I)) for n, rx in [
    ("suppression_massive", r"\brm\s+-[a-z]*r[a-z]*\b|\bdel\s+/[sqf]\b|\bformat\s+[a-z]:|\bmkfs\b"),
    ("shell_distant", r"/dev/tcp/|\bnc(at)?\b[^\n]{0,30}\s-(e|c)\s|\bbash\s+-i\b|--exec\s"),
    ("telechargement_puis_execution", r"\b(curl|wget)\b[^\n|]{0,120}\|\s*(ba|z)?sh\b|Invoke-Expression|\biex\s*\("),
    ("powershell_encode", r"powershell[^\n]{0,40}\s-e(nc|ncodedcommand)?\s"),
    ("destruction_de_donnees", r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b"),
    ("deni_de_service", r"\bfork\s?bomb\b|:\(\)\s*\{\s*:\|:&\s*\};:|--flood\b|\bslowloris\b"),
    ("persistance", r"\bcrontab\s+-|\buseradd\b|\bnet\s+user\s+\S+\s+\S+\s+/add\b|authorized_keys"),
]]

_HOST = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                   r"(?:com|net|org|fr|ma|io|eu|local|lan|corp|internal|intra|priv)\b", re.I)


def review(answer: str, guard=None) -> list[str]:
    """Catégories de risques présentes dans une réponse de l'IA."""
    flags = [name for name, rx in DANGEROUS if rx.search(answer)]
    if guard is not None:
        outside = sorted({h for h in _HOST.findall(answer) if not guard.is_in_scope(h)})
        if outside:
            flags.append("cible_hors_perimetre")
    return flags


def hosts_out_of_scope(answer: str, guard) -> list[str]:
    """Noms d'hôtes / IP cités par l'IA mais absents du périmètre (affichage LOCAL uniquement)."""
    return sorted({h for h in _HOST.findall(answer) if not guard.is_in_scope(h)})
