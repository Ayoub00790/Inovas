# -*- coding: utf-8 -*-
"""Structures de données partagées par tous les modules d'INOVA."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Route(str, Enum):
    """Chemin choisi par l'aiguilleur."""
    LOCAL = "LOCAL"                    # pentest simple : tout reste en local
    CLOUD = "CLOUD"                    # pentest lourd : LLM externe via la passerelle
    LOCAL_RESTRICTED = "LOCAL_RESTRICTED"  # lourd MAIS trop sensible : local + validation humaine


@dataclass
class PentestProfile:
    """Ce que l'aiguilleur sait du pentest avant de démarrer."""
    pentest_type: str
    authenticated: bool
    custom_application: bool
    exploitation_chaining: bool
    nb_targets: int
    data_classification: str
    sector: str = ""
    sensitive_terms: list[str] = field(default_factory=list)


@dataclass
class RouteDecision:
    route: Route
    complexity: float
    sensitivity: float
    reasons: list[str]


@dataclass
class Service:
    host: str
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""


@dataclass
class Finding:
    """Une vulnérabilité détectée (phase 3), enrichie en phase 4 et 5."""
    id: str
    title: str
    asset: str
    severity: str
    cve: Optional[str] = None
    cvss: float = 0.0
    epss: float = 0.0
    template_id: Optional[str] = None     # identifiant du test (ex. template nuclei)
    evidence: str = ""
    internet_facing: bool = True
    # Remplis en phase 4
    decision: str = ""                    # ACT | ATTEND | TRACK* | TRACK (logique SSVC)
    priority_rank: int = 0
    # Remplis en phase 5
    verified: Optional[bool] = None
    analysis: str = ""


@dataclass
class MaskResult:
    """Résultat du masquage par la passerelle."""
    masked_text: str
    nb_entities: int
    uncertain_spans: int
    residual_leaks: list[str]     # catégories seulement, jamais les valeurs


class SafePrompt:
    """Texte autorisé à sortir vers le cloud.

    Seule la passerelle crée ces objets : le client LLM refuse tout autre
    type pour un appel cloud. C'est une garantie *dans le code* qu'aucun
    texte non masqué ne peut partir par erreur.
    """
    __slots__ = ("text", "_issuer")

    def __init__(self, text: str, _issuer: object):
        self.text = text
        self._issuer = _issuer
