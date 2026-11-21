# -*- coding: utf-8 -*-
"""L'aiguilleur : le SLM local décide du chemin AVANT le pentest.

Double critère (matrice de décision) :

                     | données peu sensibles | données très sensibles
    -----------------+-----------------------+------------------------
    pentest simple   |  LOCAL                |  LOCAL
    pentest lourd    |  CLOUD (via passerelle)|  LOCAL_RESTRICTED

1) Capacité   : le pentest est-il assez simple pour le modèle local ?
2) Confidentialité : s'il faut sortir, les données le permettent-elles ?

Les scores sont d'abord calculés par des règles explicites (reproductibles,
défendables). Optionnellement, le SLM local les affine (il peut voir les
données réelles : il tourne sur la machine).
"""
from __future__ import annotations

import json
import re

from ..core.models import PentestProfile, Route, RouteDecision

BASE_COMPLEXITY = {"web_boite_noire": 0.25, "web_boite_grise": 0.40,
                   "api": 0.40, "multi_applications": 0.60}
BASE_SENSITIVITY = {"public": 0.10, "interne": 0.40, "confidentiel": 0.65, "secret": 0.95}
SECTOR_BONUS = {"assurance": 0.10, "banque": 0.15, "sante": 0.15, "defense": 0.20}


def complexity_score(p: PentestProfile) -> tuple[float, list[str]]:
    s = BASE_COMPLEXITY.get(p.pentest_type, 0.40)
    why = [f"type {p.pentest_type} (base {s:.2f})"]
    if p.authenticated:
        s += 0.15; why.append("tests authentifiés +0.15")
    if p.custom_application:
        s += 0.15; why.append("application sur mesure +0.15")
    if p.exploitation_chaining:
        s += 0.25; why.append("enchaînement de failles requis +0.25")
    if p.nb_targets > 1:
        bonus = min(0.15, 0.03 * (p.nb_targets - 1))
        s += bonus; why.append(f"{p.nb_targets} cibles +{bonus:.2f}")
    return min(s, 1.0), why


def sensitivity_score(p: PentestProfile) -> tuple[float, list[str]]:
    s = BASE_SENSITIVITY.get(p.data_classification, 0.40)
    why = [f"classification {p.data_classification} (base {s:.2f})"]
    bonus = SECTOR_BONUS.get(p.sector, 0.0)
    if bonus:
        s += bonus; why.append(f"secteur {p.sector} +{bonus:.2f}")
    if p.sensitive_terms:
        s += 0.05; why.append("termes sensibles déclarés +0.05")
    return min(s, 1.0), why


class Aiguilleur:
    def __init__(self, settings: dict, llm=None):
        r = settings.get("router", {})
        self.c_thr = float(r.get("complexity_threshold", 0.55))
        self.s_thr = float(r.get("sensitivity_threshold", 0.70))
        self.use_slm = bool(r.get("use_slm_refinement", False))
        self.llm = llm

    def decide(self, profile: PentestProfile) -> RouteDecision:
        c, why_c = complexity_score(profile)
        s, why_s = sensitivity_score(profile)
        if self.use_slm and self.llm is not None and self.llm.mode != "mock":
            c, s = self._slm_refine(profile, c, s)

        if c < self.c_thr:
            route, verdict = Route.LOCAL, "pentest simple : le SLM local suffit"
        elif s >= self.s_thr:
            route, verdict = Route.LOCAL_RESTRICTED, (
                "pentest lourd mais données trop sensibles pour sortir : "
                "local + validation humaine renforcée")
        else:
            route, verdict = Route.CLOUD, "pentest lourd : bascule vers le LLM externe via la passerelle"
        return RouteDecision(route=route, complexity=round(c, 2), sensitivity=round(s, 2),
                             reasons=why_c + why_s + [verdict])

    def _slm_refine(self, profile: PentestProfile, c: float, s: float) -> tuple[float, float]:
        """Demande au SLM local un avis chiffré ; moyenne avec les règles (garde-fou)."""
        prompt = (
            "Évalue ce pentest. Réponds UNIQUEMENT en JSON "
            '{"complexity": 0..1, "sensitivity": 0..1}.\n'
            f"Profil : {profile}")
        try:
            raw = self.llm.local("Tu es un expert en tests d'intrusion.", prompt)
            data = json.loads(re.search(r"\{.*\}", raw, re.S).group(0))
            c = (c + float(data["complexity"])) / 2
            # prudence : la sensibilité ne peut qu'augmenter, jamais baisser sous les règles
            s = max(s, (s + float(data["sensitivity"])) / 2)
        except Exception:
            pass  # avis illisible : on garde les règles
        return c, s
