# -*- coding: utf-8 -*-
"""Phase 1 — Configuration : périmètre, profil du pentest, AIGUILLAGE."""
from __future__ import annotations

from ..core.config import build_profile
from ..core.context import Context
from ..router.aiguilleur import Aiguilleur


def run(ctx: Context) -> None:
    auth = ctx.scope.get("authorization", {})
    print(f"Client : {auth.get('client')}  |  Mandat : {auth.get('reference')}  "
          f"|  Valide jusqu'au {auth.get('valid_until')}")

    ctx.profile = build_profile(ctx.scope)
    ctx.decision = Aiguilleur(ctx.settings, ctx.llm).decide(ctx.profile)

    d = ctx.decision
    print(f"Complexité = {d.complexity}   Sensibilité = {d.sensitivity}   ->  ROUTE : {d.route.value}")
    for r in d.reasons:
        print(f"   - {r}")
    ctx.audit.event("route", route=d.route.value, complexity=d.complexity, sensitivity=d.sensitivity)
