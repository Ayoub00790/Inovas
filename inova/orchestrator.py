# -*- coding: utf-8 -*-
"""L'orchestrateur LOCAL : enchaîne les 7 phases selon la route décidée."""
from __future__ import annotations

import time
from pathlib import Path

from .core.audit import AuditLog
from .core.config import load_yaml
from .core.context import Context
from .core.models import Route
from .guardrails.scope import OutOfScopeError, ScopeGuard
from .llm.client import LLMClient
from .phases import (p1_config, p2_recon, p3_vulnscan, p4_priorisation,
                     p5_exploitation, p6_preuves, p7_rapport)
from .router.reasoner import Reasoner
from .tools.runner import ToolRunner

PHASES = [
    ("2 · Reconnaissance", p2_recon),
    ("3 · Recherche de vulnérabilités", p3_vulnscan),
    ("4 · Priorisation", p4_priorisation),
    ("5 · Exploitation (confirmation)", p5_exploitation),
    ("6 · Preuves", p6_preuves),
    ("7 · Rapport", p7_rapport),
]


def _title(t: str) -> None:
    print(f"\n{'=' * 70}\n PHASE {t}\n{'=' * 70}")


def build_context(settings_path: str, scope_path: str, demo: bool, auto_approve: bool) -> Context:
    settings, scope = load_yaml(settings_path), load_yaml(scope_path)
    eng = settings["engagement"]
    run_dir = Path(eng.get("output_dir", "runs")) / f"{eng['id']}_{time.strftime('%Y%m%d-%H%M%S')}"
    ctx = Context(settings=settings, scope=scope, run_dir=run_dir, audit=AuditLog(run_dir),
                  demo=demo, auto_approve=auto_approve and demo,
                  fixtures_dir=Path(__file__).resolve().parent.parent / "tests" / "fixtures")
    ctx.guard = ScopeGuard(scope)
    if not ctx.guard.authorization_valid():
        raise OutOfScopeError("Le mandat n'est pas valide à la date d'aujourd'hui : arrêt.")
    ctx.llm = LLMClient(settings)
    return ctx


def run(settings_path: str, scope_path: str, demo: bool = False, auto_approve: bool = False) -> Path:
    ctx = build_context(settings_path, scope_path, demo, auto_approve)

    _title("1 · Configuration + aiguillage")
    p1_config.run(ctx)

    # La passerelle (Presidio) n'est chargée que si le pentest part au cloud
    passerelle = None
    if ctx.decision.route == Route.CLOUD:
        from .gateway.passerelle import Passerelle
        from .gateway.vault import Vault
        vault = Vault(ctx.settings["gateway"].get("vault_dir", ".inova_vault"),
                      ctx.settings["engagement"]["id"])
        passerelle = Passerelle(ctx.settings, ctx.scope, vault,
                                ctx.settings["engagement"].get("language", "fr"))

    ctx.reasoner = Reasoner(ctx.decision, passerelle, ctx.llm, ctx.audit)
    ctx.runner = ToolRunner(ctx.settings, ctx.guard, ctx.run_dir, ctx.audit)

    for title, phase in PHASES:
        _title(title)
        phase.run(ctx)

    print(f"\nMission terminée. Dossier : {ctx.run_dir}")
    return ctx.run_dir / "rapport.md"
