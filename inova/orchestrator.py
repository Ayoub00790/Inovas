# -*- coding: utf-8 -*-
"""L'orchestrateur LOCAL : enchaîne les 7 phases selon la route décidée."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from .core.audit import AuditLog
from .core.budget import Budget
from .core.config import load_yaml
from .core.context import Context
from .core.models import Route
from .core.results import save_mission
from .guardrails.scope import OutOfScopeError, ScopeGuard
from .llm.client import LLMClient
from .phases import (p1_config, p2_recon, p3_vulnscan, p4_priorisation,
                     p5_exploitation, p6_preuves, p7_rapport)
from .router.reasoner import Reasoner
from .tools.runner import ToolRunner

PHASE_NAMES = ["Configuration + aiguillage", "Reconnaissance", "Recherche de vulnérabilités",
               "Priorisation", "Exploitation (confirmation)", "Preuves", "Rapport"]
PHASES = [p2_recon, p3_vulnscan, p4_priorisation, p5_exploitation, p6_preuves, p7_rapport]


def _title(i: int, ctx: Context) -> None:
    print(f"\n{'=' * 70}\n PHASE {i + 1} · {PHASE_NAMES[i]}\n{'=' * 70}")
    if ctx.on_phase:
        ctx.on_phase(i, PHASE_NAMES[i])


def build_context(settings: dict, scope: dict, demo: bool, auto_approve: bool) -> Context:
    eng = settings["engagement"]
    stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{int(time.time() * 1000) % 1000:03d}"
    run_dir = Path(eng.get("output_dir", "runs")) / f"{eng['id']}_{stamp}"
    ctx = Context(settings=settings, scope=scope, run_dir=run_dir, audit=AuditLog(run_dir),
                  demo=demo, auto_approve=auto_approve and demo,
                  fixtures_dir=Path(__file__).resolve().parent.parent / "tests" / "fixtures",
                  started_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
    ctx.guard = ScopeGuard(scope)
    if not ctx.guard.authorization_valid():
        raise OutOfScopeError("Le mandat n'est pas valide à la date d'aujourd'hui : arrêt.")
    ctx.budget = Budget(settings)
    ctx.llm = LLMClient(settings, usage_log=run_dir / "usage.jsonl", budget=ctx.budget)
    return ctx


def run(settings_path: str, scope_path: str, demo: bool = False, auto_approve: bool = False) -> Context:
    return run_with(load_yaml(settings_path), load_yaml(scope_path), demo, auto_approve)


def run_with(settings: dict, scope: dict, demo: bool = False, auto_approve: bool = False,
             approver: Optional[Callable[[str, str], bool]] = None,
             on_phase: Optional[Callable[[int, str], None]] = None) -> Context:
    ctx = build_context(settings, scope, demo, auto_approve)
    ctx.approver, ctx.on_phase = approver, on_phase

    _title(0, ctx)
    p1_config.run(ctx)

    # La passerelle (Presidio) n'est chargée que si le pentest part au cloud
    if ctx.decision.route == Route.CLOUD:
        from .gateway.passerelle import Passerelle
        from .gateway.vault import Vault
        vault = Vault(ctx.settings["gateway"].get("vault_dir", ".inova_vault"),
                      ctx.settings["engagement"]["id"])
        ctx.passerelle = Passerelle(ctx.settings, ctx.scope, vault,
                                    ctx.settings["engagement"].get("language", "fr"))

    ctx.reasoner = Reasoner(ctx.decision, ctx.passerelle, ctx.llm, ctx.audit, guard=ctx.guard)
    ctx.runner = ToolRunner(ctx.settings, ctx.guard, ctx.run_dir, ctx.audit)

    for i, phase in enumerate(PHASES, start=1):
        _title(i, ctx)
        phase.run(ctx)

    save_mission(ctx)
    if ctx.on_phase:
        ctx.on_phase(len(PHASE_NAMES), "terminée")
    print(f"\nMission terminée. Dossier : {ctx.run_dir}")
    return ctx
