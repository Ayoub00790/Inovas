# -*- coding: utf-8 -*-
"""Sauvegarde et relecture des missions (historique).

Chaque dossier runs/<mission>/ contient :
  rapport.md · audit.jsonl · usage.jsonl · evidence_index.json
  cloud_outbox.jsonl (si route CLOUD) · mission.json (détail) · summary.json (résumé)
Tout reste en LOCAL (dossier non versionné).
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict
from pathlib import Path

RUN_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def _read_jsonl(path: Path) -> list:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


SEVERITIES = ("critical", "high", "medium", "low", "info")


def _severity(findings: list[dict]) -> dict:
    return {s: sum(f.get("severity") == s for f in findings) for s in SEVERITIES}


def save_mission(ctx) -> dict:
    d = ctx.decision
    trace = ctx.reasoner.trace if ctx.reasoner else []
    usage = ctx.llm.summary()
    audit = _read_jsonl(ctx.audit.path)
    pentest = ctx.scope.get("pentest", {})
    auth = ctx.scope.get("authorization", {})
    mission = {
        "run": ctx.run_dir.name, "started_at": ctx.started_at,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "demo": ctx.demo,
        "client": auth.get("client"), "reference": auth.get("reference"),
        "pentest": pentest,
        "decision": {"route": d.route.value, "complexity": d.complexity,
                     "sensitivity": d.sensitivity, "reasons": d.reasons},
        "services": [asdict(s) for s in ctx.services],
        "findings": [asdict(f) for f in ctx.findings],
        "trace": trace,
        "usage": usage, "usage_calls": ctx.llm.calls,
        "budget": {"cloud_calls": ctx.budget.cloud_calls, "tokens": ctx.budget.tokens,
                   "elapsed_s": round(ctx.budget.elapsed(), 1),
                   "max_cloud_calls": ctx.budget.max_cloud_calls, "max_tokens": ctx.budget.max_tokens},
        "outbox_check": ctx.outbox_check,
        "spacy_models": getattr(ctx.passerelle, "models", None),
    }
    summary = {
        "run": mission["run"], "started_at": ctx.started_at, "demo": ctx.demo,
        "client": mission["client"],
        "type": pentest.get("type"), "classification": pentest.get("data_classification"),
        "route": d.route.value, "complexity": d.complexity, "sensitivity": d.sensitivity,
        "findings": len(ctx.findings),
        "severity": _severity([asdict(f) for f in ctx.findings]),
        "act": sum(f.decision == "ACT" for f in ctx.findings),
        "attend": sum(f.decision == "ATTEND" for f in ctx.findings),
        "verified": sum(bool(f.verified) for f in ctx.findings),
        "local_calls": usage["local"]["calls"], "cloud_calls": usage["cloud"]["calls"],
        "fail_closed": sum(e["event"] in ("fail_closed", "cloud_indisponible") for e in audit),
        "injections": sum(e.get("count", 1) for e in audit if e["event"] == "injection_suspectee"),
        "actions_signalees": sum(e["event"] == "action_signalee" for e in audit),
        "masked_entities": sum(e.get("entities", 0) for e in audit if e["event"] == "masking"),
        "tokens": sum(u["prompt_tokens"] + u["completion_tokens"] for u in usage.values()),
        "cost_usd": usage["cloud"]["cost_usd"],
        "duration_s": mission["budget"]["elapsed_s"],
        "outbox_leaks": len(ctx.outbox_check.get("leaks", [])) if ctx.outbox_check else 0,
    }
    (ctx.run_dir / "mission.json").write_text(json.dumps(mission, ensure_ascii=False, indent=1), encoding="utf-8")
    (ctx.run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    return summary


def load_mission(run_dir: Path) -> dict:
    """Tout ce dont l'interface a besoin pour afficher une mission (nouvelle ou passée)."""
    run_dir = Path(run_dir)
    data = json.loads((run_dir / "mission.json").read_text(encoding="utf-8"))
    data["audit"] = _read_jsonl(run_dir / "audit.jsonl")
    data["outbox"] = _read_jsonl(run_dir / "cloud_outbox.jsonl")
    report = run_dir / "rapport.md"
    data["report"] = report.read_text(encoding="utf-8") if report.exists() else ""
    return data


def list_missions(runs_root: Path) -> list[dict]:
    out = []
    if runs_root.exists():
        for f in runs_root.glob("*/summary.json"):
            try:
                summ = json.loads(f.read_text(encoding="utf-8"))
                if "severity" not in summ:        # missions enregistrées avant l'ajout du champ
                    mission = json.loads((f.parent / "mission.json").read_text(encoding="utf-8"))
                    summ["severity"] = _severity(mission.get("findings", []))
                out.append(summ)
            except (OSError, ValueError):
                continue
    return sorted(out, key=lambda s: s.get("started_at", ""), reverse=True)


def resolve_run(runs_root: Path, name: str) -> Path:
    """Chemin sûr vers une mission (refuse ../ et noms inattendus)."""
    if not RUN_NAME.match(name or ""):
        raise ValueError("nom de mission invalide")
    path = (runs_root / name).resolve()
    if path.parent != runs_root.resolve() or not (path / "mission.json").exists():
        raise FileNotFoundError("mission introuvable")
    return path
