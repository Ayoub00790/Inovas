# -*- coding: utf-8 -*-
"""Phase 4 — Priorisation par risque RÉEL (arbre de décision inspiré de SSVC).

Pas de formule pondérée à justifier : trois questions, une décision.
  1. Exploitation : la faille est-elle exploitée / exploitable ?  (EPSS, sévérité)
  2. Exposition    : l'actif est-il exposé sur Internet ?
  3. Impact métier : quelle criticité le client donne-t-il à l'actif ?
Décisions : ACT (immédiat) > ATTEND (rapide) > TRACK* (surveiller) > TRACK.
"""
from __future__ import annotations

from urllib.parse import urlparse

import requests

from ..core.context import Context
from ..core.models import Finding
from .coherence import assess

ORDER = {"ACT": 0, "ATTEND": 1, "TRACK*": 2, "TRACK": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def fetch_epss(cves: list[str]) -> dict[str, float]:
    """Score EPSS public (FIRST). N'envoie QUE des identifiants CVE publics."""
    if not cves:
        return {}
    try:
        r = requests.get("https://api.first.org/data/v1/epss",
                         params={"cve": ",".join(cves)}, timeout=10)
        return {d["cve"]: float(d["epss"]) for d in r.json().get("data", [])}
    except Exception:
        return {}


def exploitation_level(f: Finding) -> str:
    if f.epss >= 0.5:
        return "active"
    if f.epss >= 0.05 or f.severity == "critical":
        return "poc"
    # Faille sans CVE (configuration, application maison) : pas d'EPSS possible.
    # Si le scanner l'a CONFIRMÉE avec une sévérité haute, elle est exploitable en pratique.
    if not f.cve and f.severity == "high":
        return "poc"
    return "none"


def criticality(f: Finding, scope: dict) -> str:
    table = {k.lower(): v for k, v in scope.get("asset_criticality", {}).items()}
    host = (urlparse(f.asset).hostname if "://" in f.asset else f.asset).lower()
    return table.get(host, "moyenne")


def decide(f: Finding, scope: dict) -> str:
    expl, exposed, impact = exploitation_level(f), f.internet_facing, criticality(f, scope)
    if expl == "active" and exposed and impact == "haute":
        return "ACT"
    if expl == "active" and (exposed or impact == "haute"):
        return "ATTEND"
    if expl == "poc" and impact == "haute":
        return "ATTEND"
    if expl in ("active", "poc"):
        return "TRACK*"
    return "TRACK"


def run(ctx: Context) -> None:
    if not ctx.demo:
        missing = [f.cve for f in ctx.findings if f.cve and not f.epss]
        scores = fetch_epss(missing)
        for f in ctx.findings:
            if f.cve in scores:
                f.epss = scores[f.cve]

    assess(ctx.findings, ctx.services)          # contradictions, confirmation nmap, doublons
    for f in ctx.findings:
        f.decision = decide(f, ctx.scope)
    # beaucoup de tests nuclei (identifiants par défaut, RCE de frameworks) n'ont pas de score CVSS :
    # à décision égale, on classe d'abord par gravité, puis par CVSS et EPSS
    ctx.findings.sort(key=lambda f: (ORDER[f.decision], SEV_ORDER.get(f.severity, 5), -f.cvss, -f.epss))
    for rank, f in enumerate(ctx.findings, start=1):
        f.priority_rank = rank
        tag = f"doublon de {f.duplicate_of}" if f.duplicate_of else f.confidence
        print(f"   #{rank}  {f.decision:<7} {f.id}  CVSS {f.cvss:>4}  EPSS {f.epss:.2f}  {f.title}  [{tag}]")
