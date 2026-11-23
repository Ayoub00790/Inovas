# -*- coding: utf-8 -*-
"""Phase 3 — Recherche de vulnérabilités (outils seuls : nuclei)."""
from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlparse

from ..core.context import Context
from ..core.models import Finding


def _is_internet_facing(asset: str) -> bool:
    host = urlparse(asset).hostname if "://" in asset else asset
    try:
        return not ipaddress.ip_address(host).is_private
    except ValueError:
        return True   # nom de domaine : supposé exposé (prudence)


def _body_excerpt(response: str, lines: int = 6, width: int = 160) -> str:
    """Quelques lignes du corps de la réponse : l'IA a besoin de VOIR ce qui est exposé.
    (Ce texte vient de la cible : il passe ensuite par la passerelle et le bloc non fiable.)"""
    body = response.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in response else response.split("\n\n", 1)[-1]
    kept = [l.strip()[:width] for l in body.splitlines() if l.strip()][:lines]
    return "; ".join(kept)


def parse_nuclei_jsonl(path: Path, start: int = 1) -> list[Finding]:
    findings = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=start):
        if not line.strip():
            continue
        r = json.loads(line)
        info = r.get("info", {})
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        asset = r.get("matched-at") or r.get("host", "")
        extracted = "; ".join(r.get("extracted-results") or [])
        parts = [extracted] if extracted else [r.get("matcher-name", ""), _body_excerpt(r.get("response", ""))]
        evidence = " — ".join(p for p in parts if p) or info.get("description", "").strip()
        findings.append(Finding(
            id=f"F-{i:03d}", title=info.get("name", r.get("template-id", "?")),
            asset=asset, severity=info.get("severity", "info"),
            cve=cves[0] if cves else None,
            cvss=float(cls.get("cvss-score") or 0.0),
            epss=float(cls.get("epss-score") or 0.0),
            template_id=r.get("template-id"), evidence=evidence,
            internet_facing=_is_internet_facing(asset)))
    return findings


def reachable(url: str, timeout: float = 3.0) -> bool:
    """La cible répond-elle ? (sinon nuclei l'ignore en silence et rend 0 constat)"""
    u = urlparse(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        with socket.create_connection((u.hostname, port), timeout=timeout):
            return True
    except OSError:
        return False


def run(ctx: Context) -> None:
    urls = ctx.scope.get("targets", {}).get("urls", [])
    if ctx.demo:
        ctx.findings = parse_nuclei_jsonl(ctx.fixtures_dir / "sample_nuclei.jsonl")
    else:
        alive = []
        for url in urls:
            if reachable(url):
                alive.append(url)
            else:
                print(f"   ⚠ {url} ne répond pas : application arrêtée ? (scan ignoré)")
                ctx.audit.event("cible_injoignable", url=url)
        if alive:
            print(f"   nuclei sur {len(alive)} cible(s) en un seul passage…")
            out = ctx.runner.run("nuclei", alive)
            if out:
                ctx.findings = parse_nuclei_jsonl(out)

    for f in ctx.findings:
        print(f"   {f.id}  [{f.severity:<8}] {f.title}  ({f.cve or 'sans CVE'})")
    ctx.audit.event("scan", findings=len(ctx.findings))
