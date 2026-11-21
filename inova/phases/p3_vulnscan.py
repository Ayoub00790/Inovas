# -*- coding: utf-8 -*-
"""Phase 3 — Recherche de vulnérabilités (outils seuls : nuclei)."""
from __future__ import annotations

import ipaddress
import json
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


def parse_nuclei_jsonl(path: Path, start: int = 1) -> list[Finding]:
    findings = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=start):
        if not line.strip():
            continue
        r = json.loads(line)
        info = r.get("info", {})
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        asset = r.get("matched-at") or r.get("host", "")
        evidence = "; ".join(r.get("extracted-results") or []) or r.get("matcher-name", "")
        findings.append(Finding(
            id=f"F-{i:03d}", title=info.get("name", r.get("template-id", "?")),
            asset=asset, severity=info.get("severity", "info"),
            cve=cves[0] if cves else None,
            cvss=float(cls.get("cvss-score") or 0.0),
            epss=float(cls.get("epss-score") or 0.0),
            template_id=r.get("template-id"), evidence=evidence,
            internet_facing=_is_internet_facing(asset)))
    return findings


def run(ctx: Context) -> None:
    urls = ctx.scope.get("targets", {}).get("urls", [])
    if ctx.demo:
        ctx.findings = parse_nuclei_jsonl(ctx.fixtures_dir / "sample_nuclei.jsonl")
    else:
        for url in urls:
            out = ctx.runner.run("nuclei", url)
            if out:
                ctx.findings += parse_nuclei_jsonl(out, start=len(ctx.findings) + 1)

    for f in ctx.findings:
        print(f"   {f.id}  [{f.severity:<8}] {f.title}  ({f.cve or 'sans CVE'})")
    ctx.audit.event("scan", findings=len(ctx.findings))
