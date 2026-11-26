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


HEALTH_MARKERS = ("mysqli_real_connect", "#2002", "SQLSTATE[", "Fatal error", "Database connection error",
                  "Internal Server Error", "Service Unavailable", "phpMyAdmin - Error", "Wrong permissions")


def health(url: str, timeout: float = 5.0) -> str:
    """« ok » ou la raison d'un mauvais état. Un port ouvert ne suffit pas : une application
    en erreur (base de données absente…) cache ses failles au scanner."""
    import urllib.error
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 127.0.0.1 : pas de proxy
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "INOVA"}), timeout=timeout) as r:
            status, body = r.status, r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, body = e.code, ""
    except Exception as e:                          # noqa: BLE001
        return f"pas de réponse HTTP ({type(e).__name__})"
    if status >= 500:
        return f"erreur HTTP {status}"
    marker = next((m for m in HEALTH_MARKERS if m in body), None)
    return f"page d'erreur applicative (« {marker} »)" if marker else "ok"


def crawl_targets(urls: list[str], out: Path, guard, limit: int) -> list[str]:
    """URL découvertes par katana -> répertoires distincts, dans le périmètre, sur les mêmes sites."""
    origins = {f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in urls}
    seen, dirs = set(urls) | {o + "/" for o in origins}, []
    for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
        u = urlparse(line.strip())
        if not u.scheme or f"{u.scheme}://{u.netloc}" not in origins:
            continue
        d = f"{u.scheme}://{u.netloc}{u.path.rsplit('/', 1)[0]}/"
        if d not in seen and (guard is None or guard.is_in_scope(d)):
            seen.add(d)
            dirs.append(d)
    return dirs[:limit]


def _merge(ctx: Context, out: Path | None) -> None:
    if not out:
        return
    known = {(f.template_id, f.asset) for f in ctx.findings}
    for f in parse_nuclei_jsonl(out, start=len(ctx.findings) + 1):
        if (f.template_id, f.asset) not in known:
            f.id = f"F-{len(ctx.findings) + 1:03d}"
            ctx.findings.append(f)
            known.add((f.template_id, f.asset))


def run(ctx: Context) -> None:
    urls = ctx.scope.get("targets", {}).get("urls", [])
    tools = ctx.settings.get("tools", {})
    if ctx.demo:
        ctx.findings = parse_nuclei_jsonl(ctx.fixtures_dir / "sample_nuclei.jsonl")
    else:
        alive = []
        for url in urls:
            if not reachable(url):
                print(f"   ⚠ {url} ne répond pas : application arrêtée ? (scan ignoré)")
                ctx.audit.event("cible_injoignable", url=url)
                continue
            alive.append(url)
            state = health(url)
            if state != "ok":
                print(f"   ⚠ {url} répond mal : {state} (scanné quand même, résultats peut-être incomplets)")
                ctx.audit.event("application_en_erreur", url=url, etat=state)
        if alive:
            print(f"   nuclei sur {len(alive)} cible(s) en un seul passage…")
            _merge(ctx, ctx.runner.run("nuclei", alive))

            # 1) exploration : pages et API cachées, testées selon les technologies détectées
            if tools.get("crawl", False):
                try:
                    found = ctx.runner.run("katana", alive)
                    deep = crawl_targets(alive, found, ctx.guard, int(tools.get("crawl_max_urls", 25))) if found else []
                    ctx.audit.event("exploration", urls_decouvertes=len(deep))
                    if deep:
                        print(f"   katana : {len(deep)} répertoire(s) découvert(s), test ciblé (nuclei -as)…")
                        _merge(ctx, ctx.runner.run("nuclei_deep", deep))
                except (PermissionError, FileNotFoundError) as exc:
                    print(f"   ⚠ exploration ignorée : {exc}")
                    ctx.audit.event("outil_indisponible", outil="katana", raison=str(exc))

        # 2) services non web vus par nmap (bases de données, SSH, SMB…)
        if tools.get("network_scan", True):
            web_ports = {urlparse(u).port or (443 if urlparse(u).scheme == "https" else 80) for u in urls}
            net = sorted({f"{s.address or s.host}:{s.port}" for s in ctx.services
                          if s.port not in web_ports and ctx.guard.is_in_scope(f"{s.address or s.host}:{s.port}")})
            if net:
                print(f"   nuclei (services réseau) sur {len(net)} port(s)…")
                _merge(ctx, ctx.runner.run("nuclei_net", net))

    for f in ctx.findings:
        print(f"   {f.id}  [{f.severity:<8}] {f.title}  ({f.cve or 'sans CVE'})")
    ctx.audit.event("scan", findings=len(ctx.findings))
