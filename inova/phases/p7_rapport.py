# -*- coding: utf-8 -*-
"""Phase 7 — Rapport (Markdown), généré en LOCAL avec les vraies valeurs."""
from __future__ import annotations

import json

from ..core.context import Context


def _audit_stats(ctx: Context) -> dict:
    stats = {"cloud": 0, "local": 0, "fail_closed": 0, "masked_entities": 0}
    path = ctx.run_dir / "audit.jsonl"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            e = json.loads(line)
            if e["event"] == "reasoning":
                stats["cloud" if e["path"] == "CLOUD" else "local"] += 1
            elif e["event"] == "fail_closed":
                stats["fail_closed"] += 1
            elif e["event"] == "masking":
                stats["masked_entities"] += e.get("entities", 0)
    return stats


def run(ctx: Context) -> None:
    top = "\n".join(f"- {f.id} {f.title} ({f.decision}) sur {f.asset}"
                    for f in ctx.findings[:5])
    ctx.executive_summary = ctx.reasoner.think(
        phase="rapport", task="Rédige une synthèse exécutive (5 lignes) pour la direction.",
        context=top, allow_cloud=True)

    d, a = ctx.decision, ctx.scope.get("authorization", {})
    st = _audit_stats(ctx)
    L = [f"# Rapport de test d'intrusion — {a.get('client', '')}",
         f"Mission : {ctx.settings['engagement']['id']}  ·  Mandat : {a.get('reference', '')}", "",
         "## 1. Synthèse exécutive", ctx.executive_summary, "",
         "## 2. Aiguillage et confidentialité",
         f"- Route : **{d.route.value}** (complexité {d.complexity}, sensibilité {d.sensitivity})",
         *[f"  - {r}" for r in d.reasons],
         f"- Raisonnements locaux : {st['local']} · via cloud (masqués) : {st['cloud']} · "
         f"replis locaux (fail-closed) : {st['fail_closed']} · entités masquées : {st['masked_entities']}",
         "", "## 3. Surface d'attaque",
         "| Hôte | Port | Service | Produit / version |", "|---|---|---|---|",
         *[f"| {s.host} | {s.port}/{s.protocol} | {s.name} | {s.product} {s.version} |"
           for s in ctx.services],
         "", "## 4. Vulnérabilités priorisées",
         "| # | ID | Constat | Actif | Sévérité | CVSS | EPSS | Décision | Vérifiée |",
         "|---|---|---|---|---|---|---|---|---|",
         *[f"| {f.priority_rank} | {f.id} | {f.title} | {f.asset} | {f.severity} | {f.cvss} | "
           f"{f.epss:.2f} | {f.decision} | {'oui' if f.verified else 'non'} |" for f in ctx.findings],
         "", "## 5. Analyses détaillées"]
    for f in ctx.findings:
        if f.analysis:
            L += [f"### {f.id} — {f.title}", f"Élément observé : `{f.evidence}`", "", f.analysis, ""]
    L += ["## 6. Preuves", "Voir `evidence_index.json` (empreintes SHA-256) et `audit.jsonl`."]

    out = ctx.run_dir / "rapport.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"   Rapport écrit : {out}")
