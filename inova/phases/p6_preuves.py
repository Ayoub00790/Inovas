# -*- coding: utf-8 -*-
"""Phase 6 — Preuves : indexer et sceller (empreinte SHA-256) chaque élément."""
from __future__ import annotations

import hashlib
import json

from ..core.context import Context


def run(ctx: Context) -> None:
    evidence_dir = ctx.run_dir / "evidence"
    files = []
    for p in sorted(evidence_dir.glob("*")):
        if p.is_file():
            files.append({"file": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})

    index = {
        "files": files,
        "findings": [{"id": f.id, "asset": f.asset, "evidence": f.evidence,
                      "verified": f.verified} for f in ctx.findings],
    }
    out = ctx.run_dir / "evidence_index.json"
    out.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"   {len(files)} fichier(s) scellé(s), {len(ctx.findings)} constat(s) indexé(s) -> {out.name}")
