# -*- coding: utf-8 -*-
"""Journal d'audit de la mission.

Règle : on journalise les DÉCISIONS (route, nombre d'entités masquées,
repli local...), jamais les valeurs réelles ni la table de correspondance.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class AuditLog:
    def __init__(self, run_dir: Path):
        run_dir.mkdir(parents=True, exist_ok=True)
        self.path = run_dir / "audit.jsonl"

    def event(self, kind: str, **data) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": kind, **data}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
