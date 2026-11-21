# -*- coding: utf-8 -*-
"""Contrôle après mission : une valeur sensible connue a-t-elle quitté la machine ?

On relit cloud_outbox.jsonl (copie exacte de ce qui est parti vers le cloud)
et on y cherche :
  - toutes les valeurs réelles masquées pendant la mission (table de correspondance) ;
  - les domaines et termes sensibles du périmètre ;
  - toute IP appartenant aux plages du périmètre ;
  - les secrets connus du laboratoire (config/secrets_labo.txt, optionnel, non versionné).

Le résultat est une mesure, pas une promesse : c'est la preuve chiffrée
« fuite = 0 » attendue par le mémoire.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from ..core.config import ROOT

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MIN_LEN = 4          # en dessous, une valeur est trop courte pour une recherche fiable


def known_lab_secrets(path: Path = ROOT / "config" / "secrets_labo.txt") -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]


def audit_outbox(run_dir: Path, scope: dict, vault_values=(), extra_secrets=()) -> dict:
    path = Path(run_dir) / "cloud_outbox.jsonl"
    entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    t = scope.get("targets", {})
    values = {v for v in (*vault_values, *t.get("domains", []), *scope.get("sensitive_terms", []),
                          *extra_secrets, *known_lab_secrets()) if v and len(v) >= MIN_LEN}
    networks = [ipaddress.ip_network(r, strict=False) for r in t.get("ip_ranges", [])]

    leaks = []
    for i, e in enumerate(entries):
        sent = e.get("sent", "")
        low = sent.lower()
        for v in values:
            if v.lower() in low:
                leaks.append({"entry": i, "phase": e.get("phase"), "type": "valeur_connue",
                              "apercu": v[:3] + "…"})
        for ip in _IPV4.findall(sent):
            try:
                if any(ipaddress.ip_address(ip) in n for n in networks):
                    leaks.append({"entry": i, "phase": e.get("phase"), "type": "ip_du_perimetre",
                                  "apercu": ip.split(".")[0] + ".…"})
            except ValueError:
                pass
    return {"entries": len(entries), "checked_values": len(values), "leaks": leaks, "ok": not leaks}
