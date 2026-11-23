# -*- coding: utf-8 -*-
"""Mesure de la détection sur le laboratoire : rappel et précision.

On compare les constats d'une mission à la VÉRITÉ TERRAIN du laboratoire
(lab/attendu.yaml) : la liste des failles réellement présentes.

  rappel    = failles attendues trouvées / failles attendues
  précision = constats justes / constats annoncés

Un constat est « juste » s'il correspond à une faille attendue ou à une faille
réelle connue (« aussi_valides »). Un constat qui figure dans « faux_positifs »
est faux. Les autres sont « à qualifier » : la précision est donnée en
fourchette (borne basse : ils sont tous faux ; borne haute : ils sont tous justes)
jusqu'à ce que le pentesteur les ajoute au fichier.

Les doublons signalés par INOVA ne comptent qu'une fois.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..core.config import ROOT
from ..core.results import load_mission, resolve_run

DEFAULT_EXPECTED = ROOT / "lab" / "attendu.yaml"


def _port(asset: str) -> int | None:
    u = urlparse(asset if "://" in asset else "tcp://" + asset)
    try:
        return u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)
    except ValueError:
        return None


def _matches(f: dict, rule: dict) -> bool:
    if rule.get("port") and _port(f.get("asset", "")) != int(rule["port"]):
        return False
    proofs = {str(p).lower() for p in rule.get("preuves", [])}
    if (f.get("template_id") or "").lower() in proofs or (f.get("cve") or "").lower() in proofs:
        return True
    title = (f.get("title") or "").lower()
    return any(str(t).lower() in title for t in rule.get("titre_contient", []))


def measure(findings: list[dict], expected: dict) -> dict:
    attendues = expected.get("attendues", [])
    valides = expected.get("aussi_valides", [])
    faux = expected.get("faux_positifs", [])
    counted = [f for f in findings if not f.get("duplicate_of")]

    found = []
    for rule in attendues:
        hits = [f["id"] for f in counted if _matches(f, rule)]
        found.append({"id": rule["id"], "nom": rule.get("nom", ""), "port": rule.get("port"),
                      "trouvee": bool(hits), "constats": hits})

    true_pos, false_pos, unknown = [], [], []
    for f in counted:
        if any(_matches(f, r) for r in attendues + valides):
            true_pos.append(f["id"])
        elif any(_matches(f, r) for r in faux):
            false_pos.append(f["id"])
        else:
            unknown.append({"id": f["id"], "titre": f.get("title"), "actif": f.get("asset"),
                            "test": f.get("template_id")})

    n = len(counted)
    recall = sum(x["trouvee"] for x in found) / len(found) if found else None
    return {
        "rappel": recall,
        "attendues": found,
        "constats_comptes": n,
        "doublons_ecartes": len(findings) - n,
        "justes": true_pos, "faux": false_pos, "a_qualifier": unknown,
        "precision_basse": len(true_pos) / n if n else None,
        "precision_haute": (len(true_pos) + len(unknown)) / n if n else None,
    }


def load_expected(path: Path | str = DEFAULT_EXPECTED) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def evaluate_run(runs_root: Path, run: str | None = None, expected: Path | str = DEFAULT_EXPECTED) -> dict:
    runs = sorted(p for p in runs_root.glob("*/mission.json"))
    if not runs:
        raise FileNotFoundError("aucune mission enregistrée")
    run_dir = resolve_run(runs_root, run) if run else runs[-1].parent
    mission = load_mission(run_dir)
    res = measure(mission.get("findings", []), load_expected(expected))
    res["mission"] = run_dir.name
    (run_dir / "detection.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return res


def pct(x: float | None) -> str:
    return "—" if x is None else f"{x * 100:.0f} %"


def print_report(res: dict) -> None:
    print(f"\nINOVA — mesure de la détection  ({res['mission']})\n")
    for a in res["attendues"]:
        mark = "✓" if a["trouvee"] else "✗"
        print(f"  {mark} port {a['port']:<5} {a['nom']:<45} {', '.join(a['constats']) or 'non trouvée'}")
    print(f"\n  Rappel     : {pct(res['rappel'])}  "
          f"({sum(a['trouvee'] for a in res['attendues'])}/{len(res['attendues'])} failles attendues)")
    print(f"  Précision  : entre {pct(res['precision_basse'])} et {pct(res['precision_haute'])}  "
          f"({len(res['justes'])} justes, {len(res['faux'])} faux, {len(res['a_qualifier'])} à qualifier, "
          f"{res['doublons_ecartes']} doublon(s) écarté(s))")
    for u in res["a_qualifier"]:
        print(f"    ? {u['id']}  {u['titre']}  ({u['test']})  {u['actif']}")
    if res["a_qualifier"]:
        print("\n  Qualifie ces constats dans lab/attendu.yaml (aussi_valides ou faux_positifs) "
              "pour resserrer la fourchette.")
