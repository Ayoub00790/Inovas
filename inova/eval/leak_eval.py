# -*- coding: utf-8 -*-
"""Mesure du taux de fuite de la passerelle sur un corpus de cas étiquetés.

Pour chaque cas : texte, valeurs sensibles attendues (« secrets ») et éléments
qu'il faut au contraire préserver (CVE, versions, identifiants de constats).

Indicateurs :
  - fuite brute      : valeurs sensibles encore présentes après masquage ;
  - fuite effective  : valeurs qui seraient RÉELLEMENT sorties, c.-à-d. fuite brute
                       dans un texte que la passerelle a accepté d'envoyer
                       (un repli local fail-closed empêche la sortie) ;
  - taux de repli    : textes refusés pour le cloud (coût en capacité) ;
  - sur-masquage     : éléments utiles au raisonnement masqués à tort.

La fuite effective est l'indicateur de confidentialité ; le repli et le
sur-masquage sont le prix payé en utilité. Les deux doivent être lus ensemble.
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from ..core.config import ROOT


def _rate(num: int, den: int) -> float | None:
    return round(100 * num / den, 1) if den else None


def _aggregate(rows: list[dict]) -> dict:
    secrets = sum(r["n_secrets"] for r in rows)
    raw = sum(len(r["leaked"]) for r in rows)
    eff = sum(len(r["effective"]) for r in rows)
    keep = sum(r["n_keep"] for r in rows)
    lost = sum(len(r["keep_lost"]) for r in rows)
    refused = sum(not r["sent"] for r in rows)
    return {"cases": len(rows), "secrets": secrets,
            "raw_leaks": raw, "raw_rate": _rate(raw, secrets),
            "effective_leaks": eff, "effective_rate": _rate(eff, secrets),
            "refused": refused, "refused_rate": _rate(refused, len(rows)),
            "keep": keep, "keep_lost": lost, "overmask_rate": _rate(lost, keep)}


def run_eval(settings: dict, scope: dict, corpus_path: str | Path, save: bool = False) -> dict:
    from ..gateway.passerelle import Passerelle
    from ..gateway.vault import Vault

    cases = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    pas = Passerelle(settings, scope, Vault(tempfile.mkdtemp(prefix="inova_eval_"), "EVAL"),
                     settings["engagement"].get("language", "fr"))
    rows = []
    for c in cases:
        safe, res = pas.to_safe_prompt(c["text"])
        masked = res.masked_text
        leaked = [s for s in c["secrets"] if s in masked]
        rows.append({
            "id": c["id"], "category": c["category"], "difficulty": c["difficulty"],
            "sent": safe is not None, "masked": masked,
            "n_secrets": len(c["secrets"]), "leaked": leaked,
            "effective": leaked if safe is not None else [],
            "n_keep": len(c.get("keep", [])),
            "keep_lost": [k for k in c.get("keep", []) if k not in masked],
            "uncertain": res.uncertain_spans, "residual": res.residual_leaks,
        })

    result = {
        "date": time.strftime("%Y-%m-%dT%H:%M:%S"), "corpus": Path(corpus_path).name,
        "models": pas.models,
        "overall": _aggregate(rows),
        "by_difficulty": {d: _aggregate([r for r in rows if r["difficulty"] == d])
                          for d in sorted({r["difficulty"] for r in rows})},
        "by_category": {k: _aggregate([r for r in rows if r["category"] == k])
                        for k in dict.fromkeys(r["category"] for r in rows)},
        "cases": rows,
    }
    if save:
        out = ROOT / settings["engagement"].get("output_dir", "runs")
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"eval_{time.strftime('%Y%m%d-%H%M%S')}.json"
        path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        result["saved_to"] = str(path.relative_to(ROOT))
    return result


def print_report(r: dict) -> None:
    def line(name, a):
        fmt = lambda v: "—" if v is None else f"{v:5.1f} %"   # noqa: E731
        print(f"  {name:<22} cas {a['cases']:>3} | fuite brute {fmt(a['raw_rate'])} ({a['raw_leaks']}/{a['secrets']})"
              f" | fuite effective {fmt(a['effective_rate'])} ({a['effective_leaks']})"
              f" | replis {fmt(a['refused_rate'])} | sur-masquage {fmt(a['overmask_rate'])}")
    print(f"\nINOVA — mesure de fuite · corpus {r['corpus']} · modèles {r['models']}\n")
    line("GLOBAL", r["overall"])
    for d, a in r["by_difficulty"].items():
        line(f"  {d}", a)
    print()
    for k, a in r["by_category"].items():
        line(k, a)
    bad = [c for c in r["cases"] if c["effective"]]
    if bad:
        print("\nValeurs qui seraient sorties (fuite effective) :")
        for c in bad:
            print(f"  {c['id']} [{c['difficulty']}] {', '.join(c['effective'])}")
    lost = [c for c in r["cases"] if c["keep_lost"]]
    if lost:
        print("\nÉléments utiles masqués à tort :")
        for c in lost:
            print(f"  {c['id']} {', '.join(c['keep_lost'])}")
    if r.get("saved_to"):
        print(f"\nRésultat détaillé : {r['saved_to']}")
