# -*- coding: utf-8 -*-
"""Point d'entrée en ligne de commande.

    python -m inova.main run   --scope config/scope.yaml [--demo] [--auto-approve]
    python -m inova.main route --scope config/scope.yaml
    python -m inova.main mask  --scope config/scope.yaml "texte à masquer"
"""
from __future__ import annotations

import argparse
import tempfile

from .core.config import build_profile, load_yaml


def main() -> None:
    ap = argparse.ArgumentParser(prog="inova", description="INOVA — pentest assisté par IA, confidentialité maîtrisée")
    ap.add_argument("--settings", default="config/settings.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="lancer une mission complète (7 phases)")
    r.add_argument("--scope", required=True)
    r.add_argument("--demo", action="store_true", help="données d'exemple, aucun outil lancé")
    r.add_argument("--auto-approve", action="store_true", help="valide automatiquement (démo uniquement)")

    d = sub.add_parser("route", help="afficher la décision de l'aiguilleur")
    d.add_argument("--scope", required=True)

    m = sub.add_parser("mask", help="démontrer la passerelle sur un texte")
    m.add_argument("--scope", required=True)
    m.add_argument("text")

    a = ap.parse_args()

    if a.cmd == "run":
        from .orchestrator import run
        run(a.settings, a.scope, demo=a.demo, auto_approve=a.auto_approve)

    elif a.cmd == "route":
        from .router.aiguilleur import Aiguilleur
        dec = Aiguilleur(load_yaml(a.settings)).decide(build_profile(load_yaml(a.scope)))
        print(f"ROUTE : {dec.route.value}  (complexité {dec.complexity}, sensibilité {dec.sensitivity})")
        for why in dec.reasons:
            print(" -", why)

    elif a.cmd == "mask":
        from .gateway.passerelle import Passerelle
        from .gateway.vault import Vault
        settings = load_yaml(a.settings)
        p = Passerelle(settings, load_yaml(a.scope), Vault(tempfile.mkdtemp(), "demo"),
                       settings["engagement"].get("language", "fr"))
        safe, res = p.to_safe_prompt(a.text)
        print("Texte masqué  :", res.masked_text)
        print(f"Entités : {res.nb_entities} · incertaines : {res.uncertain_spans} · "
              f"fuites résiduelles : {res.residual_leaks or 'aucune'}")
        print("Envoi cloud   :", "AUTORISÉ" if safe else "REFUSÉ -> repli local (fail-closed)")


if __name__ == "__main__":
    main()
