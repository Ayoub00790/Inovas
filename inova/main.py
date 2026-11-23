# -*- coding: utf-8 -*-
"""Point d'entrée en ligne de commande.

    python -m inova.main web                  interface graphique locale (recommandé)
    python -m inova.main check                diagnostic avant une vraie mission
    python -m inova.main run [--demo]         mission complète (7 phases)
    python -m inova.main route                décision de l'aiguilleur
    python -m inova.main mask "texte"         démonstration de la passerelle
    python -m inova.main eval-leaks           taux de fuite sur le corpus de test
    python -m inova.main eval-detection       rappel et précision de la dernière mission (laboratoire)

--scope est facultatif : config/scope.yaml s'il existe, sinon config/scope.example.yaml.
"""
from __future__ import annotations

import argparse
import sys
import tempfile

from .core.config import ROOT, build_profile, load_dotenv, load_yaml


def default_scope() -> str:
    own = ROOT / "config" / "scope.yaml"
    return str(own if own.exists() else ROOT / "config" / "scope.example.yaml")


def main() -> None:
    load_dotenv()
    ap = argparse.ArgumentParser(prog="inova", description="INOVA — pentest assisté par IA, confidentialité maîtrisée")
    ap.add_argument("--settings", default=str(ROOT / "config" / "settings.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("web", help="ouvrir l'interface graphique locale")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--no-browser", action="store_true")

    c = sub.add_parser("check", help="vérifier la configuration (Ollama, passerelle, cloud)")
    c.add_argument("--scope", default=None)

    r = sub.add_parser("run", help="lancer une mission complète (7 phases)")
    r.add_argument("--scope", default=None)
    r.add_argument("--demo", action="store_true", help="données d'exemple, aucun outil lancé")
    r.add_argument("--auto-approve", action="store_true", help="valide automatiquement (démo uniquement)")

    d = sub.add_parser("route", help="afficher la décision de l'aiguilleur")
    d.add_argument("--scope", default=None)

    m = sub.add_parser("mask", help="démontrer la passerelle sur un texte")
    m.add_argument("--scope", default=None)
    m.add_argument("text")

    e = sub.add_parser("eval-leaks", help="mesurer le taux de fuite sur le corpus de test")
    e.add_argument("--scope", default=None)
    e.add_argument("--corpus", default=str(ROOT / "tests" / "fixtures" / "leak_cases.json"))
    e.add_argument("--model", default=None, help="forcer un modèle spaCy français (ex. fr_core_news_sm)")
    dt = sub.add_parser("eval-detection", help="rappel et précision d'une mission sur le laboratoire")
    dt.add_argument("--run", default=None, help="dossier de mission (par défaut : la dernière)")
    dt.add_argument("--expected", default=str(ROOT / "lab" / "attendu.yaml"))

    a = ap.parse_args()
    scope = getattr(a, "scope", None) or default_scope()

    if a.cmd == "web":
        from .web.server import serve
        serve(port=a.port, open_browser=not a.no_browser)

    elif a.cmd == "check":
        from .diagnostic import run as check
        sys.exit(check(a.settings, scope))

    elif a.cmd == "run":
        from .orchestrator import run
        run(a.settings, scope, demo=a.demo, auto_approve=a.auto_approve)

    elif a.cmd == "route":
        from .router.aiguilleur import Aiguilleur
        dec = Aiguilleur(load_yaml(a.settings)).decide(build_profile(load_yaml(scope)))
        print(f"ROUTE : {dec.route.value}  (complexité {dec.complexity}, sensibilité {dec.sensitivity})")
        for why in dec.reasons:
            print(" -", why)

    elif a.cmd == "mask":
        from .gateway.passerelle import Passerelle
        from .gateway.vault import Vault
        settings = load_yaml(a.settings)
        p = Passerelle(settings, load_yaml(scope), Vault(tempfile.mkdtemp(), "demo"),
                       settings["engagement"].get("language", "fr"))
        safe, res = p.to_safe_prompt(a.text)
        print("Texte masqué  :", res.masked_text)
        print(f"Entités : {res.nb_entities} · incertaines : {res.uncertain_spans} · "
              f"fuites résiduelles : {res.residual_leaks or 'aucune'}")
        print("Envoi cloud   :", "AUTORISÉ" if safe else "REFUSÉ -> repli local (fail-closed)")

    elif a.cmd == "eval-leaks":
        from .eval.leak_eval import print_report, run_eval
        settings = load_yaml(a.settings)
        if a.model:
            settings.setdefault("gateway", {})["spacy_models"] = {"fr": [a.model], "en": ["en_core_web_sm"]}
        print_report(run_eval(settings, load_yaml(scope), a.corpus, save=True))

    elif a.cmd == "eval-detection":
        from .eval.detection import evaluate_run, print_report as show
        settings = load_yaml(a.settings)
        runs_root = ROOT / settings["engagement"].get("output_dir", "runs")
        show(evaluate_run(runs_root, a.run, a.expected))


if __name__ == "__main__":
    main()
