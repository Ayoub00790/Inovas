# -*- coding: utf-8 -*-
"""Logique de l'interface, indépendante du serveur HTTP (testable directement).

Toutes ces fonctions tournent sur la machine du pentesteur : l'interface
n'écoute que sur 127.0.0.1, c'est pourquoi elle peut afficher les valeurs
réelles et la table de correspondance.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import threading
from dataclasses import asdict
from pathlib import Path

from ..core.config import build_profile, load_yaml
from ..core.models import PentestProfile, SafePrompt
from ..llm.client import LLMClient
from ..router.aiguilleur import Aiguilleur
from ..router.reasoner import SYSTEM

ROOT = Path(__file__).resolve().parents[2]
MAX_TEXT = 20_000


class InovaAPI:
    def __init__(self, root: Path = ROOT):
        self.root = root
        self.settings = load_yaml(root / "config" / "settings.yaml")
        scope_file = root / "config" / "scope.yaml"
        self.scope_file = scope_file if scope_file.exists() else root / "config" / "scope.example.yaml"
        self.scope = load_yaml(self.scope_file)
        self._passerelle = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def info(self) -> dict:
        llm = self.settings.get("llm", {})
        router = self.settings.get("router", {})
        auth = self.scope.get("authorization", {})
        p = build_profile(self.scope)
        return {
            "mode": llm.get("mode", "mock"),
            "local_model": llm.get("local_model"),
            "cloud_model": llm.get("cloud_model"),
            "thresholds": {"complexity": router.get("complexity_threshold", 0.55),
                           "sensitivity": router.get("sensitivity_threshold", 0.70)},
            "scope_file": self.scope_file.name,
            "client": auth.get("client"), "reference": auth.get("reference"),
            "valid_from": str(auth.get("valid_from")), "valid_until": str(auth.get("valid_until")),
            "targets": self.scope.get("targets", {}),
            "profile": asdict(p),
        }

    # ------------------------------------------------------------------
    # 1) Aiguillage
    # ------------------------------------------------------------------
    def route(self, p: dict) -> dict:
        profile = PentestProfile(
            pentest_type=str(p.get("pentest_type", "web_boite_noire")),
            authenticated=bool(p.get("authenticated")),
            custom_application=bool(p.get("custom_application")),
            exploitation_chaining=bool(p.get("exploitation_chaining")),
            nb_targets=max(1, min(int(p.get("nb_targets", 1)), 50)),
            data_classification=str(p.get("data_classification", "interne")),
            sector=str(p.get("sector", "")),
            sensitive_terms=["x"] if p.get("sensitive_terms") else [])
        router = Aiguilleur(self.settings)
        d = router.decide(profile)
        return {"route": d.route.value, "complexity": d.complexity, "sensitivity": d.sensitivity,
                "reasons": d.reasons,
                "thresholds": {"complexity": router.c_thr, "sensitivity": router.s_thr}}

    # ------------------------------------------------------------------
    # 2) Passerelle
    # ------------------------------------------------------------------
    def passerelle(self):
        if self._passerelle is None:
            from ..gateway.passerelle import Passerelle
            from ..gateway.vault import Vault
            vault = Vault(tempfile.mkdtemp(prefix="inova_ui_"), "INTERFACE")
            self._passerelle = Passerelle(self.settings, self.scope, vault,
                                          self.settings["engagement"].get("language", "fr"))
        return self._passerelle

    def reset_vault(self) -> dict:
        with self._lock:
            self._passerelle = None
            self.passerelle()
        return {"ok": True}

    def mask(self, p: dict) -> dict:
        text = str(p.get("text", ""))[:MAX_TEXT]
        with self._lock:
            pas = self.passerelle()
            res, spans = pas.mask_detailed(text)
            safe = res.uncertain_spans <= pas.max_uncertain and not res.residual_leaks
            seen, mapping = set(), []
            for s in spans:
                if s["token"] not in seen:
                    seen.add(s["token"])
                    mapping.append({"token": s["token"], "entity": s["entity"],
                                    "value": pas.vault.lookup(s["token"])})
            cloud_raw = restored = None
            if safe and p.get("simulate_cloud", True):
                llm = LLMClient(self.settings)
                cloud_raw = llm.cloud(SafePrompt(res.masked_text, pas), SYSTEM)
                restored = pas.restore(cloud_raw)
        return {"text": text, "masked": res.masked_text, "spans": spans, "mapping": mapping,
                "entities": res.nb_entities, "uncertain": res.uncertain_spans,
                "residual": res.residual_leaks, "safe": safe,
                "max_uncertain": pas.max_uncertain, "min_confidence": pas.min_conf,
                "cloud_raw": cloud_raw, "restored": restored}

    # ------------------------------------------------------------------
    # 3) Mission complète (démo)
    # ------------------------------------------------------------------
    def run(self, p: dict) -> dict:
        from ..orchestrator import run_with

        scope = copy.deepcopy(self.scope)
        pentest = scope.setdefault("pentest", {})
        for key in ("type", "data_classification", "sector"):
            if p.get(key):
                pentest[key] = p[key]
        for key in ("authenticated", "custom_application", "exploitation_chaining"):
            if key in p:
                pentest[key] = bool(p[key])

        settings = copy.deepcopy(self.settings)
        settings["engagement"]["output_dir"] = str(self.root / settings["engagement"].get("output_dir", "runs"))
        settings["gateway"]["vault_dir"] = str(self.root / settings["gateway"].get("vault_dir", ".inova_vault"))

        console = io.StringIO()
        with self._lock, contextlib.redirect_stdout(console):
            ctx = run_with(settings, scope, demo=True, auto_approve=True)

        def read_jsonl(name: str) -> list:
            f = ctx.run_dir / name
            return [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines()] if f.exists() else []

        d = ctx.decision
        return {
            "decision": {"route": d.route.value, "complexity": d.complexity,
                         "sensitivity": d.sensitivity, "reasons": d.reasons},
            "services": [asdict(s) for s in ctx.services],
            "findings": [asdict(f) for f in ctx.findings],
            "trace": ctx.reasoner.trace,
            "audit": read_jsonl("audit.jsonl"),
            "outbox": read_jsonl("cloud_outbox.jsonl"),
            "report": (ctx.run_dir / "rapport.md").read_text(encoding="utf-8"),
            "run_dir": str(ctx.run_dir.relative_to(self.root)),
            "console": console.getvalue(),
        }
