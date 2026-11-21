# -*- coding: utf-8 -*-
"""Logique de l'interface, indépendante du serveur HTTP (testable directement).

Toutes ces fonctions tournent sur la machine du pentesteur : l'interface
n'écoute que sur 127.0.0.1, c'est pourquoi elle peut afficher les valeurs
réelles et la table de correspondance.
"""
from __future__ import annotations

import copy
import tempfile
import threading
import time
import traceback
import uuid
from dataclasses import asdict
from pathlib import Path

import yaml

from ..core.config import (ROOT, build_profile, load_dotenv, load_yaml, validate_scope)
from ..core.models import PentestProfile, SafePrompt
from ..core.results import list_missions, load_mission, resolve_run
from ..llm.client import TOKEN_RE, LLMClient
from ..router.aiguilleur import Aiguilleur
from ..router.reasoner import SYSTEM

MAX_TEXT = 20_000
APPROVAL_TIMEOUT_S = 900          # sans réponse en 15 min : refus par défaut


class MissionManager:
    """Une mission à la fois, en arrière-plan, avec validation humaine depuis l'interface."""

    def __init__(self, api: "InovaAPI"):
        self.api = api
        self._lock = threading.Lock()
        self._reset()

    def _reset(self):
        self.status, self.phase, self.phase_name = "idle", -1, ""
        self.pending, self.result, self.error = None, None, None
        self.decisions: list[dict] = []
        self._event, self._decision = None, False

    # --- appelés par le fil de la mission ---
    def _on_phase(self, i: int, name: str) -> None:
        self.phase, self.phase_name = i, name

    def _approve(self, action: str, details: str) -> bool:
        self._event, self._decision = threading.Event(), False
        self.pending = {"id": uuid.uuid4().hex[:8], "action": action, "details": details,
                        "since": time.strftime("%H:%M:%S")}
        self.status = "waiting_approval"
        answered = self._event.wait(APPROVAL_TIMEOUT_S)
        decision = self._decision if answered else False
        self.decisions.append({"action": action, "approved": decision,
                               "by": "humain" if answered else "délai dépassé"})
        self.pending, self.status = None, "running"
        return decision

    def _run(self, params: dict) -> None:
        from ..orchestrator import run_with
        try:
            settings, scope, demo = self.api.mission_inputs(params)
            interactive = bool(params.get("interactive", True))
            ctx = run_with(settings, scope, demo=demo, auto_approve=not interactive,
                           approver=self._approve if interactive else None, on_phase=self._on_phase)
            self.result = load_mission(ctx.run_dir)
            self.status = "done"
        except Exception as exc:
            traceback.print_exc()
            self.error, self.status = f"{type(exc).__name__} : {exc}", "error"

    # --- appelés par l'interface ---
    def start(self, params: dict) -> dict:
        with self._lock:
            if self.status in ("running", "waiting_approval"):
                raise RuntimeError("une mission est déjà en cours")
            self._reset()
            self.status = "running"
            threading.Thread(target=self._run, args=(params,), daemon=True).start()
        return {"ok": True}

    def decide(self, p: dict) -> dict:
        if not self.pending or p.get("id") != self.pending["id"]:
            raise ValueError("aucune validation en attente avec cet identifiant")
        self._decision = bool(p.get("approve"))
        self._event.set()
        return {"ok": True}

    def state(self) -> dict:
        return {"status": self.status, "phase": self.phase, "phase_name": self.phase_name,
                "pending": self.pending, "error": self.error, "decisions": self.decisions,
                "result": self.result if self.status == "done" else None}


class InovaAPI:
    def __init__(self, root: Path = ROOT):
        load_dotenv(root)
        self.root = root
        self.settings = load_yaml(root / "config" / "settings.yaml")
        self.runs_root = root / self.settings["engagement"].get("output_dir", "runs")
        self._load_scope()
        self._passerelle = None
        self._lock = threading.Lock()
        self.mission = MissionManager(self)

    def _load_scope(self):
        own = self.root / "config" / "scope.yaml"
        self.scope_file = own if own.exists() else self.root / "config" / "scope.example.yaml"
        self.scope = load_yaml(self.scope_file)

    # ------------------------------------------------------------------
    def info(self) -> dict:
        llm = LLMClient(self.settings)
        router = self.settings.get("router", {})
        auth = self.scope.get("authorization", {})
        from ..gateway.passerelle import pick_spacy_models
        try:
            models = pick_spacy_models(self.settings)
        except RuntimeError:
            models = {}
        return {
            "local_mode": llm.local_mode, "cloud_mode": llm.cloud_mode,
            "local_model": llm.local_model, "cloud_model": llm.cloud_model,
            "thresholds": {"complexity": router.get("complexity_threshold", 0.55),
                           "sensitivity": router.get("sensitivity_threshold", 0.70)},
            "budget": self.settings.get("budget", {}),
            "tools_dry_run": bool(self.settings.get("tools", {}).get("dry_run", True)),
            "spacy_models": models,
            "scope_file": self.scope_file.name,
            "client": auth.get("client"), "reference": auth.get("reference"),
            "valid_from": str(auth.get("valid_from")), "valid_until": str(auth.get("valid_until")),
            "targets": self.scope.get("targets", {}),
            "profile": asdict(build_profile(self.scope)),
        }

    # ------------------------------------------------------------------
    # Périmètre
    # ------------------------------------------------------------------
    def get_scope(self, _p=None) -> dict:
        return {"scope": self.scope, "file": self.scope_file.name,
                "example": load_yaml(self.root / "config" / "scope.example.yaml")}

    def save_scope(self, p: dict) -> dict:
        scope = p.get("scope") or {}
        errors = validate_scope(scope)
        if errors:
            return {"ok": False, "errors": errors}
        path = self.root / "config" / "scope.yaml"
        path.write_text("# Périmètre enregistré depuis l'interface INOVA\n"
                        + yaml.safe_dump(scope, allow_unicode=True, sort_keys=False), encoding="utf-8")
        with self._lock:
            self._load_scope()
            self._passerelle = None          # la deny-list dépend du périmètre
        return {"ok": True, "file": path.name}

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

    def reset_vault(self, _p=None) -> dict:
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
            # table de correspondance : chaque jeton présent dans le texte masqué
            # (une URL masquée par morceaux en contient plusieurs)
            mapping = [{"token": t, "entity": t[1:].rsplit("_", 1)[0], "value": pas.vault.lookup(t)}
                       for t in dict.fromkeys(TOKEN_RE.findall(res.masked_text))]
            cloud_raw = restored = None
            if safe and p.get("simulate_cloud", True):
                llm = LLMClient(self.settings)
                cloud_raw = llm.cloud(SafePrompt(res.masked_text, pas), SYSTEM, phase="passerelle")
                restored = pas.restore(cloud_raw)
        return {"text": text, "masked": res.masked_text, "spans": spans, "mapping": mapping,
                "entities": res.nb_entities, "uncertain": res.uncertain_spans,
                "residual": res.residual_leaks, "safe": safe,
                "max_uncertain": pas.max_uncertain, "min_confidence": pas.min_conf,
                "cloud_raw": cloud_raw, "restored": restored, "models": pas.models}

    # ------------------------------------------------------------------
    # 3) Mission
    # ------------------------------------------------------------------
    def mission_inputs(self, p: dict) -> tuple[dict, dict, bool]:
        scope = copy.deepcopy(self.scope)
        pentest = scope.setdefault("pentest", {})
        for key in ("type", "data_classification", "sector"):
            if p.get(key):
                pentest[key] = p[key]
        for key in ("authenticated", "custom_application", "exploitation_chaining"):
            if key in p:
                pentest[key] = bool(p[key])
        settings = copy.deepcopy(self.settings)
        settings["engagement"]["output_dir"] = str(self.runs_root)
        settings["gateway"]["vault_dir"] = str(self.root / settings["gateway"].get("vault_dir", ".inova_vault"))
        return settings, scope, p.get("source", "demo") != "tools"

    def run(self, p: dict) -> dict:
        """Mission complète, synchrone, validations automatiques (tests, scripts)."""
        from ..orchestrator import run_with
        settings, scope, demo = self.mission_inputs(p)
        ctx = run_with(settings, scope, demo=demo, auto_approve=True)
        return load_mission(ctx.run_dir)

    def mission_start(self, p: dict) -> dict:
        return self.mission.start(p)

    def mission_status(self, _p=None) -> dict:
        return self.mission.state()

    def mission_decide(self, p: dict) -> dict:
        return self.mission.decide(p)

    # ------------------------------------------------------------------
    # 4) Historique
    # ------------------------------------------------------------------
    def history(self, _p=None) -> dict:
        return {"missions": list_missions(self.runs_root)}

    def history_item(self, name: str) -> dict:
        return load_mission(resolve_run(self.runs_root, name))

    # ------------------------------------------------------------------
    # 5) Évaluation (taux de fuite)
    # ------------------------------------------------------------------
    def evaluate(self, p: dict) -> dict:
        from ..eval.leak_eval import run_eval
        settings = copy.deepcopy(self.settings)
        settings["engagement"]["output_dir"] = str(self.runs_root)
        model = p.get("model")
        if model:
            settings["gateway"]["spacy_models"] = {"fr": [model], "en": ["en_core_web_sm"]}
        with self._lock:
            return run_eval(settings, self.scope, self.root / "tests" / "fixtures" / "leak_cases.json", save=True)

    def eval_models(self, _p=None) -> dict:
        import spacy
        return {"installed": [m for m in ("fr_core_news_md", "fr_core_news_sm", "fr_core_news_lg")
                              if spacy.util.is_package(m)]}
