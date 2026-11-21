# -*- coding: utf-8 -*-
"""Chargement des fichiers de configuration (settings + périmètre)."""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import PentestProfile


def load_yaml(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_profile(scope: dict) -> PentestProfile:
    """Construit le profil du pentest à partir du périmètre (phase 1)."""
    p = scope.get("pentest", {})
    t = scope.get("targets", {})
    nb_targets = len(t.get("domains", [])) + len(t.get("ip_ranges", [])) + len(t.get("urls", []))
    return PentestProfile(
        pentest_type=p.get("type", "web_boite_noire"),
        authenticated=bool(p.get("authenticated", False)),
        custom_application=bool(p.get("custom_application", False)),
        exploitation_chaining=bool(p.get("exploitation_chaining", False)),
        nb_targets=max(nb_targets, 1),
        data_classification=p.get("data_classification", "interne"),
        sector=p.get("sector", ""),
        sensitive_terms=list(scope.get("sensitive_terms", [])),
    )
