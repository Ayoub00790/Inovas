# -*- coding: utf-8 -*-
"""Chargement et validation de la configuration (settings, périmètre, .env)."""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
from pathlib import Path

import yaml

from .models import PentestProfile

ROOT = Path(__file__).resolve().parents[2]

PENTEST_TYPES = ["web_boite_noire", "web_boite_grise", "api", "multi_applications"]
CLASSIFICATIONS = ["public", "interne", "confidentiel", "secret"]
SECTORS = ["", "assurance", "banque", "sante", "defense"]
CRITICALITIES = ["basse", "moyenne", "haute"]
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def load_yaml(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_dotenv(root: Path = ROOT) -> list[str]:
    """Charge le fichier .env (CLÉ=valeur) sans écraser les variables déjà définies.

    Retourne les NOMS des variables chargées (jamais les valeurs).
    """
    path = root / ".env"
    loaded = []
    if not path.exists():
        return loaded
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


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


def validate_scope(scope: dict) -> list[str]:
    """Vérifie un périmètre avant de l'enregistrer. Retourne la liste des erreurs."""
    errors = []
    auth = scope.get("authorization", {}) or {}
    for key in ("client", "reference", "signed_by"):
        if not str(auth.get(key, "")).strip():
            errors.append(f"Mandat : le champ « {key} » est obligatoire.")
    try:
        start = dt.date.fromisoformat(str(auth.get("valid_from")))
        end = dt.date.fromisoformat(str(auth.get("valid_until")))
        if end < start:
            errors.append("Mandat : la date de fin précède la date de début.")
    except ValueError:
        errors.append("Mandat : dates attendues au format AAAA-MM-JJ.")

    p = scope.get("pentest", {}) or {}
    if p.get("type") not in PENTEST_TYPES:
        errors.append("Type de pentest inconnu.")
    if p.get("data_classification") not in CLASSIFICATIONS:
        errors.append("Classification des données inconnue.")
    if p.get("sector", "") not in SECTORS:
        errors.append("Secteur inconnu.")

    t = scope.get("targets", {}) or {}
    if not (t.get("domains") or t.get("ip_ranges") or t.get("urls")):
        errors.append("Cibles : indiquer au moins un domaine, une plage IP ou une URL.")
    for d in t.get("domains", []):
        if not _DOMAIN.match(d):
            errors.append(f"Domaine invalide : {d}")
    for r in t.get("ip_ranges", []):
        try:
            ipaddress.ip_network(r, strict=False)
        except ValueError:
            errors.append(f"Plage IP invalide : {r}")
    for u in t.get("urls", []):
        if not re.match(r"^https?://[^\s/]+", u):
            errors.append(f"URL invalide (http:// ou https:// attendu) : {u}")
    for host, level in (scope.get("asset_criticality") or {}).items():
        if level not in CRITICALITIES:
            errors.append(f"Criticité « {level} » invalide pour {host} (basse, moyenne ou haute).")
    return errors
