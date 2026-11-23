# -*- coding: utf-8 -*-
"""Fiabilité des constats : moins de faux positifs, moins de doublons.

Un scanner à signatures peut se tromper ou se répéter. Avant la priorisation, INOVA
croise ce que disent les différentes sources :

  1. Contradiction de versions : deux constats sur le même site affirment des
     versions incompatibles du même produit (ex. « ThinkPHP < 3.2.4 » alors qu'un
     autre test a reconnu ThinkPHP 5.0.23) -> le constat est marqué DOUTEUX.
  2. Confirmation par nmap : la version citée par le constat est celle que nmap a
     relevée sur le même port -> CONFIRMÉE (deux sources indépendantes).
     Si nmap voit une version du même produit hors de la plage visée -> DOUTEUSE.
  3. Doublons : même site, même produit, même type de faille (ex. deux variantes
     d'encodage de la même traversée Apache) -> un seul constat principal ; les
     autres sont rattachés et ne sont pas réanalysés (temps et coût économisés).

Le re-test reproduit (phase 5) confirme aussi un constat qui n'est pas douteux.
Ces règles sont prudentes : elles annotent, elles ne suppriment rien.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core.models import Finding, Service

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_VERSION = re.compile(r"(?<![\w.])(\d+(?:\.\d+){1,3})(?![\w.])")
_BELOW = re.compile(r"(?:<|&lt;|avant|before|prior to)\s*=?\s*v?(\d+(?:\.\d+){1,3})", re.I)


def _origin(asset: str) -> str:
    u = urlparse(asset)
    return f"{u.scheme}://{u.netloc}" if u.scheme else asset.split("/")[0]


def _port(asset: str) -> int | None:
    u = urlparse(asset if "://" in asset else "tcp://" + asset)
    try:
        return u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)
    except ValueError:
        return None


def _product(title: str) -> str:
    m = re.match(r"\s*([A-Za-z][A-Za-z0-9_.+-]*)", title)
    return m.group(1).lower().rstrip(".") if m else ""


def _kind(title: str) -> str:
    """Type de faille, sans produit ni versions : « path traversal and remote code execution »."""
    rest = title.split(" - ", 1)[1] if " - " in title else title
    rest = _VERSION.sub("", _BELOW.sub("", rest))
    return re.sub(r"[^a-z]+", " ", rest.lower()).strip()


def _v(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


def _claims(f: Finding) -> tuple[list[str], str | None]:
    """Versions exactes citées, et éventuelle borne « < X »."""
    below = _BELOW.search(f.title)
    exact = [] if below else _VERSION.findall(f.title.split(" - ")[0])
    return exact, below.group(1) if below else None


def _note(f: Finding, level: str | None, text: str) -> None:
    if text not in f.confidence_notes:
        f.confidence_notes.append(text)
    if level == "douteuse" or (level == "confirmée" and f.confidence != "douteuse"):
        f.confidence = level


def assess(findings: list[Finding], services: list[Service]) -> None:
    # 1) contradictions entre constats du même site et du même produit
    exact_by = {}
    for f in findings:
        exact, _ = _claims(f)
        for v in exact:
            exact_by.setdefault((_origin(f.asset), _product(f.title)), []).append((v, f.id))
    for f in findings:
        _, below = _claims(f)
        if not below:
            continue
        for v, other in exact_by.get((_origin(f.asset), _product(f.title)), []):
            if other != f.id and _v(v) >= _v(below):
                _note(f, "douteuse", f"{other} indique la version {v}, hors de la plage visée (< {below})")

    # 2) confirmation (ou contradiction) par la version relevée par nmap sur le même port
    for f in findings:
        port, prod = _port(f.asset), _product(f.title)
        exact, below = _claims(f)
        for s in services:
            if s.port != port or not s.version or not prod or prod not in f"{s.product} {s.name}".lower():
                continue
            seen = _VERSION.search(s.version)
            if not seen:
                continue
            seen = seen.group(1)
            if exact and seen in exact:
                _note(f, "confirmée", f"version {seen} confirmée par nmap (port {port})")
            elif exact and _v(seen)[:2] == _v(exact[0])[:2]:
                _note(f, "douteuse", f"nmap relève la version {seen}, pas {'/'.join(exact)}")
            elif below and _v(seen) >= _v(below):
                _note(f, "douteuse", f"nmap relève la version {seen}, hors de la plage visée (< {below})")

    # 3) doublons : même site, même produit, même type de faille
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        if f.duplicate_of is None and _kind(f.title):
            groups.setdefault((_origin(f.asset), _product(f.title), _kind(f.title)), []).append(f)
    for group in groups.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda f: (f.confidence == "douteuse", SEV_ORDER.get(f.severity, 5), -f.cvss, f.id))
        main = group[0]
        for f in group[1:]:
            f.duplicate_of = main.id
            _note(f, None, f"doublon probable de {main.id} (même site, même type de faille)")
