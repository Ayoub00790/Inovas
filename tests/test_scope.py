# -*- coding: utf-8 -*-
"""Garde-fous : périmètre, priorisation."""
import datetime as dt

from inova.core.models import Finding
from inova.guardrails.scope import ScopeGuard
from inova.phases.p4_priorisation import decide


def test_perimetre(scope):
    g = ScopeGuard(scope)
    assert g.is_in_scope("https://demo.inova-lab.local/login")
    assert g.is_in_scope("10.10.0.20")
    assert not g.is_in_scope("10.10.0.1")            # exclu explicitement
    assert not g.is_in_scope("https://google.com")   # hors périmètre
    assert not g.is_in_scope("192.168.1.5")


def test_mandat_date(scope):
    g = ScopeGuard(scope)
    assert g.authorization_valid(dt.date(2026, 11, 15))
    assert not g.authorization_valid(dt.date(2027, 1, 15))


def test_priorisation_ssvc(scope):
    critique = Finding(id="F1", title="x", asset="https://demo.inova-lab.local/a",
                       severity="critical", cvss=9.8, epss=0.9, internet_facing=True)
    faible = Finding(id="F2", title="y", asset="https://demo.inova-lab.local/b",
                     severity="low", cvss=3.1, epss=0.0)
    assert decide(critique, scope) == "ACT"
    assert decide(faible, scope) == "TRACK"


def test_titres_de_l_ia_ne_cassent_pas_le_rapport():
    from inova.phases.p7_rapport import _demote
    txt = "## 1. Exploitabilité réelle\nTexte\n### Détail\n- point"
    out = _demote(txt)
    assert "##" not in out and "**1. Exploitabilité réelle**" in out and "- point" in out
