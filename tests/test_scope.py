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


def test_titre_repete_retire_et_cout_sans_appel():
    from inova.phases.p7_rapport import _fmt_cost, _strip_title
    assert _strip_title("**Synthèse Exécutive**\nTexte.", "Synthèse exécutive") == "Texte."
    assert _strip_title("Texte seul.", "Synthèse exécutive") == "Texte seul."
    assert _fmt_cost(None, 0) == "0 $ (aucun appel)"
    assert _fmt_cost(0.0051, 3) == "0.0051 $"


def test_cible_injoignable_detectee():
    import socket
    from inova.phases.p3_vulnscan import reachable
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    assert reachable(f"http://127.0.0.1:{port}")
    srv.close()
    assert not reachable(f"http://127.0.0.1:{port}", timeout=1)


def test_constats_analyses_meme_sans_act_attend():
    from inova.core.models import Finding
    from inova.phases.p5_exploitation import select_candidates
    mk = lambda i, sev, dec: Finding(id=i, title=i, asset="x", severity=sev, cve=None, cvss=5.0,  # noqa: E731
                                    epss=0.0, decision=dec)
    assert [f.id for f in select_candidates([mk("A", "medium", "TRACK"), mk("B", "low", "TRACK")], 5)] == ["A"]
    assert [f.id for f in select_candidates([mk("A", "medium", "TRACK"), mk("C", "high", "ACT")], 5)] == ["C"]


def test_preuve_extraite_du_corps_de_reponse(tmp_path):
    import json
    from inova.phases.p3_vulnscan import parse_nuclei_jsonl
    rec = {"template-id": "prometheus-metrics", "matched-at": "http://127.0.0.1:3000/metrics",
           "info": {"name": "Prometheus Metrics - Detect", "severity": "medium"},
           "response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n# HELP process_cpu\nprocess_cpu 1.5\n"}
    f = tmp_path / "n.jsonl"
    f.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert parse_nuclei_jsonl(f)[0].evidence == "# HELP process_cpu; process_cpu 1.5"


def test_tous_les_fichiers_lus_et_ecrits_en_utf8():
    """Sous Windows, l'encodage par défaut est cp1252 : une lecture sans encoding="utf-8"
    plante sur la sortie d'un outil (UnicodeDecodeError). On l'interdit dans tout le code."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "inova"
    bad = []
    for f in root.rglob("*.py"):
        src = f.read_text(encoding="utf-8")
        for m in re.finditer(r"\.(read_text|write_text)\((?P<args>[^()]*(?:\([^()]*\)[^()]*)*)\)|\bopen\((?P<o>[^()]*)\)", src):
            args = m.group("args") if m.group("args") is not None else m.group("o")
            if "webbrowser" in src[max(0, m.start() - 12):m.start()]:
                continue
            if "encoding" not in args and "rb" not in args and "wb" not in args:
                bad.append(f"{f.name}: {m.group(0)[:60]}")
    assert bad == []


def test_constat_sans_cvss_classe_par_gravite():
    from inova.core.models import Finding
    from inova.phases.p4_priorisation import ORDER, SEV_ORDER
    mk = lambda i, sev, cvss: Finding(id=i, title=i, asset="x", severity=sev, cvss=cvss, decision="ATTEND")  # noqa: E731
    fs = sorted([mk("haute", "high", 7.5), mk("critique-sans-cvss", "critical", 0.0)],
                key=lambda f: (ORDER[f.decision], SEV_ORDER.get(f.severity, 5), -f.cvss, -f.epss))
    assert fs[0].id == "critique-sans-cvss"
