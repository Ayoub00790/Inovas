# -*- coding: utf-8 -*-
"""L'API de l'interface web : cohérence, non-fuite, mission interactive, périmètre, historique."""
import shutil
import time
from pathlib import Path

import pytest

from inova.web.api import InovaAPI

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    """API sur une copie du projet : les tests n'écrivent ni scope.yaml ni runs/ dans le dépôt."""
    root = tmp_path_factory.mktemp("inova")
    shutil.copytree(ROOT / "config", root / "config", ignore=shutil.ignore_patterns("scope.yaml", "secrets_labo.txt"))
    shutil.copytree(ROOT / "tests" / "fixtures", root / "tests" / "fixtures")
    return InovaAPI(root=root)


def test_aiguillage(api):
    assert api.route({"pentest_type": "web_boite_noire", "data_classification": "public"})["route"] == "LOCAL"
    lourd = {"pentest_type": "multi_applications", "authenticated": True, "custom_application": True,
             "exploitation_chaining": True, "nb_targets": 4}
    assert api.route({**lourd, "data_classification": "interne"})["route"] == "CLOUD"
    assert api.route({**lourd, "data_classification": "secret"})["route"] == "LOCAL_RESTRICTED"


def test_passerelle_cycle_complet(api):
    r = api.mask({"text": "Faille sur https://demo.inova-lab.local/login (10.10.0.20), password=Adm1n2026."})
    assert r["safe"]
    for secret in ("demo.inova-lab.local", "10.10.0.20", "Adm1n2026"):
        assert secret not in r["masked"] and secret not in r["cloud_raw"]
    assert "password=[SECRET_" in r["masked"]             # seule la valeur est masquée
    assert "Adm1n2026" in r["restored"]                   # réinjection locale
    assert "Adm1n2026.." not in r["restored"]             # ponctuation finale préservée


def test_passerelle_refus(api):
    r = api.mask({"text": "Contact : Karim Bennani, +212 6 12 34 56 78"})
    assert not r["safe"] and r["cloud_raw"] is None


def test_mission_secret_ne_sort_rien(api):
    r = api.run({"data_classification": "secret"})
    assert r["decision"]["route"] == "LOCAL_RESTRICTED"
    assert r["outbox"] == [] and all(t["path"] == "LOCAL" for t in r["trace"])


def test_mission_interactive_autoriser_puis_refuser(api):
    api.mission_start({"data_classification": "interne", "interactive": True})
    answers = [True, False]
    deadline = time.time() + 60
    while time.time() < deadline:
        s = api.mission_status()
        if s["status"] == "waiting_approval":
            api.mission_decide({"id": s["pending"]["id"], "approve": answers.pop(0)})
        elif s["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert s["status"] == "done", s.get("error")
    assert [d["approved"] for d in s["decisions"]] == [True, False]
    checked = [f for f in s["result"]["findings"] if f["decision"] in ("ACT", "ATTEND")]
    # re-test autorisé : reproduit ; re-test refusé : « non testé » (None), pas « non reproduit »
    assert sorted((f["verified"] for f in checked), key=str) == [None, True]
    assert any("re-test refusé par le pentesteur" in f["alerts"] for f in checked)
    # la page piégée du panneau d'administration a été neutralisée
    assert any(f["alerts"] for f in s["result"]["findings"])
    assert s["result"]["outbox_check"]["ok"]


def test_mauvaise_decision_refusee(api):
    with pytest.raises(ValueError):
        api.mission_decide({"id": "inexistant", "approve": True})


def test_historique(api):
    missions = api.history()["missions"]
    assert len(missions) >= 2 and {"route", "cloud_calls", "outbox_leaks"} <= set(missions[0])
    assert api.history_item(missions[0]["run"])["report"].startswith("# Rapport")
    for bad in ("../config", "..", "x/../../etc"):
        with pytest.raises((ValueError, FileNotFoundError)):
            api.history_item(bad)


def test_perimetre_valide_et_invalide(api):
    scope = api.get_scope()["example"]
    bad = {**scope, "targets": {"domains": ["pas un domaine"], "ip_ranges": ["999.1.1.0/24"], "urls": []}}
    r = api.save_scope({"scope": bad})
    assert not r["ok"] and len(r["errors"]) >= 2
    good = {**scope, "sensitive_terms": scope["sensitive_terms"] + ["ProjetAtlas"]}
    assert api.save_scope({"scope": good})["ok"]
    assert api.scope_file.name == "scope.yaml"
    assert "ProjetAtlas" not in api.mask({"text": "Le ProjetAtlas est exposé"})["masked"]


def test_requete_illisible_ne_fait_pas_planter_le_serveur():
    """Un scanner (nmap -sV, nuclei réseau) envoie des octets non HTTP : réponse 400, sans exception."""
    import socket
    import threading
    from http.server import ThreadingHTTPServer
    from inova.web.server import make_handler
    errors = []
    from types import SimpleNamespace
    fake_api = SimpleNamespace(**{n: (lambda *a, **k: {}) for n in dir(InovaAPI) if not n.startswith("_")})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fake_api, 0))
    srv.handle_error = lambda request, addr: errors.append(addr)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for raw in (b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n", b"HELP\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n"):
            with socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=3) as c:
                c.sendall(raw)
                c.recv(1024)
    finally:
        srv.shutdown()
    assert errors == []
