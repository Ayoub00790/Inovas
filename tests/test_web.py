# -*- coding: utf-8 -*-
"""L'API de l'interface web renvoie des données cohérentes et ne fait rien fuiter."""
import pytest

from inova.web.api import InovaAPI


@pytest.fixture(scope="module")
def api():
    return InovaAPI()


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
