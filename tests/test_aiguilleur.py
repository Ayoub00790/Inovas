# -*- coding: utf-8 -*-
"""L'aiguilleur respecte la matrice simple/lourd × peu/très sensible."""
import pytest

from inova.core.models import PentestProfile, Route
from inova.router.aiguilleur import Aiguilleur


def profile(lourd: bool, sensible: bool) -> PentestProfile:
    return PentestProfile(
        pentest_type="multi_applications" if lourd else "web_boite_noire",
        authenticated=lourd, custom_application=lourd, exploitation_chaining=lourd,
        nb_targets=4 if lourd else 1,
        data_classification="secret" if sensible else "public",
        sector="banque" if sensible else "")


@pytest.mark.parametrize("lourd,sensible,attendu", [
    (False, False, Route.LOCAL),
    (False, True, Route.LOCAL),
    (True, False, Route.CLOUD),
    (True, True, Route.LOCAL_RESTRICTED),
])
def test_matrice(settings, lourd, sensible, attendu):
    assert Aiguilleur(settings).decide(profile(lourd, sensible)).route == attendu


def test_decision_justifiee(settings):
    d = Aiguilleur(settings).decide(profile(True, False))
    assert d.reasons and "passerelle" in d.reasons[-1]
