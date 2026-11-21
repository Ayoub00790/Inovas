# -*- coding: utf-8 -*-
"""Tests de NON-FUITE : la propriété centrale d'INOVA."""
import pytest

from inova.core.models import SafePrompt
from inova.llm.client import LLMClient, UnsafePromptError


def test_aucune_valeur_sensible_ne_sort(passerelle, leak_cases):
    for case in leak_cases:
        safe, res = passerelle.to_safe_prompt(case["text"])
        for secret in case["secrets"]:
            assert secret not in res.masked_text, f"FUITE de '{secret}' dans : {res.masked_text}"


def test_meme_valeur_meme_jeton(passerelle):
    _, r = passerelle.to_safe_prompt("Le serveur 10.10.0.42 héberge l'app ; 10.10.0.42 expose SSH.")
    tokens = [t for t in r.masked_text.split() if t.startswith("[TARGET_IP")]
    assert len(set(t.strip(".;") for t in tokens)) == 1


def test_valeurs_differentes_jetons_differents(passerelle):
    _, r = passerelle.to_safe_prompt("Web sur 10.10.0.61, base sur 10.10.0.62.")
    assert r.masked_text.count("[TARGET_IP_") == 2
    assert "10.10.0.61" not in r.masked_text and "10.10.0.62" not in r.masked_text


def test_reinjection_aller_retour(passerelle):
    original = "Corriger la faille sur https://demo.inova-lab.local/admin (serveur 10.10.0.20)."
    _, r = passerelle.to_safe_prompt(original)
    assert passerelle.restore(r.masked_text) == original


def test_identifiants_de_constat_preserves(passerelle):
    _, r = passerelle.to_safe_prompt("Constat F-001 : faille signalée par Karim Bennani.")
    assert "F-001" in r.masked_text          # utile au raisonnement, pas sensible
    assert "Bennani" not in r.masked_text    # la vraie personne reste masquée


def test_fail_closed_si_fuite_residuelle(passerelle):
    # simule un raté de détection : une IP du périmètre reste dans le texte "masqué"
    assert "IP_DANS_LE_PERIMETRE" in passerelle.residual_check("rapport sur 10.10.0.99")


def test_cloud_refuse_un_texte_brut(settings):
    llm = LLMClient(settings)
    with pytest.raises(UnsafePromptError):
        llm.cloud("texte brut non masqué", "system")
    with pytest.raises(UnsafePromptError):
        llm.cloud(SafePrompt("contrefait", _issuer=object()), "system")
