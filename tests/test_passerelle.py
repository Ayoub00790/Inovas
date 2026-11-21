# -*- coding: utf-8 -*-
"""Tests de NON-FUITE : la propriété centrale d'INOVA."""
import pytest

from inova.core.models import SafePrompt
from inova.llm.client import LLMClient, UnsafePromptError


def _effective_leaks(passerelle, cases):
    """Valeurs qui seraient RÉELLEMENT sorties (texte accepté pour le cloud ET non masqué)."""
    out = []
    for case in cases:
        safe, res = passerelle.to_safe_prompt(case["text"])
        if safe is not None:
            out += [(case["id"], s) for s in case["secrets"] if s in res.masked_text]
    return out


def test_fuite_effective_nulle_sur_les_cas_standard(passerelle, leak_cases):
    """Seuil du mémoire : 0 % de fuite effective sur les cas standard (modèle fr_core_news_md)."""
    if passerelle.models.get("fr") != "fr_core_news_md":
        pytest.skip("seuil 0 % mesuré avec fr_core_news_md : python -m spacy download fr_core_news_md")
    standard = [c for c in leak_cases if c["difficulty"] == "standard"]
    assert _effective_leaks(passerelle, standard) == []


def test_fuite_effective_faible_quel_que_soit_le_modele(passerelle, leak_cases):
    standard = [c for c in leak_cases if c["difficulty"] == "standard"]
    total = sum(len(c["secrets"]) for c in standard)
    assert len(_effective_leaks(passerelle, standard)) / total <= 0.05


def test_aucun_secret_technique_ne_sort(passerelle, leak_cases):
    """Secrets, IP, URL, cartes, IBAN : détectés par motifs, donc indépendants du modèle NER."""
    techniques = [c for c in leak_cases if c["difficulty"] == "standard"
                  and c["category"] in ("nuclei", "http", "json", "config")]
    assert _effective_leaks(passerelle, techniques) == []


def test_elements_utiles_preserves(passerelle, leak_cases):
    for case in leak_cases:
        _, res = passerelle.to_safe_prompt(case["text"])
        for keep in case.get("keep", []):
            assert keep in res.masked_text, f"{case['id']} : « {keep} » masqué à tort"


def test_valeur_seule_masquee_la_cle_reste_lisible(passerelle):
    _, r = passerelle.to_safe_prompt("DB_PASSWORD=S3cr3t!2026")
    assert r.masked_text.startswith("DB_PASSWORD=[SECRET_")


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


def test_url_masquee_par_morceaux(passerelle):
    """Même hôte -> même jeton : le modèle peut relier les constats d'un même serveur."""
    t = ("F-001 sur https://demo.inova-lab.local/index.php ; F-003 sur https://demo.inova-lab.local/admin ; "
         "F-002 sur http://10.10.0.20:8080/cgi-bin/ et SSH sur 10.10.0.20")
    _, r = passerelle.to_safe_prompt(t)
    host = r.masked_text.split("https://")[1].split("/")[0]
    assert host.startswith("[") and r.masked_text.count(f"https://{host}/") == 2
    assert "/index.php" in r.masked_text and "/admin" in r.masked_text
    assert r.masked_text.count("[TARGET_IP_") == 2 and len(set(
        x.split("]")[0] for x in r.masked_text.split("[TARGET_IP_")[1:])) == 1
    assert passerelle.restore(r.masked_text) == t


def test_secrets_dans_une_url_masques(passerelle):
    _, r = passerelle.to_safe_prompt("https://user:Secr3t@demo.inova-lab.local/SinistresPro/x?token=abcdef123456")
    for s in ("Secr3t", "demo.inova-lab.local", "SinistresPro", "abcdef123456"):
        assert s not in r.masked_text
