# -*- coding: utf-8 -*-
"""python -m inova.main check — vérifie la configuration avant une vraie mission.

Teste, avec un texte FICTIF :
  1. le SLM local (Ollama) ;
  2. la passerelle (Presidio + modèles spaCy) ;
  3. le LLM cloud, via la passerelle (le texte envoyé est affiché : que des jetons).
Chaque échec est accompagné de la marche à suivre.
"""
from __future__ import annotations

import importlib.util
import os
import tempfile

from .core.config import load_dotenv, load_yaml
from .llm.client import API_KEY_VARS, LLMClient

TEST_TEXT = "Test INOVA : réponds uniquement OK. Serveur 10.99.0.42, password=Diagnostic2026, hôte srv-test.labo.local."
OK, KO, INFO = "  [OK] ", "  [ÉCHEC] ", "  [i] "


def _key_var(model: str) -> str | None:
    return API_KEY_VARS.get(model.split("/", 1)[0])


def run(settings_path: str, scope_path: str) -> int:
    loaded = load_dotenv()
    settings, scope = load_yaml(settings_path), load_yaml(scope_path)
    llm = LLMClient(settings)
    problems = 0
    print(f"\nINOVA — diagnostic\n{INFO}.env : {', '.join(loaded) if loaded else 'aucune variable chargée'}")
    print(f"{INFO}SLM local : {llm.local_model} (mode {llm.local_mode})")
    print(f"{INFO}LLM cloud : {llm.cloud_model} (mode {llm.cloud_mode})")

    needs_litellm = "live" in (llm.local_mode, llm.cloud_mode)
    if needs_litellm and importlib.util.find_spec("litellm") is None:
        print(f"{KO}litellm n'est pas installé -> pip install --default-timeout=300 --retries 10 litellm")
        return 1

    # 1) SLM local
    print("\n1. SLM local")
    try:
        ans = llm.local("Réponds en un mot.", "Réponds uniquement : OK", phase="diagnostic")
        c = llm.calls[-1]
        print(f"{OK}réponse « {ans.strip()[:60]} » en {c['latency_ms']} ms ({c['prompt_tokens']}+{c['completion_tokens']} tokens)")
    except Exception as exc:
        problems += 1
        print(f"{KO}{type(exc).__name__} : {str(exc)[:200]}")
        print(f"{INFO}Ollama est-il lancé ? (ollama serve) · modèle téléchargé ? "
              f"(ollama pull {llm.local_model.split('/', 1)[-1]}) · adresse : {llm.local_api_base}")

    # 2) Passerelle
    print("\n2. Passerelle (Presidio)")
    try:
        from .gateway.passerelle import Passerelle
        from .gateway.vault import Vault
        pas = Passerelle(settings, scope, Vault(tempfile.mkdtemp(), "diagnostic"),
                         settings["engagement"].get("language", "fr"))
        safe, res = pas.to_safe_prompt(TEST_TEXT)
        print(f"{OK}modèles spaCy : {pas.models} · {res.nb_entities} entité(s) masquée(s)")
        print(f"{INFO}texte qui partirait : {res.masked_text}")
        if safe is None:
            print(f"{KO}la passerelle refuse l'envoi (incertitude {res.uncertain_spans}, résidus {res.residual_leaks})")
            problems += 1
    except Exception as exc:
        print(f"{KO}{type(exc).__name__} : {exc}")
        print(f"{INFO}python -m spacy download fr_core_news_md   (ou fr_core_news_sm)")
        return problems + 1

    # 3) LLM cloud via la passerelle
    print("\n3. LLM cloud (via la passerelle)")
    var = _key_var(llm.cloud_model)
    if llm.cloud_mode == "live" and var and not os.environ.get(var):
        print(f"{KO}variable {var} absente : ajoute-la dans le fichier .env (jamais dans le code)")
        return problems + 1
    try:
        raw = llm.cloud(safe, "Réponds en un mot.", phase="diagnostic")
        c = llm.calls[-1]
        print(f"{OK}réponse « {pas.restore(raw).strip()[:80]} » en {c['latency_ms']} ms "
              f"({c['prompt_tokens']}+{c['completion_tokens']} tokens{', estimés' if c['estimated'] else ''})")
    except Exception as exc:
        problems += 1
        print(f"{KO}{type(exc).__name__} : {str(exc)[:200]}")
        print(f"{INFO}clé valide ? nom du modèle correct ? crédit disponible chez le fournisseur ?")

    print("\n" + ("Tout est prêt." if not problems else f"{problems} problème(s) à corriger."))
    return 1 if problems else 0
