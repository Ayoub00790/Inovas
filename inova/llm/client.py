# -*- coding: utf-8 -*-
"""Accès aux modèles : SLM local (Ollama) et LLM externe (cloud), via LiteLLM.

Règle d'or appliquée DANS LE CODE : `cloud()` n'accepte qu'un SafePrompt
émis par la passerelle. Passer un texte brut lève une erreur — impossible
d'envoyer par mégarde une donnée non masquée.

Mode "mock" : réponses simulées, pour démontrer la chaîne sans modèle installé.
"""
from __future__ import annotations

import re

from ..core.models import SafePrompt

TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+\]")


class UnsafePromptError(TypeError):
    pass


class LLMClient:
    def __init__(self, settings: dict):
        c = settings.get("llm", {})
        self.mode = c.get("mode", "mock")
        self.local_model = c.get("local_model", "ollama/qwen2.5:7b")
        self.local_api_base = c.get("local_api_base")
        self.cloud_model = c.get("cloud_model", "openai/gpt-4o")
        self.temperature = float(c.get("temperature", 0.2))

    # ------------------------------------------------------------------
    def local(self, system: str, user: str) -> str:
        """SLM local : peut recevoir les données réelles (rien ne sort)."""
        if self.mode == "mock":
            return self._mock_local(user)
        return self._complete(self.local_model, system, user, api_base=self.local_api_base)

    def cloud(self, prompt: SafePrompt, system: str) -> str:
        """LLM externe : uniquement du texte masqué et validé par la passerelle."""
        from ..gateway.passerelle import Passerelle
        if not isinstance(prompt, SafePrompt) or not isinstance(prompt._issuer, Passerelle):
            raise UnsafePromptError("Appel cloud refusé : le texte n'est pas passé par la passerelle.")
        if self.mode == "mock":
            return self._mock_cloud(prompt.text)
        return self._complete(self.cloud_model, system, prompt.text)

    # ------------------------------------------------------------------
    def _complete(self, model: str, system: str, user: str, api_base: str | None = None) -> str:
        import litellm  # import tardif : inutile en mode mock
        resp = litellm.completion(
            model=model, api_base=api_base, temperature=self.temperature,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}])
        return resp.choices[0].message.content

    # ------------------------------------------------------------------
    # Réponses simulées (mode démo)
    # ------------------------------------------------------------------
    @staticmethod
    def _mock_local(user: str) -> str:
        return ("[SLM local — simulé] Analyse sommaire effectuée en local. "
                "Les éléments restent sur la machine ; capacité de raisonnement limitée : "
                "validation humaine recommandée pour les enchaînements complexes.")

    @staticmethod
    def _mock_cloud(masked: str) -> str:
        toks = list(dict.fromkeys(TOKEN_RE.findall(masked)))
        if "synthèse" in masked.lower():
            urls = [t for t in toks if "URL" in t] or ["la cible"]
            return ("[LLM externe — simulé, n'a vu que des jetons]\n"
                    f"Le test a révélé une faille critique sur {urls[0]}, activement exploitée dans la nature : "
                    "correctif à appliquer immédiatement.\n"
                    + (f"Un panneau d'administration ({urls[1]}) accepte des identifiants par défaut.\n"
                       if len(urls) > 1 else "")
                    + "Les autres constats relèvent de la configuration et peuvent être planifiés.\n"
                    "Combinées, les deux premières failles permettraient une prise de contrôle du serveur.\n"
                    "Priorité : corriger sous 48 h, puis re-tester.")
        target = next((t for t in toks if "URL" in t or "HOSTNAME" in t or "CLIENT_TERM" in t), "la cible")
        ip = next((t for t in toks if "IP" in t), "le serveur")
        secret = next((t for t in toks if "SECRET" in t), None)
        lines = [
            "[LLM externe — simulé, n'a vu que des jetons]",
            f"1. Exploitabilité : la faille sur {target} (hébergée sur {ip}) est atteignable "
            "depuis l'extérieur ; le score EPSS élevé confirme un intérêt actif des attaquants.",
            f"2. Chaînage : combinée à l'exposition de l'interface d'administration de {ip}, "
            "elle permettrait une élévation de privilèges.",
            "3. Vérification non destructive proposée : relancer le test ciblé de détection "
            "et comparer la réponse, sans charge malveillante.",
        ]
        if secret:
            lines.append(f"4. Remédiation immédiate : révoquer et faire tourner {secret}.")
        return "\n".join(lines)
