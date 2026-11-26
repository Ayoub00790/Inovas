# -*- coding: utf-8 -*-
"""Accès aux modèles : SLM local (Ollama) et LLM externe (cloud), via LiteLLM.

Règle d'or appliquée DANS LE CODE : `cloud()` n'accepte qu'un SafePrompt
émis par la passerelle. Passer un texte brut lève une erreur — impossible
d'envoyer par mégarde une donnée non masquée.

Chaque modèle a son mode (settings.llm.local_mode / cloud_mode) :
  mock -> réponse simulée, pour démontrer la chaîne sans modèle installé ;
  live -> vrai appel via LiteLLM.

Chaque appel est mesuré (tokens, durée, coût estimé) dans usage.jsonl :
ce sont les données de l'analyse ROI.
"""
from __future__ import annotations

import json
import math
import re
import time
from pathlib import Path

from ..core.budget import Budget
from ..core.models import SafePrompt

TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+\]")

# Variable d'environnement attendue selon le préfixe LiteLLM du modèle
API_KEY_VARS = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
                "gemini": "GEMINI_API_KEY", "mistral": "MISTRAL_API_KEY",
                "azure": "AZURE_API_KEY", "groq": "GROQ_API_KEY", "deepseek": "DEEPSEEK_API_KEY"}


class UnsafePromptError(TypeError):
    pass


def estimate_tokens(text: str) -> int:
    """Estimation grossière (≈ 4 caractères par token) pour le mode simulé."""
    return max(1, math.ceil(len(text) / 4))


class LLMClient:
    def __init__(self, settings: dict, usage_log: Path | None = None, budget: Budget | None = None):
        c = settings.get("llm", {})
        legacy = c.get("mode", "mock")             # ancien réglage unique, encore accepté
        self.local_mode = c.get("local_mode", legacy)
        self.cloud_mode = c.get("cloud_mode", legacy)
        self.local_model = c.get("local_model", "ollama/qwen2.5:7b")
        self.local_api_base = c.get("local_api_base")
        self.cloud_model = c.get("cloud_model", "openai/gpt-4o")
        self.cloud_api_base = c.get("cloud_api_base")
        # Température : réglage commun « temperature », ou propre à chaque modèle
        # (local_temperature / cloud_temperature). null = valeur par défaut du modèle.
        common = c.get("temperature", 0.2)
        self.local_temperature = c.get("local_temperature", common)
        self.cloud_temperature = c.get("cloud_temperature", common)
        self.timeout = float(c.get("timeout_s", 120))
        self.retries = int(c.get("retries", 1))              # nouvel essai si réseau lent ou API surchargée
        self.max_tokens = c.get("max_tokens", 3000)          # réponses bornées : plus rapides, moins coûteuses
        p = settings.get("pricing", {})
        self.price_in = float(p.get("cloud_input_per_million", 0) or 0)
        self.price_out = float(p.get("cloud_output_per_million", 0) or 0)
        self.usage_log = usage_log
        self.budget = budget
        self.calls: list[dict] = []

    # ------------------------------------------------------------------
    def local(self, system: str, user: str, phase: str = "") -> str:
        """SLM local : peut recevoir les données réelles (rien ne sort)."""
        return self._call("local", self.local_model, self.local_mode, system, user,
                          self.local_api_base, phase, self._mock_local, self.local_temperature)

    def cloud(self, prompt: SafePrompt, system: str, phase: str = "") -> str:
        """LLM externe : uniquement du texte masqué et validé par la passerelle."""
        from ..gateway.passerelle import Passerelle
        if not isinstance(prompt, SafePrompt) or not isinstance(prompt._issuer, Passerelle):
            raise UnsafePromptError("Appel cloud refusé : le texte n'est pas passé par la passerelle.")
        if self.budget:
            self.budget.check_cloud()              # lève BudgetExceeded si plafond atteint
        return self._call("cloud", self.cloud_model, self.cloud_mode, system, prompt.text,
                          self.cloud_api_base, phase, self._mock_cloud, self.cloud_temperature)

    # ------------------------------------------------------------------
    @staticmethod
    def _tokens(resp) -> tuple[int, int]:
        u = getattr(resp, "usage", None)
        return int(getattr(u, "prompt_tokens", 0) or 0), int(getattr(u, "completion_tokens", 0) or 0)

    def _call(self, target, model, mode, system, user, api_base, phase, mock, temperature=None) -> str:
        t0 = time.perf_counter()
        if mode == "live":
            import os
            # pas d'appel réseau parasite au chargement (grille de prix embarquée)
            os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
            import litellm  # import tardif : inutile en mode simulé
            litellm.telemetry = False
            # Certains modèles imposent leurs paramètres (ex. Claude Haiku 5.5 : temperature=1
            # uniquement). Un paramètre refusé est alors ignoré au lieu de faire échouer l'appel.
            litellm.drop_params = True
            kwargs = {"model": model, "api_base": api_base, "timeout": self.timeout,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user}]}
            if temperature is not None:
                kwargs["temperature"] = float(temperature)
            if self.max_tokens:
                kwargs["max_tokens"] = int(self.max_tokens)
            if self.retries:
                kwargs["num_retries"] = self.retries
            t0 = time.perf_counter()     # on chronomètre l'appel seul, pas le chargement de LiteLLM
            resp = litellm.completion(**kwargs)
            content = resp.choices[0].message.content or ""
            pt, ct = self._tokens(resp)
            # Certains modèles « réfléchissent » avant de répondre et ces tokens comptent dans
            # max_tokens : budget épuisé = texte VIDE (constaté avec Claude Haiku 5.5).
            # Un nouvel essai avec un budget plus large, une seule fois.
            if not content.strip() and kwargs.get("max_tokens") and \
                    getattr(resp.choices[0], "finish_reason", None) == "length":
                kwargs["max_tokens"] = min(int(kwargs["max_tokens"]) * 3, 12000)
                resp = litellm.completion(**kwargs)
                content = resp.choices[0].message.content or ""
                pt2, ct2 = self._tokens(resp)
                pt, ct = pt + pt2, ct + ct2                     # les deux appels sont facturés
            if getattr(resp.choices[0], "finish_reason", None) == "length":   # coupée par max_tokens
                content += "\n\n[Réponse tronquée : limite de longueur atteinte (llm.max_tokens).]"
            usage = getattr(resp, "usage", None)
            pt = pt or estimate_tokens(system + user)
            ct = ct or estimate_tokens(content)
            estimated = usage is None
        else:
            content = mock(user)
            pt, ct, estimated = estimate_tokens(system + user), estimate_tokens(content), True

        cost = None
        if target == "cloud" and (self.price_in or self.price_out):
            cost = round((pt * self.price_in + ct * self.price_out) / 1_000_000, 6)
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "phase": phase, "target": target,
                  "model": model, "mode": mode, "prompt_tokens": pt, "completion_tokens": ct,
                  "latency_ms": round((time.perf_counter() - t0) * 1000), "estimated": estimated,
                  "cost_usd": cost}
        self.calls.append(record)
        if self.budget:
            self.budget.record(target, pt + ct)
        if self.usage_log:
            with open(self.usage_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return content

    def summary(self) -> dict:
        out = {}
        for target in ("local", "cloud"):
            calls = [c for c in self.calls if c["target"] == target]
            costs = [c["cost_usd"] for c in calls if c["cost_usd"] is not None]
            out[target] = {
                "calls": len(calls),
                "prompt_tokens": sum(c["prompt_tokens"] for c in calls),
                "completion_tokens": sum(c["completion_tokens"] for c in calls),
                "latency_ms": sum(c["latency_ms"] for c in calls),
                "cost_usd": round(sum(costs), 4) if costs else None,
                "estimated": any(c["estimated"] for c in calls),
            }
        return out

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
        if "réponds uniquement" in masked.lower():           # diagnostic (commande check)
            return "OK " + " ".join(toks)
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
