# -*- coding: utf-8 -*-
"""Exécute une étape de raisonnement IA selon la route décidée.

    route LOCAL / LOCAL_RESTRICTED  -> SLM local (données réelles, rien ne sort)
    route CLOUD + étape autorisée   -> passerelle -> LLM externe -> réinjection

Replis locaux automatiques (fail-closed) :
  - masquage incertain ou fuite résiduelle (passerelle) ;
  - plafond de mission atteint (appels, tokens, durée).

Avant tout envoi : neutralisation des instructions piégées venues de la cible.
Après chaque réponse : revue des actions proposées par l'IA.
"""
from __future__ import annotations

import json

from ..core.audit import AuditLog
from ..core.budget import BudgetExceeded
from ..core.models import Route, RouteDecision
from ..gateway.passerelle import Passerelle
from ..guardrails.actions import hosts_out_of_scope, review
from ..guardrails.injection import SYSTEM_RULE, sanitize
from ..llm.client import LLMClient

SYSTEM = ("Tu assistes un pentesteur dans une mission AUTORISÉE. Tu analyses, priorises "
          "et proposes des vérifications NON destructives. Tu ne fournis jamais de charge "
          "malveillante ni d'action hors périmètre. Conserve tels quels les jetons [XXX_n]. "
          + SYSTEM_RULE)


class Reasoner:
    def __init__(self, decision: RouteDecision, passerelle: Passerelle | None,
                 llm: LLMClient, audit: AuditLog, guard=None):
        self.decision = decision
        self.passerelle = passerelle
        self.llm = llm
        self.audit = audit
        self.guard = guard
        # Trace EN MÉMOIRE de chaque échange (pour l'interface locale) ;
        # seule la partie masquée est écrite sur disque (cloud_outbox.jsonl).
        self.trace: list[dict] = []
        self.last: dict = {}

    def think(self, phase: str, task: str, context: str, allow_cloud: bool = False) -> str:
        # 1) neutraliser les instructions piégées venues de la cible
        context, injections = sanitize(context)
        if injections:
            self.audit.event("injection_suspectee", phase=phase, count=len(injections),
                             categories=sorted({c for i in injections for c in i["categories"]}),
                             sources=sorted({i["source"] for i in injections}))
        text = f"{task}\n\n{context}"
        step = {"phase": phase, "allow_cloud": allow_cloud, "real": text, "sent": None,
                "cloud_raw": None, "fail_closed": False, "budget": None, "injections": injections}

        # 2) choisir le chemin
        answer = None
        if allow_cloud and self.decision.route == Route.CLOUD and self.passerelle:
            answer = self._via_cloud(phase, text, step)
        if answer is None:
            self.audit.event("reasoning", phase=phase, path="LOCAL")
            answer = self.llm.local(SYSTEM, text, phase=phase)
            step["path"] = "LOCAL"

        # 3) relire les actions proposées par l'IA
        flags = review(answer, self.guard)
        step["unsafe_actions"] = flags
        step["out_of_scope"] = hosts_out_of_scope(answer, self.guard) if self.guard else []
        if flags:
            self.audit.event("action_signalee", phase=phase, categories=flags)
        step["answer"] = answer
        self.trace.append(step)
        self.last = step
        return answer

    def _via_cloud(self, phase: str, text: str, step: dict) -> str | None:
        safe, result = self.passerelle.to_safe_prompt(text)
        self.audit.event("masking", phase=phase, entities=result.nb_entities,
                         uncertain=result.uncertain_spans, residual=result.residual_leaks)
        step.update(entities=result.nb_entities, uncertain=result.uncertain_spans,
                    residual=result.residual_leaks)
        if safe is None:   # FAIL-CLOSED : le masquage n'est pas sûr -> on ne sort pas
            self.audit.event("fail_closed", phase=phase,
                             reason="détection incertaine ou fuite résiduelle", path="LOCAL")
            step["fail_closed"] = True
            return None
        try:
            raw = self.llm.cloud(safe, SYSTEM, phase=phase)
        except BudgetExceeded as exc:   # plafond atteint -> on ne sort plus
            self.audit.event("budget_atteint", phase=phase, reason=str(exc), path="LOCAL")
            step["budget"] = str(exc)
            return None
        self.audit.event("reasoning", phase=phase, path="CLOUD")
        self._outbox(phase, safe.text)
        step.update(path="CLOUD", sent=safe.text, cloud_raw=raw)
        return self.passerelle.restore(raw)

    def _outbox(self, phase: str, masked: str) -> None:
        """Copie exacte de ce qui quitte la machine (texte masqué uniquement) :
        preuve auditable qu'aucune donnée réelle n'est sortie."""
        with open(self.audit.path.parent / "cloud_outbox.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"phase": phase, "sent": masked}, ensure_ascii=False) + "\n")
