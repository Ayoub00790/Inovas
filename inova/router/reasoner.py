# -*- coding: utf-8 -*-
"""Exécute une étape de raisonnement IA selon la route décidée.

    route LOCAL / LOCAL_RESTRICTED  -> SLM local (données réelles, rien ne sort)
    route CLOUD + étape autorisée   -> passerelle -> LLM externe -> réinjection
                                       (repli local automatique si le masquage
                                        n'est pas sûr : fail-closed)
"""
from __future__ import annotations

from ..core.audit import AuditLog
from ..core.models import Route, RouteDecision
from ..gateway.passerelle import Passerelle
from ..llm.client import LLMClient

SYSTEM = ("Tu assistes un pentesteur dans une mission AUTORISÉE. Tu analyses, priorises "
          "et proposes des vérifications NON destructives. Tu ne fournis jamais de charge "
          "malveillante ni d'action hors périmètre. Conserve tels quels les jetons [XXX_n].")


class Reasoner:
    def __init__(self, decision: RouteDecision, passerelle: Passerelle | None,
                 llm: LLMClient, audit: AuditLog):
        self.decision = decision
        self.passerelle = passerelle
        self.llm = llm
        self.audit = audit

    def think(self, phase: str, task: str, context: str, allow_cloud: bool = False) -> str:
        text = f"{task}\n\n{context}"
        if not (allow_cloud and self.decision.route == Route.CLOUD and self.passerelle):
            self.audit.event("reasoning", phase=phase, path="LOCAL")
            return self.llm.local(SYSTEM, text)

        safe, result = self.passerelle.to_safe_prompt(text)
        self.audit.event("masking", phase=phase, entities=result.nb_entities,
                         uncertain=result.uncertain_spans, residual=result.residual_leaks)
        if safe is None:
            # FAIL-CLOSED : le masquage n'est pas sûr -> on ne sort pas
            self.audit.event("fail_closed", phase=phase,
                             reason="détection incertaine ou fuite résiduelle", path="LOCAL")
            return self.llm.local(SYSTEM, text)

        self.audit.event("reasoning", phase=phase, path="CLOUD")
        self._outbox(phase, safe.text)
        answer = self.llm.cloud(safe, SYSTEM)
        return self.passerelle.restore(answer)

    def _outbox(self, phase: str, masked: str) -> None:
        """Copie exacte de ce qui quitte la machine (texte masqué uniquement) :
        preuve auditable qu'aucune donnée réelle n'est sortie."""
        import json
        with open(self.audit.path.parent / "cloud_outbox.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"phase": phase, "sent": masked}, ensure_ascii=False) + "\n")
