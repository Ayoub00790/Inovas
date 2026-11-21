# -*- coding: utf-8 -*-
"""Phase 7 — Rapport (Markdown), généré en LOCAL avec les vraies valeurs.

Les sections 1 à 5 forment la version « direction » ; le rapport complet
(1 à 8) forme la version « technique » (voir l'export PDF de l'interface).
"""
from __future__ import annotations

import json
import re

from ..core.context import Context
from ..eval.outbox_audit import audit_outbox
from ..guardrails.injection import wrap_untrusted


def _audit_events(ctx: Context) -> list[dict]:
    p = ctx.audit.path
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


def _demote(text: str) -> str:
    """Les réponses de l'IA contiennent leurs propres titres (« ## 1. Exploitabilité »).
    On les transforme en lignes en gras pour qu'ils ne se mélangent pas à la
    numérotation du rapport (sinon la version « direction » les prendrait pour
    des sections)."""
    return re.sub(r"(?m)^\s*#{1,6}\s+(.+?)\s*#*\s*$", r"**\1**", text or "")


def _strip_title(text: str, title: str) -> str:
    """Retire une première ligne qui répète le titre de la section (« **Synthèse Exécutive** »)."""
    lines = (text or "").strip().splitlines()
    norm = lambda s: re.sub(r"[^a-z]", "", s.lower().translate(str.maketrans("éèêàç", "eeeac")))  # noqa: E731
    if lines and norm(lines[0]) == norm(title):
        lines = lines[1:]
    return "\n".join(lines).strip()


def _fmt_cost(v, calls: int = 1) -> str:
    if not calls:
        return "0 $ (aucun appel)"
    return f"{v:.4f} $" if v is not None else "non renseigné (tarifs à saisir dans settings.yaml)"


def run(ctx: Context) -> None:
    top = "\n".join(f"- {f.id} {f.title} ({f.decision}) sur {f.asset}" for f in ctx.findings[:5])
    ctx.executive_summary = ctx.reasoner.think(
        phase="rapport", task="Rédige une synthèse exécutive (5 lignes) pour la direction.",
        context=wrap_untrusted("constats", top), allow_cloud=True)

    # Contrôle de l'outbox : une valeur sensible connue est-elle sortie ?
    vault_values = ctx.passerelle.vault.values() if ctx.passerelle else []
    ctx.outbox_check = audit_outbox(ctx.run_dir, ctx.scope, vault_values)

    d, a = ctx.decision, ctx.scope.get("authorization", {})
    ev = _audit_events(ctx)
    count = lambda kind: sum(e["event"] == kind for e in ev)   # noqa: E731
    cloud_calls = sum(e["event"] == "reasoning" and e.get("path") == "CLOUD" for e in ev)
    local_calls = sum(e["event"] == "reasoning" and e.get("path") == "LOCAL" for e in ev)
    masked = sum(e.get("entities", 0) for e in ev if e["event"] == "masking")
    injections = sum(e.get("count", 1) for e in ev if e["event"] == "injection_suspectee")
    u = ctx.llm.summary()
    oc = ctx.outbox_check

    L = [f"# Rapport de test d'intrusion — {a.get('client', '')}",
         f"Mission : {ctx.settings['engagement']['id']}  ·  Mandat : {a.get('reference', '')}  ·  "
         f"Date : {ctx.started_at[:10]}" + ("  ·  Données de démonstration" if ctx.demo else ""), "",
         "## 1. Synthèse exécutive", _strip_title(_demote(ctx.executive_summary), "Synthèse exécutive"), "",
         "## 2. Vulnérabilités priorisées",
         "| # | ID | Constat | Actif | Sévérité | CVSS | EPSS | Décision | Vérifiée |",
         "|---|---|---|---|---|---|---|---|---|",
         *[f"| {f.priority_rank} | {f.id} | {f.title} | {f.asset} | {f.severity} | {f.cvss} | "
           f"{f.epss:.2f} | {f.decision} | {'oui' if f.verified else 'non'} |" for f in ctx.findings],
         "", "Décisions : **ACT** corriger immédiatement · **ATTEND** corriger rapidement · "
         "**TRACK\\*** surveiller de près · **TRACK** suivi normal.",
         "", "## 3. Aiguillage et confidentialité",
         f"- Route : **{d.route.value}** (complexité {d.complexity}, sensibilité {d.sensitivity})",
         *[f"  - {r}" for r in d.reasons],
         f"- Raisonnements locaux : {local_calls} · via cloud (masqués) : {cloud_calls} · "
         f"replis locaux (fail-closed) : {count('fail_closed')} · entités masquées : {masked}",
         f"- Contrôle de l'outbox : **{'aucune valeur sensible sortie' if oc['ok'] else str(len(oc['leaks'])) + ' fuite(s) détectée(s)'}** "
         f"({oc['entries']} envoi(s) vérifié(s) contre {oc['checked_values']} valeur(s) connue(s))",
         "", "## 4. Sécurité de la mission",
         f"- Instructions piégées venues de la cible, neutralisées : {injections}",
         f"- Actions proposées par l'IA et signalées (jamais exécutées) : {count('action_signalee')}",
         f"- Validations humaines : {sum(e['event'] == 'approval' and e.get('approved') for e in ev)} accordée(s), "
         f"{sum(e['event'] == 'approval' and not e.get('approved') for e in ev)} refusée(s)",
         f"- Plafonds de mission atteints : {count('budget_atteint')}",
         *[f"- {f.id} : {al}" for f in ctx.findings for al in f.alerts],
         "", "## 5. Coût et performance",
         "| Modèle | Appels | Tokens envoyés | Tokens reçus | Durée cumulée | Coût |",
         "|---|---|---|---|---|---|",
         f"| SLM local ({ctx.llm.local_model}, {ctx.llm.local_mode}) | {u['local']['calls']} | "
         f"{u['local']['prompt_tokens']} | {u['local']['completion_tokens']} | {u['local']['latency_ms']} ms | 0 $ (local) |",
         f"| LLM cloud ({ctx.llm.cloud_model}, {ctx.llm.cloud_mode}) | {u['cloud']['calls']} | "
         f"{u['cloud']['prompt_tokens']} | {u['cloud']['completion_tokens']} | {u['cloud']['latency_ms']} ms | "
         f"{_fmt_cost(u['cloud']['cost_usd'], u['cloud']['calls'])} |",
         f"Durée totale de la mission (validations humaines comprises) : {ctx.budget.elapsed():.1f} s"
         + "".join(f"  ·  tokens du {name} estimés (IA simulée)"
                   for name, key in (("SLM local", "local"), ("LLM cloud", "cloud"))
                   if u[key]["estimated"] and u[key]["calls"]),
         "", "## 6. Surface d'attaque",
         "| Hôte | Port | Service | Produit / version |", "|---|---|---|---|",
         *[f"| {s.host} | {s.port}/{s.protocol} | {s.name} | {s.product} {s.version} |"
           for s in ctx.services],
         "", "## 7. Analyses détaillées"]
    for f in ctx.findings:
        if f.analysis:
            L += [f"### {f.id} — {f.title}", f"Élément observé : `{f.evidence}`", "", _demote(f.analysis), ""]
    L += ["## 8. Preuves", "Voir `evidence_index.json` (empreintes SHA-256), `audit.jsonl`, "
          "`usage.jsonl` et `cloud_outbox.jsonl`."]

    out = ctx.run_dir / "rapport.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"   Contrôle de l'outbox : {'OK, aucune valeur sensible sortie' if oc['ok'] else 'FUITE DÉTECTÉE'}")
    print(f"   Rapport écrit : {out}")
