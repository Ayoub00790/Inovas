# -*- coding: utf-8 -*-
"""Exécution encadrée des outils de pentest.

- Liste blanche d'outils (settings.tools.allowlist).
- Vérification du périmètre AVANT chaque commande.
- Pas de shell (liste d'arguments) : pas d'injection de commande.
- Mode dry_run : affiche la commande sans l'exécuter.
- Toutes les sorties sont rangées dans runs/<mission>/evidence/.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from ..core.audit import AuditLog
from ..guardrails.scope import ScopeGuard

# Gabarits de commandes (non destructives)
TEMPLATES = {
    "nmap":          lambda t, out, _: ["nmap", "-sV", "-T3", "--top-ports", "1000", "-oX", out, t],
    "whatweb":       lambda t, out, _: ["whatweb", "--log-json", out, t],
    # -ni : pas d'Interactsh. Sinon nuclei fait appeler par la cible un serveur PUBLIC
    #       (oast.live…) : un tiers apprendrait quelles cibles sont testées. Contraire à INOVA.
    # -duc : pas de vérification de mise à jour pendant la mission.
    "nuclei":        lambda t, out, sev: ["nuclei", "-u", t, "-severity", sev or "medium,high,critical",
                                          "-ni", "-duc", "-jsonl", "-o", out],
    # services non web (bases de données, SSH, SMB…) : modèles réseau de nuclei sur hôte:port
    "nuclei_net":    lambda t, out, sev: ["nuclei", "-u", t, "-pt", "tcp,javascript,ssl",
                                          "-severity", sev or "medium,high,critical",
                                          "-ni", "-duc", "-jsonl", "-o", out],
    # pages découvertes par l'exploration : seulement les tests adaptés aux technologies vues (-as)
    "nuclei_deep":   lambda t, out, sev: ["nuclei", "-u", t, "-as", "-severity", sev or "medium,high,critical",
                                          "-ni", "-duc", "-jsonl", "-o", out],
    # exploration (lecture seule) : découvre pages et API à tester ; JavaScript analysé (-jc)
    "katana":        lambda t, out, depth: ["katana", "-u", t, "-d", depth or "2", "-jc", "-silent",
                                            "-ef", "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,map",
                                            "-ct", "120s", "-rl", "50", "-o", out],
    # re-test ciblé d'UN seul test déjà détecté (vérification, pas d'attaque)
    "nuclei_verify": lambda t, out, tid: ["nuclei", "-u", t, "-id", tid, "-ni", "-duc",
                                          "-jsonl", "-o", out],
}
TOOL_OF = {"nuclei_verify": "nuclei", "nuclei_net": "nuclei", "nuclei_deep": "nuclei"}


class ToolRunner:
    def __init__(self, settings: dict, guard: ScopeGuard, run_dir: Path, audit: AuditLog):
        t = settings.get("tools", {})
        self.dry_run = bool(t.get("dry_run", True))
        self.timeout = int(t.get("timeout_s", 900))
        self.allowlist = set(t.get("allowlist", []))
        self.nuclei_severity = str(t.get("nuclei_severity", "medium,high,critical"))
        # non-destructivité : jamais de tests de déni de service, intrusifs (écriture, envoi de
        # fichiers) ou de fuzzing, même s'ils existent dans la base de nuclei
        self.nuclei_exclude_tags = str(t.get("nuclei_exclude_tags", "dos,intrusive,fuzz"))
        # rythme maximal (requêtes/s) : une cible fragile saturée (ex. Elasticsearch en 429)
        # répond mal et peut masquer des failles
        self.nuclei_rate_limit = t.get("nuclei_rate_limit")
        self.guard = guard
        self.audit = audit
        self.evidence = run_dir / "evidence"
        self.evidence.mkdir(parents=True, exist_ok=True)

    def run(self, template: str, target: str | list[str], extra: str = "") -> Path | None:
        tool = TOOL_OF.get(template, template)
        if tool not in self.allowlist:
            raise PermissionError(f"Outil non autorisé : {tool}")
        targets = list(target) if isinstance(target, (list, tuple)) else [target]
        for t in targets:
            self.guard.check(t)                        # garde-fou périmètre, cible par cible

        out = self.evidence / f"{template}_{int(time.time() * 1000)}.out"
        if template in ("nuclei", "nuclei_net", "nuclei_deep") and not extra:
            extra = self.nuclei_severity
        cmd = TEMPLATES[template](targets[0], str(out), extra)
        if len(targets) > 1:                           # un seul nuclei pour toutes les cibles :
            lst = out.with_suffix(".cibles.txt")       # il les teste en parallèle (bien plus rapide)
            lst.write_text("\n".join(targets) + "\n", encoding="utf-8")
            i = cmd.index("-u")
            cmd[i:i + 2] = ["-list" if tool == "katana" else "-l", str(lst)]
        if tool == "nuclei" and self.nuclei_exclude_tags:
            cmd += ["-etags", self.nuclei_exclude_tags]
        if tool == "nuclei" and self.nuclei_rate_limit:
            cmd += ["-rl", str(int(self.nuclei_rate_limit))]
        if tool == "nmap" and self.guard.excluded:         # une plage peut contenir un hôte exclu
            cmd[-1:-1] = ["--exclude", ",".join(sorted(self.guard.excluded))]
        self.audit.event("tool", template=template, dry_run=self.dry_run)

        if self.dry_run:
            print("  [dry-run] " + " ".join(cmd))
            return None
        if shutil.which(tool) is None:
            raise FileNotFoundError(f"{tool} n'est pas installé")
        try:
            proc = subprocess.run(cmd, timeout=self.timeout, check=False, capture_output=True,
                                  text=True, encoding="utf-8", errors="replace")
            code, log = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired as exc:
            code, log = "délai dépassé", f"{exc}"
        # journal complet de l'outil, rangé avec les preuves (diagnostic)
        out.with_suffix(".log").write_text(" ".join(cmd) + "\n\n" + log, encoding="utf-8")
        produced = out.exists() and out.stat().st_size > 0
        self.audit.event("tool_result", template=template, returncode=code, output=produced)
        if code != 0:
            last = next((l for l in reversed(log.strip().splitlines()) if l.strip()), "")
            print(f"  ⚠ {template} a échoué (code {code}) : {last[:200]}")
        return out if produced else None
