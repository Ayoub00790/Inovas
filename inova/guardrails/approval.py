# -*- coding: utf-8 -*-
"""Garde-fou n°2 : l'IA propose, l'humain décide.

Toute action active (vérification d'une faille) demande une validation
explicite. Sans terminal interactif, la réponse par défaut est NON.
"""
from __future__ import annotations

import sys


def ask_approval(action: str, details: str = "", auto: str | None = None) -> bool:
    """auto = "approve" n'est accepté qu'en mode démo (voir main.py)."""
    if auto == "approve":
        print(f"  [validation auto — démo] {action}")
        return True
    if auto == "deny" or not sys.stdin.isatty():
        print(f"  [refusé par défaut] {action}")
        return False
    print("\n" + "=" * 70)
    print(f"VALIDATION HUMAINE REQUISE : {action}")
    if details:
        print(details)
    answer = input("Autoriser cette action ? [o/N] ").strip().lower()
    return answer in ("o", "oui", "y", "yes")
