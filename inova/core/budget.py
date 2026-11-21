# -*- coding: utf-8 -*-
"""Plafonds par mission : nombre d'appels cloud, tokens, durée.

Au-delà d'un plafond, le cloud n'est plus appelé : l'étape retombe en local
(même logique "fail-closed" que la passerelle). Évite une facture surprise
si une boucle s'emballe.
"""
from __future__ import annotations

import time


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self, settings: dict):
        b = settings.get("budget", {})
        self.max_cloud_calls = int(b.get("max_cloud_calls", 20))
        self.max_tokens = int(b.get("max_total_tokens", 200_000))
        self.max_seconds = float(b.get("max_mission_minutes", 60)) * 60
        self.started = time.monotonic()
        self.cloud_calls = 0
        self.tokens = 0

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def time_exceeded(self) -> bool:
        return self.elapsed() > self.max_seconds

    def check_cloud(self) -> None:
        if self.cloud_calls >= self.max_cloud_calls:
            raise BudgetExceeded(f"plafond de {self.max_cloud_calls} appels cloud atteint")
        if self.tokens >= self.max_tokens:
            raise BudgetExceeded(f"plafond de {self.max_tokens} tokens atteint")
        if self.time_exceeded():
            raise BudgetExceeded(f"durée maximale de mission ({self.max_seconds / 60:.0f} min) dépassée")

    def record(self, target: str, tokens: int) -> None:
        self.tokens += tokens
        if target == "cloud":
            self.cloud_calls += 1
