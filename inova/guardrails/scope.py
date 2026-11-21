# -*- coding: utf-8 -*-
"""Garde-fou n°1 : aucune action hors du périmètre signé par le client."""
from __future__ import annotations

import datetime as dt
import ipaddress
from urllib.parse import urlparse


class OutOfScopeError(PermissionError):
    pass


class ScopeGuard:
    def __init__(self, scope: dict):
        t = scope.get("targets", {})
        self.domains = [d.lower() for d in t.get("domains", [])]
        self.networks = [ipaddress.ip_network(r, strict=False) for r in t.get("ip_ranges", [])]
        self.excluded = {e.lower() for e in scope.get("excluded", [])}
        auth = scope.get("authorization", {})
        self.valid_from = dt.date.fromisoformat(str(auth.get("valid_from", "1970-01-01")))
        self.valid_until = dt.date.fromisoformat(str(auth.get("valid_until", "1970-01-01")))

    def authorization_valid(self, today: dt.date | None = None) -> bool:
        today = today or dt.date.today()
        return self.valid_from <= today <= self.valid_until

    @staticmethod
    def _host(target: str) -> str:
        return (urlparse(target).hostname if "://" in target else target.split("/")[0]).lower()

    def is_in_scope(self, target: str) -> bool:
        if "://" not in target and "/" in target:          # plage CIDR : entièrement incluse ?
            try:
                net = ipaddress.ip_network(target, strict=False)
                return any(net.version == n.version and net.subnet_of(n) for n in self.networks)
            except ValueError:
                pass
        host = self._host(target)
        if host in self.excluded:
            return False
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in n for n in self.networks)
        except ValueError:
            return any(host == d or host.endswith("." + d) for d in self.domains)

    def check(self, target: str) -> None:
        if not self.authorization_valid():
            raise OutOfScopeError("Autorisation expirée ou pas encore valide.")
        if not self.is_in_scope(target):
            raise OutOfScopeError(f"Cible hors périmètre : {self._host(target)}")
