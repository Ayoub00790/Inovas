# -*- coding: utf-8 -*-
"""Table de correspondance jeton <-> valeur réelle.

- Reste 100 % LOCALE, chiffrée sur disque (Fernet / AES).
- Une par mission (engagement) : les jetons ne se mélangent pas entre clients.
- Cohérente : une même valeur reçoit toujours le même jeton ;
  deux valeurs différentes reçoivent deux jetons différents.
- Jamais affichée ni journalisée (__repr__ volontairement muet).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from cryptography.fernet import Fernet

TOKEN_RE = re.compile(r"\[([A-Z_]+_\d+)\]")


class Vault:
    def __init__(self, vault_dir: str | Path, engagement_id: str):
        self.dir = Path(vault_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.path = self.dir / f"{engagement_id}.vault"
        self._fernet = Fernet(self._load_key())
        self._forward: dict[str, str] = {}   # valeur réelle -> jeton
        self._reverse: dict[str, str] = {}   # jeton -> valeur réelle
        self._counters: dict[str, int] = {}
        self._load()

    # ---------- clé de chiffrement ----------
    def _load_key(self) -> bytes:
        env = os.environ.get("INOVA_VAULT_KEY")
        if env:
            return env.encode()
        key_file = self.dir / ".key"
        if not key_file.exists():
            key_file.write_bytes(Fernet.generate_key())
            os.chmod(key_file, 0o600)
        return key_file.read_bytes()

    # ---------- persistance chiffrée ----------
    def _load(self) -> None:
        if self.path.exists():
            data = json.loads(self._fernet.decrypt(self.path.read_bytes()))
            self._forward = data["forward"]
            self._counters = data["counters"]
            self._reverse = {t: v for v, t in self._forward.items()}

    def save(self) -> None:
        blob = json.dumps({"forward": self._forward, "counters": self._counters}).encode()
        self.path.write_bytes(self._fernet.encrypt(blob))
        os.chmod(self.path, 0o600)

    # ---------- jetons ----------
    def token_for(self, entity: str, value: str) -> str:
        key = value.strip()
        if key in self._forward:
            return self._forward[key]
        self._counters[entity] = self._counters.get(entity, 0) + 1
        token = f"[{entity}_{self._counters[entity]}]"
        self._forward[key] = token
        self._reverse[token] = key
        return token

    def restore(self, text: str) -> str:
        """Réinjecte les vraies valeurs (jetons inconnus laissés tels quels)."""
        return TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    def lookup(self, token: str) -> str | None:
        """Valeur réelle d'un jeton (usage LOCAL uniquement : interface sur 127.0.0.1)."""
        return self._reverse.get(token)

    def __len__(self) -> int:
        return len(self._forward)

    def __repr__(self) -> str:   # ne jamais exposer le contenu
        return f"<Vault entries={len(self)}>"
