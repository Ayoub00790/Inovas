# -*- coding: utf-8 -*-
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def settings():
    return yaml.safe_load((ROOT / "config/settings.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def scope():
    return yaml.safe_load((ROOT / "config/scope.example.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def passerelle(settings, scope, tmp_path_factory):
    from inova.gateway.passerelle import Passerelle
    from inova.gateway.vault import Vault
    vault = Vault(tmp_path_factory.mktemp("vault"), "TEST")
    return Passerelle(settings, scope, vault, "fr")


@pytest.fixture(scope="session")
def leak_cases():
    return json.loads((ROOT / "tests/fixtures/leak_cases.json").read_text(encoding="utf-8"))
