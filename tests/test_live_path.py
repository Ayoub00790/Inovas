# -*- coding: utf-8 -*-
"""Le VRAI chemin d'appel (LiteLLM) testé contre un faux serveur d'API compatible OpenAI.

On vérifie, sans clé ni Internet :
  - que le mode « live » appelle bien le serveur et lit la réponse ;
  - que les tokens réels renvoyés par le fournisseur sont enregistrés ;
  - et surtout que le serveur « cloud » n'a reçu AUCUNE valeur réelle.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytest.importorskip("litellm")

from inova.core.budget import Budget, BudgetExceeded  # noqa: E402
from inova.core.models import SafePrompt  # noqa: E402
from inova.llm.client import LLMClient  # noqa: E402

RECEIVED: list[dict] = []


class FakeOpenAI(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        RECEIVED.append(body)
        user = body["messages"][-1]["content"]
        reply = {"id": "fake-1", "object": "chat.completion", "created": 0, "model": body["model"],
                 "choices": [{"index": 0, "finish_reason": "stop",
                              "message": {"role": "assistant", "content": "Analyse : corriger " +
                                          " ".join(t for t in user.split() if t.startswith("["))}}],
                 "usage": {"prompt_tokens": 111, "completion_tokens": 22, "total_tokens": 133}}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def fake_cloud(monkeypatch_module=None):
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenAI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


def live_settings(settings, api_base, **budget):
    s = json.loads(json.dumps(settings))
    s["llm"].update(cloud_mode="live", cloud_model="openai/gpt-test", cloud_api_base=api_base)
    s["pricing"] = {"cloud_input_per_million": 2.0, "cloud_output_per_million": 8.0}
    s["budget"] = {"max_cloud_calls": 20, "max_total_tokens": 200000, "max_mission_minutes": 60, **budget}
    return s


def test_appel_reel_masque_et_mesure(settings, passerelle, fake_cloud, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "cle-de-test")
    llm = LLMClient(live_settings(settings, fake_cloud))
    real = "Faille sur https://demo.inova-lab.local/admin (10.10.0.20), password=Adm1n2026"
    safe, _ = passerelle.to_safe_prompt(real)
    RECEIVED.clear()
    answer = passerelle.restore(llm.cloud(safe, "system", phase="test"))

    sent = json.dumps(RECEIVED, ensure_ascii=False)
    for secret in ("demo.inova-lab.local", "10.10.0.20", "Adm1n2026"):
        assert secret not in sent, f"le serveur cloud a reçu {secret}"
    assert "https://demo.inova-lab.local/admin" in answer          # réinjection locale
    call = llm.calls[-1]
    assert (call["prompt_tokens"], call["completion_tokens"], call["estimated"]) == (111, 22, False)
    assert call["cost_usd"] == pytest.approx((111 * 2 + 22 * 8) / 1e6)


def test_plafond_d_appels(settings, passerelle, fake_cloud, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "cle-de-test")
    s = live_settings(settings, fake_cloud, max_cloud_calls=1)
    llm = LLMClient(s, budget=Budget(s))
    safe, _ = passerelle.to_safe_prompt("Faille sur 10.10.0.21")
    llm.cloud(safe, "system")
    with pytest.raises(BudgetExceeded):
        llm.cloud(SafePrompt(safe.text, passerelle), "system")


def test_parametre_refuse_ignore(settings, passerelle, monkeypatch):
    """Un modèle qui impose ses paramètres (ex. temperature=1) ne doit pas faire échouer l'appel."""
    import litellm
    seen = {}

    class Resp:
        class _C:
            class message:
                content = "OK"
        choices = [_C]
        usage = None

    def fake_completion(**kw):
        seen.update(kw, drop=litellm.drop_params)
        return Resp

    monkeypatch.setattr(litellm, "completion", fake_completion)
    s = live_settings(settings, None)
    s["llm"].update(cloud_model="anthropic/claude-haiku-5-5", cloud_temperature=None)
    safe, _ = passerelle.to_safe_prompt("Faille sur 10.10.0.22")
    assert LLMClient(s).cloud(safe, "system") == "OK"
    assert seen["drop"] is True and "temperature" not in seen
