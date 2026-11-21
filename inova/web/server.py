# -*- coding: utf-8 -*-
"""Serveur HTTP local (bibliothèque standard de Python, aucune installation).

Sécurité : il n'écoute QUE sur 127.0.0.1 — l'interface affiche des valeurs
réelles et la table de correspondance, elle ne doit pas être joignable depuis
le réseau.
"""
from __future__ import annotations

import json
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .api import InovaAPI

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 1_000_000


def make_handler(api: InovaAPI):
    routes = {"/api/route": api.route, "/api/mask": api.mask,
              "/api/run": api.run, "/api/reset": lambda _p: api.reset_vault()}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, data) -> None:
            self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif self.path == "/api/info":
                self._json(200, api.info())
            else:
                self._json(404, {"error": "introuvable"})

        def do_POST(self):
            fn = routes.get(self.path)
            if fn is None:
                return self._json(404, {"error": "introuvable"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "requête trop grande"})
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
                self._json(200, fn(payload))
            except Exception as exc:  # message lisible dans l'interface
                traceback.print_exc()
                self._json(500, {"error": f"{type(exc).__name__} : {exc}"})

        def log_message(self, fmt, *args):  # journal console sobre
            if self.path.startswith("/api/"):
                print(f"  {self.command} {self.path}")

    return Handler


def serve(port: int = 8000, open_browser: bool = True) -> None:
    api = InovaAPI()
    # pré-charge Presidio en arrière-plan : le 1er masquage sera instantané
    threading.Thread(target=api.passerelle, daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(api))
    url = f"http://127.0.0.1:{port}"
    print(f"\n  INOVA — interface locale : {url}\n  (Ctrl+C pour arrêter)\n")
    if open_browser:
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Interface arrêtée.")
    finally:
        httpd.server_close()
