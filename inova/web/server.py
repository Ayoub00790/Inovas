# -*- coding: utf-8 -*-
"""Serveur HTTP local (bibliothèque standard de Python, aucune installation).

Sécurité : il n'écoute QUE sur 127.0.0.1 — l'interface affiche des valeurs
réelles et la table de correspondance, elle ne doit pas être joignable depuis
le réseau. Les requêtes venant d'une autre origine sont refusées.
"""
from __future__ import annotations

import json
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .api import InovaAPI

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 1_000_000
FONTS = {"/fonts/source-sans-3.woff2": "source-sans-3.woff2",
         "/fonts/source-serif-4.woff2": "source-serif-4.woff2"}


def make_handler(api: InovaAPI, port: int):
    posts = {"/api/route": api.route, "/api/mask": api.mask, "/api/reset": api.reset_vault,
             "/api/run": api.run, "/api/scope": api.save_scope, "/api/eval": api.evaluate,
             "/api/mission/start": api.mission_start, "/api/mission/decide": api.mission_decide}
    gets = {"/api/info": api.info, "/api/scope": api.get_scope, "/api/history": api.history,
            "/api/mission/status": api.mission_status, "/api/eval/models": api.eval_models}
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, data) -> None:
            self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _guarded(self, fn, *args):
            try:
                self._json(200, fn(*args))
            except (ValueError, FileNotFoundError, RuntimeError) as exc:
                self._json(400, {"error": str(exc)})
            except Exception as exc:  # message lisible dans l'interface
                traceback.print_exc()
                self._json(500, {"error": f"{type(exc).__name__} : {exc}"})

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif path in FONTS:                       # polices locales (aucun appel à Internet)
                self._send(200, (STATIC / "fonts" / FONTS[path]).read_bytes(), "font/woff2")
            elif path in gets:
                self._guarded(gets[path])
            elif path.startswith("/api/history/"):
                self._guarded(api.history_item, unquote(path[len("/api/history/"):]))
            else:
                self._json(404, {"error": "introuvable"})

        def do_POST(self):
            # protection contre les requêtes forgées par un autre site (CSRF)
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                return self._json(403, {"error": "origine refusée"})
            fn = posts.get(self.path)
            if fn is None:
                return self._json(404, {"error": "introuvable"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "requête trop grande"})
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._json(400, {"error": "JSON invalide"})
            self._guarded(fn, payload)

        def log_message(self, fmt, *args):  # journal console sobre
            if self.path.startswith("/api/") and "/status" not in self.path:
                print(f"  {self.command} {self.path}")

    return Handler


def serve(port: int = 8000, open_browser: bool = True) -> None:
    api = InovaAPI()
    # pré-charge Presidio en arrière-plan : le 1er masquage sera instantané
    threading.Thread(target=api.passerelle, daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(api, port))
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
