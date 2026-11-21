# -*- coding: utf-8 -*-
"""python -m inova.web [--port 8000] [--no-browser]"""
import argparse

from .server import serve

ap = argparse.ArgumentParser(prog="python -m inova.web")
ap.add_argument("--port", type=int, default=8000)
ap.add_argument("--no-browser", action="store_true", help="ne pas ouvrir le navigateur")
a = ap.parse_args()
serve(port=a.port, open_browser=not a.no_browser)
