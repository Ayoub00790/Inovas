# -*- coding: utf-8 -*-
"""Fiabilité de la détection : doublons, contradictions, confirmation nmap, mesure rappel/précision."""
import datetime as dt
import threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer

from inova.core.models import Finding, Service
from inova.eval.detection import load_expected, measure
from inova.phases.coherence import assess


def _lab_findings():
    mk = lambda i, t, a, sev, tid, cve=None: Finding(id=i, title=t, asset=a, severity=sev,  # noqa: E731
                                                    template_id=tid, cve=cve)
    return [
        mk("F-001", "ElasticSearch - Remote Code Execution", "http://127.0.0.1:9200/_search", "high", "CVE-2015-1427", "CVE-2015-1427"),
        mk("F-002", "ThinkPHP < 3.2.4 - Remote Code Execution", "http://127.0.0.1:8084/index.php?s=captcha", "high", "thinkphp-2-rce"),
        mk("F-003", "Apache 2.4.49/2.4.50 - Path Traversal and Remote Code Execution",
           "http://127.0.0.1:8081/icons/.%%32%65/etc/passwd", "critical", "CVE-2021-42013", "CVE-2021-42013"),
        mk("F-004", "Apache 2.4.49 - Path Traversal and Remote Code Execution",
           "http://127.0.0.1:8081/icons/.%2e/etc/passwd", "high", "CVE-2021-41773", "CVE-2021-41773"),
        mk("F-005", "Apache Tomcat Manager Default Login", "http://127.0.0.1:8083/manager/html", "high", "tomcat-default-login"),
        mk("F-006", "ThinkPHP 5.0.23 - Remote Code Execution", "http://127.0.0.1:8084/index.php?s=captcha", "critical", "thinkphp-5023-rce"),
        mk("F-007", "Prometheus Metrics - Detect", "http://127.0.0.1:3000/metrics", "medium", "prometheus-metrics"),
        mk("F-008", "NPM package.json Disclosure", "http://127.0.0.1:8082/package.json", "low", "package-json"),
        mk("F-011", "Quelque chose d'inconnu", "http://127.0.0.1:8083/x", "low", "inconnu"),
    ]


def test_contradiction_doublons_et_confirmation_nmap():
    fs = _lab_findings()
    assess(fs, [Service(host="localhost", port=8081, protocol="tcp", name="http", product="Apache httpd",
                        version="2.4.49", address="127.0.0.1")])
    by = {f.id: f for f in fs}
    assert by["F-002"].confidence == "douteuse"               # ThinkPHP < 3.2.4 alors que 5.0.23 est reconnu
    assert by["F-002"].duplicate_of == "F-006"                 # et rattaché au vrai constat
    assert by["F-006"].duplicate_of is None
    assert by["F-004"].duplicate_of == "F-003"                 # deux encodages de la même traversée
    assert by["F-003"].confidence == "confirmée"               # 2.4.49 confirmée par nmap
    assert by["F-005"].confidence == "à confirmer" and not by["F-005"].confidence_notes


def test_nmap_contredit_une_version():
    f = Finding(id="F-1", title="Apache 2.4.49 - Path Traversal", asset="http://127.0.0.1:8082/x", severity="high")
    assess([f], [Service(host="h", port=8082, protocol="tcp", name="http", product="Apache httpd", version="2.4.25")])
    assert f.confidence == "douteuse" and "2.4.25" in f.confidence_notes[0]


def test_mesure_rappel_precision():
    fs = _lab_findings()
    assess(fs, [])
    res = measure([asdict(f) for f in fs], load_expected())
    found = {a["id"]: a["trouvee"] for a in res["attendues"]}
    assert found == {"JS-METRICS": True, "APACHE-TRAVERSAL": True, "PMA-LFI": False,
                     "TOMCAT-DEFAULT": True, "THINKPHP-RCE": True, "ES-RCE": True}
    assert round(res["rappel"], 2) == 0.83                     # 5 failles sur 6
    assert res["doublons_ecartes"] == 2                        # F-002 et F-004 ne comptent qu'une fois
    assert [u["id"] for u in res["a_qualifier"]] == ["F-011"]
    assert res["precision_basse"] < res["precision_haute"] == 1.0


class _Broken(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<h1>Error</h1> mysqli_real_connect(): (HY000/2002): Connection refused"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_application_en_erreur_detectee():
    from inova.phases.p3_vulnscan import health
    srv = HTTPServer(("127.0.0.1", 0), _Broken)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert "mysqli_real_connect" in health(f"http://127.0.0.1:{srv.server_port}/")
    finally:
        srv.shutdown()


def test_exploration_reste_sur_les_sites_du_perimetre(tmp_path):
    from inova.guardrails.scope import ScopeGuard
    from inova.phases.p3_vulnscan import crawl_targets
    today = dt.date.today().isoformat()
    g = ScopeGuard({"authorization": {"valid_from": today, "valid_until": today},
                    "targets": {"ip_ranges": ["127.0.0.1/32"]}})
    out = tmp_path / "katana.out"
    out.write_text("http://127.0.0.1:3000/rest/products/search?q=x\nhttp://127.0.0.1:3000/ftp/legal.md\n"
                   "http://127.0.0.1:3000/rest/user/login\nhttps://cdn.exemple.com/lib.js\n", encoding="utf-8")
    assert crawl_targets(["http://127.0.0.1:3000"], out, g, 25) == [
        "http://127.0.0.1:3000/rest/products/", "http://127.0.0.1:3000/ftp/", "http://127.0.0.1:3000/rest/user/"]


def test_services_reseau_et_exploration_dans_le_perimetre(tmp_path, capsys):
    from inova.core.audit import AuditLog
    from inova.guardrails.scope import ScopeGuard
    from inova.tools.runner import ToolRunner
    today = dt.date.today().isoformat()
    g = ScopeGuard({"authorization": {"valid_from": today, "valid_until": today},
                    "targets": {"ip_ranges": ["127.0.0.1/32"]}})
    assert g.is_in_scope("127.0.0.1:3306") and not g.is_in_scope("10.0.0.1:3306")
    r = ToolRunner({"tools": {"dry_run": True, "allowlist": ["nuclei", "katana"], "nuclei_rate_limit": 50}},
                   g, tmp_path, AuditLog(tmp_path))
    r.run("nuclei_net", ["127.0.0.1:3306", "127.0.0.1:445"])
    r.run("katana", ["http://127.0.0.1:3000", "http://127.0.0.1:8081"])
    out = capsys.readouterr().out
    assert "-pt tcp,javascript,ssl" in out and "-rl 50" in out and " -ni " in out
    assert "katana -list" in out and "-jc" in out
