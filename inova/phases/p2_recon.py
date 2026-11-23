# -*- coding: utf-8 -*-
"""Phase 2 — Reconnaissance : services, ports, versions (outils + IA légère LOCALE)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..core.context import Context
from ..core.models import Service
from ..guardrails.injection import wrap_untrusted


def parse_nmap_xml(path: Path) -> list[Service]:
    services = []
    root = ET.parse(path).getroot()
    for host in root.iter("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        name_el = host.find("hostnames/hostname")
        host_id = name_el.get("name") if name_el is not None else (
            addr_el.get("addr") if addr_el is not None else "?")
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            services.append(Service(
                host=host_id, port=int(port.get("portid")), protocol=port.get("protocol", "tcp"),
                name=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                address=addr_el.get("addr") if addr_el is not None else ""))
    return services


def run(ctx: Context) -> None:
    t = ctx.scope.get("targets", {})
    targets = t.get("domains", []) + t.get("ip_ranges", [])

    if ctx.demo:
        ctx.services = parse_nmap_xml(ctx.fixtures_dir / "sample_nmap.xml")
    else:
        for target in targets:
            out = ctx.runner.run("nmap", target)
            if out:
                ctx.services += parse_nmap_xml(out)

    for s in ctx.services:
        print(f"   {s.host}:{s.port}/{s.protocol}  {s.name}  {s.product} {s.version}".rstrip())

    # IA légère, toujours LOCALE : résumer la surface d'attaque.
    # Les bannières de service sont écrites par la cible -> données non fiables.
    listing = "\n".join(f"{s.host}:{s.port} {s.name} {s.product} {s.version}" for s in ctx.services)
    ctx.recon_summary = ctx.reasoner.think(
        phase="reconnaissance",
        task="Résume la surface d'attaque et signale les services à examiner en priorité.",
        context=wrap_untrusted("nmap", listing), allow_cloud=False)
