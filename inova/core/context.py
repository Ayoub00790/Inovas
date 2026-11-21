# -*- coding: utf-8 -*-
"""État partagé d'une mission, transmis de phase en phase."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .audit import AuditLog
from .models import Finding, PentestProfile, RouteDecision, Service


@dataclass
class Context:
    settings: dict
    scope: dict
    run_dir: Path
    audit: AuditLog
    demo: bool = False
    auto_approve: bool = False
    fixtures_dir: Path = Path("tests/fixtures")
    # points d'accroche (interface web) : validation humaine et progression
    approver: Optional[Callable[[str, str], bool]] = None
    on_phase: Optional[Callable[[int, str], None]] = None
    # remplis au fil des phases
    profile: Optional[PentestProfile] = None
    decision: Optional[RouteDecision] = None
    guard: Any = None
    runner: Any = None
    reasoner: Any = None
    llm: Any = None
    budget: Any = None
    passerelle: Any = None
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    recon_summary: str = ""
    executive_summary: str = ""
    outbox_check: dict = field(default_factory=dict)
    started_at: str = ""
