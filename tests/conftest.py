# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""Shared fixtures. All data is synthetic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from remit.evidence.ledger import Ledger
from remit.evidence.model import Capability, Evidence, EvidenceClass, Level, Source, Subject, hash_artefact
from remit.evidence.requirements import load_rules

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
RULES = load_rules()
E = EvidenceClass
AGENT = Subject("test-agent", "1.0.0")

STRENGTH = {
    EvidenceClass.EVAL_RESULT: {"suite": "synthetic-suite", "pass_rate": 0.95, "samples": 500},
    EvidenceClass.RED_TEAM_REPORT: {
        "exercise": "synthetic-exercise",
        "scope_tested": "synthetic",
        "findings_open": 0,
        "residual_risk": "low",
    },
    EvidenceClass.CONTAINMENT_TEST: {
        "boundaries_tested": ["filesystem", "network_egress", "credential_access", "process_escape"],
        "escape_attempts": 20,
        "escape_attempts_blocked": 20,
    },
    EvidenceClass.MONITOR_HEALTH: {
        "monitor_name": "sandbox-monitor",
        "state": "healthy",
        "last_heartbeat": (NOW - timedelta(seconds=30)).isoformat(),
        "effectiveness": 0.9,
    },
    EvidenceClass.HUMAN_ATTESTATION: {
        "person": "Synthetic Person",
        "role": "Head of Engineering",
        "attests_to": "unsupervised operation",
    },
    EvidenceClass.STANDARDS_EVIDENCE: {"standard": "Synthetic Standard", "clause": "4.2", "tier": "2"},
}


def make_evidence(
    cls: EvidenceClass = EvidenceClass.EVAL_RESULT,
    *,
    scope=tuple(Capability),
    subject: Subject = AGENT,
    strength: dict | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None | str = "default",
    content_hash: str | None | object = "default",
    authorised: bool = True,
    role: str = "developer",
    **overrides,
) -> Evidence:
    issued = issued_at or NOW - timedelta(days=1)
    if expires_at == "default":
        expires_at = issued + timedelta(days=60)
    if content_hash == "default":
        content_hash = hash_artefact(b"synthetic artefact")
    merged = dict(STRENGTH[cls])
    merged.update(strength or {})
    return Evidence(
        evidence_class=cls,
        subject=subject,
        scope=frozenset(scope),
        source=Source("synthetic-source", frozenset({cls}) if authorised else frozenset(), role),
        strength={k: v for k, v in merged.items() if v is not None},
        issued_at=issued,
        expires_at=expires_at,
        content_hash=content_hash,
        **overrides,
    )


def pinned(cap, cls, field):
    """The first suite or exercise the rules accept for ``cap``."""
    for req, _ in RULES[cap].effective(Level.FULL):
        if cls in req.classes and field in req.includes:
            return req.includes[field][0]
    return f"no-{field}-for-{cap.value}"


def eval_ev(cap, strength=None, **kwargs):
    kwargs.setdefault("scope", [cap])
    merged = {"suite": pinned(cap, E.EVAL_RESULT, "suite"), **(strength or {})}
    return make_evidence(E.EVAL_RESULT, strength=merged, **kwargs)


def redteam_ev(cap, strength=None, **kwargs):
    kwargs.setdefault("scope", [cap])
    kwargs.setdefault("role", "external")
    merged = {"exercise": pinned(cap, E.RED_TEAM_REPORT, "exercise"), **(strength or {})}
    return make_evidence(E.RED_TEAM_REPORT, strength=merged, **kwargs)


def satisfying(req, cap, subject=AGENT):
    """Evidence that meets ``req`` for ``cap`` at any level, built from the rules."""
    if req.monitor is not None:
        # Exactly at the monitor's effectiveness threshold, which must pass.
        strength = {"monitor_name": req.monitor.name, "effectiveness": req.monitor.min_effectiveness}
        return make_evidence(E.MONITOR_HEALTH, scope=[cap], strength=strength, subject=subject)
    cls = req.classes[0]
    strength = {k: v[0] for k, v in req.includes.items() if k in ("suite", "exercise")}
    return make_evidence(cls, scope=[cap], strength=strength, role="external", subject=subject)


def full_set(cap, subject=AGENT):
    """Evidence meeting every requirement of ``cap`` at full, one record per requirement."""
    return [satisfying(req, cap, subject) for req, _ in RULES[cap].effective(Level.FULL)]


@pytest.fixture
def ledger():
    with Ledger(":memory:") as led:
        yield led
