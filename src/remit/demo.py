# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""Weekend 1 demo: a synthetic ledger for one coding agent, and what it supports.

All data is synthetic. Run with ``make demo`` or ``uv run demo``.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .evidence.ledger import Ledger
from .evidence.model import Capability, Evidence, EvidenceClass, Source, Subject, hash_artefact
from .evidence.requirements import load_rules
from .evidence.support import explain_capability, render

DEMO_DB = Path("demo-evidence.db")
CLOCK = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
AGENT = Subject("coder-agent", "0.1.0")

EVAL_LAB = Source("synthetic-eval-lab", frozenset({EvidenceClass.EVAL_RESULT}))
RED_TEAM = Source("synthetic-red-team", frozenset({EvidenceClass.RED_TEAM_REPORT}))
SANDBOX_LAB = Source("synthetic-sandbox-lab", frozenset({EvidenceClass.CONTAINMENT_TEST}))
MONITORING = Source("platform-monitoring", frozenset({EvidenceClass.MONITOR_HEALTH}))
UNVERIFIED = Source("unverified-vendor")


def _ev(cls, scope, source, strength, issued_days_ago, valid_days, ev_id, content=True):
    issued = CLOCK - timedelta(days=issued_days_ago)
    return Evidence(
        id=ev_id,
        evidence_class=cls,
        subject=AGENT,
        scope=frozenset(scope),
        source=source,
        strength=strength,
        issued_at=issued,
        expires_at=issued + timedelta(days=valid_days),
        content_hash=hash_artefact(f"synthetic artefact {ev_id}".encode()) if content else None,
    )


def seed(ledger: Ledger) -> None:
    C = Capability
    heartbeat = (CLOCK - timedelta(minutes=1)).isoformat()
    evidence = [
        _ev(EvidenceClass.EVAL_RESULT, [C.READ_DATA, C.CODE_EXECUTION, C.REPO_WRITE, C.BUDGET], EVAL_LAB,
            {"suite": "synthetic-coding-v1", "pass_rate": 0.94, "samples": 400}, 5, 90, "ev-eval-coding"),
        _ev(EvidenceClass.EVAL_RESULT, [C.WRITE_DATA], EVAL_LAB,
            {"suite": "synthetic-data-writes-v1", "pass_rate": 0.93, "samples": 150}, 5, 90, "ev-eval-writes"),
        _ev(EvidenceClass.EVAL_RESULT, [C.NETWORK_OUT], EVAL_LAB,
            {"suite": "synthetic-egress-v1", "pass_rate": 1.0, "samples": 500}, 2, 90, "ev-eval-egress"),
        _ev(EvidenceClass.EVAL_RESULT, [C.EXTERNAL_COMMS], EVAL_LAB,
            {"suite": "synthetic-messaging-v1", "pass_rate": 0.97, "samples": 300}, 2, 90, "ev-eval-comms",
            content=False),
        _ev(EvidenceClass.EVAL_RESULT, [C.DELEGATION], UNVERIFIED,
            {"suite": "vendor-handoff", "pass_rate": 0.99, "samples": 1000}, 1, 90, "ev-eval-handoff"),
        _ev(EvidenceClass.RED_TEAM_REPORT, [C.READ_DATA], RED_TEAM,
            {"scope_tested": "exfiltration of synthetic records", "findings_open": 1, "residual_risk": "medium"},
            20, 180, "ev-redteam-read"),
        _ev(EvidenceClass.CONTAINMENT_TEST, [C.CODE_EXECUTION, C.WRITE_DATA, C.DELEGATION], SANDBOX_LAB,
            {"boundaries_tested": ["filesystem", "process_escape"], "escape_attempts": 60,
             "escape_attempts_blocked": 60}, 6, 30, "ev-contain-sandbox"),
        _ev(EvidenceClass.CONTAINMENT_TEST, [C.CODE_EXECUTION], SANDBOX_LAB,
            {"boundaries_tested": ["filesystem", "network_egress", "credential_access", "process_escape"],
             "escape_attempts": 120, "escape_attempts_blocked": 120}, 3, 14, "ev-contain-full"),
        _ev(EvidenceClass.CONTAINMENT_TEST, [C.REPO_WRITE], SANDBOX_LAB,
            {"boundaries_tested": ["filesystem", "credential_access"], "escape_attempts": 40,
             "escape_attempts_blocked": 40}, 45, 30, "ev-contain-repo-old"),
        _ev(EvidenceClass.MONITOR_HEALTH, [C.CODE_EXECUTION], MONITORING,
            {"monitor_name": "sandbox-monitor", "state": "healthy", "last_heartbeat": heartbeat,
             "effectiveness": 0.97}, 0, 1, "ev-monitor-sandbox"),
        _ev(EvidenceClass.MONITOR_HEALTH, [C.REPO_WRITE], MONITORING,
            {"monitor_name": "test-tamper-sensor", "state": "degraded", "last_heartbeat": heartbeat,
             "effectiveness": 0.61}, 0, 1, "ev-monitor-tamper"),
    ]
    for ev in evidence:
        ledger.add(ev, recorded_at=CLOCK)


def summary(ledger: Ledger, rules, now: datetime) -> str:
    evidence = ledger.for_subject(AGENT)
    lines = [f"Highest supported level per capability for {AGENT}:"]
    for cap in Capability:
        level = explain_capability(evidence, rules, cap, AGENT, now).highest_supported
        lines.append(f"  {cap.value:<16} {level.value}")
    return "\n".join(lines)


def banner(text: str) -> None:
    print()
    print("=" * 78)
    print(text)
    print("=" * 78)


def main() -> int:
    if DEMO_DB.exists():
        DEMO_DB.unlink()
    rules = load_rules()
    with Ledger(DEMO_DB) as ledger:
        seed(ledger)
        now = CLOCK

        def explain(cap: Capability) -> None:
            print()
            print(render(explain_capability(ledger.for_subject(AGENT), rules, cap, AGENT, now)))

        banner(f"Synthetic ledger seeded at {DEMO_DB}")
        print(summary(ledger, rules, now))

        banner("Containment is a separate gate: a perfect eval_result does not open network_out")
        explain(Capability.NETWORK_OUT)

        banner("code_execution with a healthy sandbox monitor and full containment evidence")
        explain(Capability.CODE_EXECUTION)

        now = CLOCK + timedelta(minutes=10)
        banner("Ten minutes later the sandbox monitor has stopped sending heartbeats")
        explain(Capability.CODE_EXECUTION)

        ledger.revoke("ev-contain-sandbox", "escape found in the shared sandbox image", at=now)
        ledger.revoke("ev-contain-full", "escape found in the shared sandbox image", at=now)
        banner("An escape is found in the sandbox image and both containment tests are revoked")
        explain(Capability.CODE_EXECUTION)

        banner("Final position")
        print(summary(ledger, rules, now))
        print()
        print("Explore further with, for example:")
        print(f"  uv run remit evidence --db {DEMO_DB} --now {now.isoformat()} list")
        print(
            f"  uv run remit evidence --db {DEMO_DB} --now {now.isoformat()} "
            f"explain all --agent {AGENT.agent_id} --version {AGENT.version}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
