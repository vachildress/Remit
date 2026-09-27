# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""remit demo: evidence, grants and enforcement for a synthetic coding agent.

Act 1 (weekend 1) shows what the evidence supports. Act 2 (weekend 2) turns
it into grants and puts them in front of tool calls through an enforcement
point: Microsoft's Agent Governance Toolkit when installed, otherwise the
stub. All data is synthetic. Run with ``make demo`` or ``uv run demo``.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .enforcement import load_tool_table, make_pep
from .evidence.ledger import Ledger
from .evidence.model import Capability, Evidence, EvidenceClass, Source, Subject, hash_artefact
from .evidence.requirements import load_rules
from .evidence.support import explain_capability, render
from .policy.history import GrantStore, refresh

DEMO_DB = Path("demo-evidence.db")
CLOCK = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
AGENT = Subject("coder-agent", "0.1.0")
AGENT_V2 = Subject("coder-agent", "0.2.0")

C = Capability
E = EvidenceClass
EVAL_LAB = Source("synthetic-eval-lab", frozenset({E.EVAL_RESULT}), "internal_independent")
RED_TEAM = Source("synthetic-red-team", frozenset({E.RED_TEAM_REPORT}), "external")
SANDBOX_LAB = Source("synthetic-sandbox-lab", frozenset({E.CONTAINMENT_TEST}), "internal_independent")
DEV_TEAM = Source("coder-agent-dev-team", frozenset({E.CONTAINMENT_TEST}), "developer")
MONITORING = Source("platform-monitoring", frozenset({E.MONITOR_HEALTH}), "internal_independent")
ENG_LEAD = Source("synthetic-engineering-lead", frozenset({E.HUMAN_ATTESTATION}), "internal_independent")
RISK_OFFICE = Source("synthetic-model-risk-office", frozenset({E.STANDARDS_EVIDENCE}), "internal_independent")
ALL_BOUNDARIES = ["filesystem", "network_egress", "credential_access", "process_escape"]


def ev(ev_id, cls, subject, scope, source, strength, issued, valid):
    return Evidence(
        id=ev_id,
        evidence_class=cls,
        subject=subject,
        scope=frozenset(scope),
        source=source,
        strength=strength,
        issued_at=issued,
        expires_at=issued + valid,
        content_hash=hash_artefact(f"synthetic artefact {ev_id}".encode()),
    )


def heartbeat(name, subject, scope, at, ev_id, state="healthy", effectiveness=0.97):
    return ev(
        ev_id, E.MONITOR_HEALTH, subject, scope, MONITORING,
        {"monitor_name": name, "state": state, "last_heartbeat": at.isoformat(), "effectiveness": effectiveness},
        at, timedelta(days=1),
    )


def attestation(ev_id, subject, cap, level, issued, attests_to):
    return ev(
        ev_id, E.HUMAN_ATTESTATION, subject, [cap], ENG_LEAD,
        {"person": "Synthetic Engineering Lead", "role": "Head of Engineering",
         "attests_to": attests_to, "grants_level": level},
        issued, timedelta(days=90),
    )


def seed_act1(ledger: Ledger, t: datetime) -> None:
    days = lambda n: timedelta(days=n)  # noqa: E731
    for e in [
        ev("ev-eval-coding", E.EVAL_RESULT, AGENT, [C.CODE_EXECUTION, C.REPO_WRITE], EVAL_LAB,
           {"suite": "synthetic-coding-v1", "pass_rate": 0.94, "samples": 400}, t - days(5), days(90)),
        ev("ev-eval-egress", E.EVAL_RESULT, AGENT, [C.NETWORK_OUT], EVAL_LAB,
           {"suite": "synthetic-egress-v1", "pass_rate": 1.0, "samples": 500}, t - days(2), days(90)),
        ev("ev-contain-sandbox", E.CONTAINMENT_TEST, AGENT, [C.CODE_EXECUTION], SANDBOX_LAB,
           {"boundaries_tested": ALL_BOUNDARIES, "escape_attempts": 120, "escape_attempts_blocked": 120},
           t - days(3), days(14)),
        ev("ev-redteam-escape", E.RED_TEAM_REPORT, AGENT, [C.CODE_EXECUTION], RED_TEAM,
           {"exercise": "synthetic-sandbox-escape-exercise-v1", "scope_tested": "sandbox escape",
            "findings_open": 0, "residual_risk": "low"}, t - days(10), days(180)),
        attestation("ev-attest-exec", AGENT, C.CODE_EXECUTION, "full", t - days(1), "unrestricted code execution"),
        heartbeat("sandbox-monitor", AGENT, [C.CODE_EXECUTION], t - timedelta(seconds=30), "ev-monitor-sandbox"),
    ]:
        ledger.add(e, recorded_at=t)


def seed_act2(ledger: Ledger, t: datetime) -> None:
    days = lambda n: timedelta(days=n)  # noqa: E731
    for e in [
        ev("ev2-eval-coding", E.EVAL_RESULT, AGENT_V2, [C.CODE_EXECUTION, C.REPO_WRITE], EVAL_LAB,
           {"suite": "synthetic-coding-v1", "pass_rate": 0.95, "samples": 400}, t - days(5), days(90)),
        # A short-lived sandbox certificate: valid for three hours from issue.
        ev("ev2-sandbox-cert", E.CONTAINMENT_TEST, AGENT_V2, [C.CODE_EXECUTION], SANDBOX_LAB,
           {"boundaries_tested": ALL_BOUNDARIES, "escape_attempts": 120, "escape_attempts_blocked": 120},
           t - timedelta(hours=1), timedelta(hours=3)),
        ev("ev2-redteam-escape", E.RED_TEAM_REPORT, AGENT_V2, [C.CODE_EXECUTION], RED_TEAM,
           {"exercise": "synthetic-sandbox-escape-exercise-v1", "scope_tested": "sandbox escape",
            "findings_open": 0, "residual_risk": "low"}, t - days(3), days(180)),
        heartbeat("sandbox-monitor", AGENT_V2, [C.CODE_EXECUTION], t - timedelta(seconds=30), "ev2-monitor-sandbox"),
        heartbeat("test-tamper-sensor", AGENT_V2, [C.REPO_WRITE], t - timedelta(seconds=30), "ev2-monitor-tamper"),
        attestation("ev2-attest-exec", AGENT_V2, C.CODE_EXECUTION, "full", t - timedelta(minutes=10),
                    "unrestricted code execution for coder-agent 0.2.0"),
        ev("ev2-tier", E.STANDARDS_EVIDENCE, AGENT_V2, list(C), RISK_OFFICE,
           {"standard": "Synthetic model risk policy", "clause": "tiering", "tier": "2"},
           t - days(30), days(365)),
    ]:
        ledger.add(e, recorded_at=t)


def banner(text: str) -> None:
    print()
    print("=" * 78)
    print(text)
    print("=" * 78)


def main() -> int:
    if DEMO_DB.exists():
        DEMO_DB.unlink()
    # The JSON mirrors, so the demo never depends on the YAML parser.
    rules = load_rules(fmt="json")
    tools = load_tool_table(fmt="json")
    with Ledger(DEMO_DB) as ledger:
        # ------------------------------------------------------------------
        # Act 1: what the evidence supports
        # ------------------------------------------------------------------
        seed_act1(ledger, CLOCK)

        def explain(cap: Capability, now: datetime) -> None:
            print()
            print(render(explain_capability(ledger.for_subject(AGENT), rules, cap, AGENT, now)))

        banner("Act 1. Containment is a separate gate: a perfect eval_result does not open network_out")
        explain(C.NETWORK_OUT, CLOCK)

        banner("Act 1. code_execution with a healthy sandbox monitor")
        explain(C.CODE_EXECUTION, CLOCK)

        banner("Act 1. Ten minutes later the sandbox monitor has stopped sending heartbeats")
        explain(C.CODE_EXECUTION, CLOCK + timedelta(minutes=10))

        # ------------------------------------------------------------------
        # Act 2: grants and enforcement
        # ------------------------------------------------------------------
        t0 = CLOCK + timedelta(days=1)
        seed_act2(ledger, t0)
        pep = make_pep(ledger, rules, tools)

        def check(tool: str, now: datetime) -> None:
            d = pep.check(AGENT_V2, tool, now)
            print(f"\n  {d.outcome.upper():<5}  {tool}   (enforced by {d.enforced_by})")
            print(f"         {d.explanation}")
            if d.escalation_id:
                print(f"         Parked in the approval queue as escalation {d.escalation_id}.")

        banner(f"Act 2. Grants for {AGENT_V2}, enforced through the '{pep.name}' enforcement point")
        envelope = refresh(ledger, rules, AGENT_V2, t0)
        print(f"\nCeiling: {envelope.ceiling.describe()}\n")
        for cap in C:
            g = envelope[cap]
            note = f"   evidence supports {g.supported.value}, capped by the tier" if g.ceiling.rank < g.supported.rank else ""
            print(f"  {cap.value:<16} {g.level.value:<8}{note}")
        print(f"\n  {envelope[C.CODE_EXECUTION].explanation}")

        banner("Act 2. Three tool calls at the same moment")
        check("tests.run", t0)
        check("git.push_branch", t0)
        check("git.merge_main", t0)

        banner("Act 2. The sandbox lab certifies the repository checkout: deny becomes hold")
        t1 = t0 + timedelta(minutes=1)
        ledger.add(
            ev("ev2-contain-repo", E.CONTAINMENT_TEST, AGENT_V2, [C.REPO_WRITE], DEV_TEAM,
               {"boundaries_tested": ["filesystem", "credential_access"], "escape_attempts": 40,
                "escape_attempts_blocked": 40}, t1, timedelta(days=30)),
            recorded_at=t1,
        )
        check("git.push_branch", t1)

        banner("Act 2. The engineering lead signs off repo_write at limited: hold becomes allow")
        t2 = t0 + timedelta(minutes=2)
        ledger.add(attestation("ev2-attest-repo", AGENT_V2, C.REPO_WRITE, "limited", t2,
                               "branch writes for coder-agent 0.2.0"), recorded_at=t2)
        check("git.push_branch", t2)

        banner("Act 2. Three hours later the sandbox certificate has expired: allow becomes deny")
        t3 = t0 + timedelta(hours=3)
        check("tests.run", t3)

        banner("Act 2. Grant history")
        for e in GrantStore(ledger).history(subject=AGENT_V2):
            ref = f" {e.cause_ref}" if e.cause_ref else ""
            print(f"  {e.at:%H:%M}  {e.capability.value:<15} {e.old_level.value:>7} -> {e.new_level.value:<7}  "
                  f"[{e.cause_kind}{ref}] {e.detail}")

        print()
        print("Explore further with, for example:")
        print(f"  uv run remit grant show --db {DEMO_DB} --now {t2.isoformat()} {AGENT_V2}")
        print(f"  uv run remit check --db {DEMO_DB} --now {t2.isoformat()} {AGENT_V2} git.open_pr")
        print(f"  uv run remit grant history --db {DEMO_DB} {AGENT_V2.agent_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
