# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

from datetime import timedelta

import pytest

from remit.evidence.model import WORLD_ACTING_CAPABILITIES, Capability, EvidenceClass, Level, Subject
from remit.evidence.requirements import load_rules
from remit.evidence.support import explain_capability, rejection_reasons, render

from .conftest import AGENT, NOW, make_evidence

C = Capability
E = EvidenceClass
RULES = load_rules()


def explain(evidence, cap):
    return explain_capability(evidence, RULES, cap, AGENT, NOW)


def full_set(cap, monitor=None):
    """Evidence meeting every requirement of ``cap`` at full, one record per class."""
    reqs = [r for r, _ in RULES[cap].effective(Level.FULL)]
    out = [make_evidence(E.EVAL_RESULT, scope=[cap])]
    if any(r.containment for r in reqs):
        out.append(make_evidence(E.CONTAINMENT_TEST, scope=[cap]))
    for r in reqs:
        if r.monitor is not None:
            # Exactly at the monitor's effectiveness threshold, which must pass.
            strength = {"monitor_name": r.monitor.name, "effectiveness": r.monitor.min_effectiveness}
            out.append(make_evidence(E.MONITOR_HEALTH, scope=[cap], strength=strength))
    if any(E.RED_TEAM_REPORT in r.classes for r in reqs):
        out.append(make_evidence(E.RED_TEAM_REPORT, scope=[cap]))
    if any(E.HUMAN_ATTESTATION in r.classes for r in reqs):
        out.append(make_evidence(E.HUMAN_ATTESTATION, scope=[cap]))
    return out


@pytest.mark.parametrize("cap", list(Capability))
def test_empty_ledger_supports_only_none(cap):
    ex = explain([], cap)
    assert ex.highest_supported is Level.NONE
    text = render(ex)
    assert "NOT SUPPORTED" in text and "To meet it:" in text


@pytest.mark.parametrize("cap", list(Capability))
def test_complete_evidence_supports_full_for_every_capability(cap):
    ex = explain(full_set(cap), cap)
    assert ex.highest_supported is Level.FULL, render(ex)
    assert "[unmet]" not in render(ex)


@pytest.mark.parametrize("cap", sorted(WORLD_ACTING_CAPABILITIES))
def test_behavioural_evidence_alone_never_opens_a_world_acting_capability(cap):
    perfect = make_evidence(E.EVAL_RESULT, scope=[cap], strength={"pass_rate": 1.0, "samples": 100000})
    redteam = make_evidence(E.RED_TEAM_REPORT, scope=[cap])
    others = [e for e in full_set(cap) if e.evidence_class is not E.CONTAINMENT_TEST]
    ex = explain([perfect, redteam, *others], cap)
    assert ex.highest_supported is Level.NONE
    assert "eval_result can never satisfy a containment requirement" in render(ex)
    assert "red_team_report can never satisfy a containment requirement" in render(ex)


def test_containment_gate_ignores_behavioural_evidence_even_if_rules_were_loosened():
    req = next(r for r, _ in RULES[C.NETWORK_OUT].effective(Level.LIMITED) if r.containment)
    ev = make_evidence(E.EVAL_RESULT, scope=[C.NETWORK_OUT])
    loosened = type(req)(**{**req.__dict__, "classes": (E.CONTAINMENT_TEST, E.EVAL_RESULT)})
    assert rejection_reasons(ev, loosened, C.NETWORK_OUT, NOW)


def test_monitor_degradation_drops_to_the_highest_level_without_it():
    cap = C.CODE_EXECUTION
    evidence = full_set(cap)
    assert explain(evidence, cap).highest_supported is Level.FULL
    degraded = [
        make_evidence(E.MONITOR_HEALTH, scope=[cap], strength={"monitor_name": "sandbox-monitor", "state": "degraded"})
        if e.evidence_class is E.MONITOR_HEALTH
        else e
        for e in evidence
    ]
    ex = explain(degraded, cap)
    assert ex.highest_supported is Level.LIMITED
    assert "reports degraded" in render(ex)


def test_monitor_silence_contracts_automatically_with_time():
    cap = C.CODE_EXECUTION
    evidence = full_set(cap)
    later = NOW + timedelta(minutes=10)
    assert explain_capability(evidence, RULES, cap, AGENT, later).highest_supported is Level.LIMITED


def test_monitor_at_limited_drops_capability_to_none():
    cap = C.REPO_WRITE
    evidence = [e for e in full_set(cap) if e.evidence_class is not E.MONITOR_HEALTH]
    evidence.append(
        make_evidence(E.MONITOR_HEALTH, scope=[cap], strength={"monitor_name": "test-tamper-sensor", "state": "down"})
    )
    assert explain(evidence, cap).highest_supported is Level.NONE


def test_wrong_monitor_does_not_count():
    cap = C.CODE_EXECUTION
    evidence = [e for e in full_set(cap) if e.evidence_class is not E.MONITOR_HEALTH]
    evidence.append(make_evidence(E.MONITOR_HEALTH, scope=[cap], strength={"monitor_name": "egress-monitor"}))
    ex = explain(evidence, cap)
    assert ex.highest_supported is Level.LIMITED
    assert "no report from monitor 'sandbox-monitor' for test-agent@1.0.0 is scoped to code_execution" in render(ex)


def test_expiry_and_revocation_withdraw_support():
    cap = C.CODE_EXECUTION
    evidence = full_set(cap)
    expired = [
        make_evidence(E.CONTAINMENT_TEST, scope=[cap], expires_at=NOW) if e.evidence_class is E.CONTAINMENT_TEST else e
        for e in evidence
    ]
    ex = explain(expired, cap)
    assert ex.highest_supported is Level.NONE
    assert "expired at" in render(ex)
    revoked = [
        make_evidence(E.EVAL_RESULT, scope=[cap], revoked_at=NOW, revocation_reason="suite leaked into training")
        if e.evidence_class is E.EVAL_RESULT
        else e
        for e in evidence
    ]
    ex = explain(revoked, cap)
    assert ex.highest_supported is Level.NONE
    assert "suite leaked into training" in render(ex)


def test_age_limit_applies_even_while_evidence_is_unexpired():
    cap = C.CODE_EXECUTION
    old = make_evidence(E.CONTAINMENT_TEST, scope=[cap], issued_at=NOW - timedelta(days=20),
                        expires_at=NOW + timedelta(days=100))
    evidence = [e for e in full_set(cap) if e.evidence_class is not E.CONTAINMENT_TEST] + [old]
    ex = explain(evidence, cap)
    # 20 days is inside the 30 day limit for limited but outside the 14 day limit for full.
    assert ex.highest_supported is Level.LIMITED
    assert "older than the 14 day limit" in render(ex)


def test_strength_thresholds():
    cap = C.WRITE_DATA
    weak = make_evidence(E.EVAL_RESULT, scope=[cap], strength={"pass_rate": 0.85})
    leaky = make_evidence(E.CONTAINMENT_TEST, scope=[cap], strength={"escape_attempts": 10, "escape_attempts_blocked": 9})
    text = render(explain([weak, leaky], cap))
    assert "pass_rate is 0.85, needs at least 0.9" in text
    assert "block_rate is 0.9, needs at least 1" in text


def test_containment_must_cover_required_boundaries():
    cap = C.NETWORK_OUT
    fs_only = make_evidence(E.CONTAINMENT_TEST, scope=[cap], strength={"boundaries_tested": ["filesystem"]})
    ex = explain([make_evidence(E.EVAL_RESULT, scope=[cap]), fs_only], cap)
    assert ex.highest_supported is Level.NONE
    assert "does not cover network_egress" in render(ex)


def test_red_team_residual_risk_ceiling():
    cap = C.READ_DATA
    high = make_evidence(E.RED_TEAM_REPORT, scope=[cap], strength={"residual_risk": "high"})
    medium = make_evidence(E.RED_TEAM_REPORT, scope=[cap], strength={"residual_risk": "medium"})
    ev = make_evidence(E.EVAL_RESULT, scope=[cap])
    assert explain([ev, high], cap).highest_supported is Level.LIMITED
    assert explain([ev, medium], cap).highest_supported is Level.FULL


def test_out_of_scope_and_other_subject_evidence_is_ignored():
    cap = C.BUDGET
    wrong_scope = make_evidence(E.EVAL_RESULT, scope=[C.READ_DATA])
    wrong_version = make_evidence(E.EVAL_RESULT, scope=[cap], subject=Subject(AGENT.agent_id, "0.9.0"))
    ex = explain([wrong_scope, wrong_version], cap)
    assert ex.highest_supported is Level.NONE
    assert "not scoped to budget was ignored" in render(ex)


def test_unauthorised_source_does_not_count():
    cap = C.BUDGET
    ex = explain([make_evidence(E.EVAL_RESULT, scope=[cap], authorised=False)], cap)
    assert ex.highest_supported is Level.NONE
    assert "no recorded authority" in render(ex)


def test_render_names_supporting_evidence():
    evidence = full_set(C.READ_DATA)
    text = render(explain(evidence, C.READ_DATA))
    for ev in evidence:
        assert ev.id in text
    assert "Highest level the evidence supports: full" in text


def monitor_report(cap, name, heartbeat_ago, **strength):
    hb = (NOW - timedelta(seconds=heartbeat_ago)).isoformat()
    return make_evidence(
        E.MONITOR_HEALTH, scope=[cap], strength={"monitor_name": name, "last_heartbeat": hb, **strength}
    )


def without_monitors(cap):
    return [e for e in full_set(cap) if e.evidence_class is not E.MONITOR_HEALTH]


def test_latest_monitor_report_wins_over_an_earlier_healthy_one():
    cap = C.CODE_EXECUTION
    healthy_earlier = monitor_report(cap, "sandbox-monitor", 40)
    degraded_now = monitor_report(cap, "sandbox-monitor", 5, state="degraded")
    ex = explain(without_monitors(cap) + [healthy_earlier, degraded_now], cap)
    assert ex.highest_supported is Level.LIMITED
    text = render(ex)
    assert f"superseded by the later report {degraded_now.id}" in text
    assert "reports degraded" in text


def test_recovery_is_visible_once_the_latest_report_is_healthy():
    cap = C.CODE_EXECUTION
    degraded_earlier = monitor_report(cap, "sandbox-monitor", 40, state="degraded")
    healthy_now = monitor_report(cap, "sandbox-monitor", 5)
    ex = explain(without_monitors(cap) + [degraded_earlier, healthy_now], cap)
    assert ex.highest_supported is Level.FULL


def test_revoked_latest_report_is_skipped():
    cap = C.CODE_EXECUTION
    healthy = monitor_report(cap, "sandbox-monitor", 30)
    bogus = monitor_report(cap, "sandbox-monitor", 5, state="down")
    bogus = type(bogus)(**{**bogus.__dict__, "revoked_at": NOW, "revocation_reason": "misreport"})
    assert explain(without_monitors(cap) + [healthy, bogus], cap).highest_supported is Level.FULL


def test_rules_heartbeat_timeout_is_stricter_than_the_evidence_default():
    cap = C.CODE_EXECUTION
    # 90 seconds is inside the 300 second admission default but outside the
    # 60 second timeout the rules set for the sandbox monitor.
    report = monitor_report(cap, "sandbox-monitor", 90)
    ex = explain(without_monitors(cap) + [report], cap)
    assert ex.highest_supported is Level.LIMITED
    assert "last heartbeat 90 seconds ago, beyond this monitor's 60 second timeout" in render(ex)


def test_monitor_effectiveness_below_its_minimum_does_not_count():
    cap = C.EXTERNAL_COMMS
    weak = monitor_report(cap, "outbound-content-monitor", 5, effectiveness=0.94)
    ex = explain(without_monitors(cap) + [weak], cap)
    # The monitor is a limited dependency, so the capability falls to none.
    assert ex.highest_supported is Level.NONE
    assert "effectiveness is 0.94, needs at least 0.95" in render(ex)


def test_render_states_what_healthy_means():
    text = render(explain(full_set(C.BUDGET), C.BUDGET))
    assert "healthy means: reports healthy, last heartbeat within 300 seconds, effectiveness at least 0.99" in text


def test_eval_alone_does_not_reach_full_read_data():
    ex = explain([make_evidence(E.EVAL_RESULT, scope=[C.READ_DATA])], C.READ_DATA)
    assert ex.highest_supported is Level.LIMITED
