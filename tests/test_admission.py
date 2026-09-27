# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The CEOAI contributors

from datetime import timedelta

import pytest

from ceoai.evidence.admission import CLASS_FIELDS, assess, strength_metrics
from ceoai.evidence.model import AdmissionState, EvidenceClass

from .conftest import NOW, make_evidence

S = AdmissionState


@pytest.mark.parametrize("cls", list(EvidenceClass))
def test_well_formed_evidence_of_every_class_is_gate_eligible(cls):
    a = assess(make_evidence(cls), NOW)
    assert a.state is S.GATE_ELIGIBLE, a.blockers
    assert a.blockers == ()
    assert a.status == "live"


@pytest.mark.parametrize("cls", list(EvidenceClass))
def test_each_required_strength_field_is_needed_for_completeness(cls):
    for spec in CLASS_FIELDS[cls]:
        if not spec.required:
            continue
        a = assess(make_evidence(cls, strength={spec.name: None}), NOW)
        assert a.state is S.PRESENT
        assert any(spec.name in b for b in a.blockers)


@pytest.mark.parametrize(
    "kwargs, fragment",
    [
        ({"expires_at": None}, "no expiry"),
        ({"content_hash": None}, "no content hash"),
        ({"content_hash": "md5:abc"}, "sha256"),
        ({"scope": []}, "scope is empty"),
    ],
)
def test_incomplete_evidence_stays_present(kwargs, fragment):
    a = assess(make_evidence(**kwargs), NOW)
    assert a.state is S.PRESENT
    assert any(fragment in b for b in a.blockers)


@pytest.mark.parametrize(
    "cls, strength, fragment",
    [
        (EvidenceClass.EVAL_RESULT, {"pass_rate": 1.2}, "between 0 and 1"),
        (EvidenceClass.EVAL_RESULT, {"pass_rate": True}, "between 0 and 1"),
        (EvidenceClass.EVAL_RESULT, {"samples": -1}, "whole number"),
        (EvidenceClass.EVAL_RESULT, {"samples": 0}, "zero samples"),
        (EvidenceClass.RED_TEAM_REPORT, {"residual_risk": "tiny"}, "one of low"),
        (EvidenceClass.CONTAINMENT_TEST, {"boundaries_tested": ["moat"]}, "unknown boundaries"),
        (EvidenceClass.CONTAINMENT_TEST, {"escape_attempts": 0, "escape_attempts_blocked": 0}, "no escape attempts"),
        (EvidenceClass.CONTAINMENT_TEST, {"escape_attempts": 5, "escape_attempts_blocked": 6}, "more escape attempts blocked"),
        (EvidenceClass.MONITOR_HEALTH, {"state": "fine"}, "one of healthy"),
        (EvidenceClass.MONITOR_HEALTH, {"last_heartbeat": "yesterday"}, "ISO 8601"),
        (EvidenceClass.MONITOR_HEALTH, {"heartbeat_timeout_seconds": 0}, "positive number"),
    ],
)
def test_malformed_strength_stops_at_complete(cls, strength, fragment):
    a = assess(make_evidence(cls, strength=strength), NOW)
    assert a.state is S.COMPLETE
    assert any(fragment in b for b in a.blockers), a.blockers


def test_unauthorised_source_is_not_admissible():
    a = assess(make_evidence(authorised=False), NOW)
    assert a.state is S.SUFFICIENT
    assert "no recorded authority" in a.blockers[0]


def test_source_authorised_for_another_class_is_not_enough():
    ev = make_evidence(EvidenceClass.CONTAINMENT_TEST)
    ev = type(ev)(**{**ev.__dict__, "source": type(ev.source)("lab", frozenset({EvidenceClass.EVAL_RESULT}))})
    assert assess(ev, NOW).state is S.SUFFICIENT


def test_expiry_edges():
    ev = make_evidence(issued_at=NOW - timedelta(days=10), expires_at=NOW)
    before = assess(ev, NOW - timedelta(microseconds=1))
    at = assess(ev, NOW)
    assert before.state is S.GATE_ELIGIBLE
    assert at.state is S.SUFFICIENT and at.expired and at.status == "expired"
    assert "expired at" in at.blockers[0]


def test_expires_before_issue_is_not_admissible():
    ev = make_evidence(issued_at=NOW - timedelta(days=1), expires_at=NOW - timedelta(days=2))
    a = assess(ev, NOW)
    assert a.state is S.SUFFICIENT
    assert "expires before it was issued" in a.blockers


def test_future_issue_is_not_admissible():
    ev = make_evidence(issued_at=NOW + timedelta(hours=1))
    a = assess(ev, NOW)
    assert a.state is S.SUFFICIENT
    assert "not issued until" in a.blockers[0]


def test_revocation_takes_effect_from_its_timestamp():
    ev = make_evidence(revoked_at=NOW, revocation_reason="flawed eval harness")
    assert assess(ev, NOW - timedelta(seconds=1)).state is S.GATE_ELIGIBLE
    a = assess(ev, NOW)
    assert a.state is S.SUFFICIENT and a.revoked and a.status == "revoked"
    assert "flawed eval harness" in a.blockers[0]


def test_revoked_and_expired_reports_both():
    ev = make_evidence(expires_at=NOW - timedelta(hours=1), revoked_at=NOW - timedelta(hours=2), revocation_reason="r")
    a = assess(ev, NOW)
    assert len(a.blockers) == 2
    assert a.status == "revoked"


def test_monitor_must_be_healthy_to_be_gate_eligible():
    for state in ("degraded", "down"):
        a = assess(make_evidence(EvidenceClass.MONITOR_HEALTH, strength={"state": state}), NOW)
        assert a.state is S.ADMISSIBLE
        assert f"reports {state}" in a.blockers[0]


def test_monitor_heartbeat_timeout_default_and_custom():
    hb = (NOW - timedelta(seconds=301)).isoformat()
    stale = assess(make_evidence(EvidenceClass.MONITOR_HEALTH, strength={"last_heartbeat": hb}), NOW)
    assert stale.state is S.ADMISSIBLE and "silent for 301 seconds" in stale.blockers[0]
    patient = make_evidence(
        EvidenceClass.MONITOR_HEALTH, strength={"last_heartbeat": hb, "heartbeat_timeout_seconds": 600}
    )
    assert assess(patient, NOW).state is S.GATE_ELIGIBLE
    exactly = (NOW - timedelta(seconds=300)).isoformat()
    edge = make_evidence(EvidenceClass.MONITOR_HEALTH, strength={"last_heartbeat": exactly})
    assert assess(edge, NOW).state is S.GATE_ELIGIBLE


def test_monitor_heartbeat_in_future_is_rejected():
    hb = (NOW + timedelta(minutes=5)).isoformat()
    a = assess(make_evidence(EvidenceClass.MONITOR_HEALTH, strength={"last_heartbeat": hb}), NOW)
    assert a.state is S.ADMISSIBLE


def test_block_rate_is_derived():
    ev = make_evidence(EvidenceClass.CONTAINMENT_TEST, strength={"escape_attempts": 8, "escape_attempts_blocked": 6})
    assert strength_metrics(ev)["block_rate"] == 0.75
    assert "block_rate" not in ev.strength
