# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

from datetime import timedelta

import pytest

from remit.evidence.ledger import EvidenceNotFound, Ledger, LedgerError
from remit.evidence.model import Capability, EvidenceClass, Subject

from .conftest import AGENT, NOW, make_evidence


def test_add_and_get_round_trip(ledger):
    ev = make_evidence(EvidenceClass.MONITOR_HEALTH, scope=[Capability.CODE_EXECUTION])
    ledger.add(ev, recorded_at=NOW)
    assert ledger.get(ev.id) == ev


def test_duplicate_id_is_rejected(ledger):
    ev = make_evidence()
    ledger.add(ev)
    with pytest.raises(LedgerError, match="already in the ledger"):
        ledger.add(ev)


def test_get_missing(ledger):
    with pytest.raises(EvidenceNotFound):
        ledger.get("ev-nope")


def test_query_by_subject_and_class(ledger):
    other = Subject("other-agent", "1.0.0")
    newer = Subject(AGENT.agent_id, "2.0.0")
    a = ledger.add(make_evidence(EvidenceClass.EVAL_RESULT, issued_at=NOW - timedelta(days=3)))
    b = ledger.add(make_evidence(EvidenceClass.CONTAINMENT_TEST, issued_at=NOW - timedelta(days=2)))
    c = ledger.add(make_evidence(EvidenceClass.EVAL_RESULT, subject=other))
    d = ledger.add(make_evidence(EvidenceClass.EVAL_RESULT, subject=newer))
    assert [e.id for e in ledger.query(agent_id=AGENT.agent_id, version="1.0.0")] == [a.id, b.id]
    assert {e.id for e in ledger.query(agent_id=AGENT.agent_id)} == {a.id, b.id, d.id}
    assert {e.id for e in ledger.query(evidence_class="eval_result")} == {a.id, c.id, d.id}
    assert [e.id for e in ledger.for_subject(AGENT)] == [a.id, b.id]
    assert ledger.query(agent_id=AGENT.agent_id, evidence_class=EvidenceClass.HUMAN_ATTESTATION) == []


def test_expire_brings_expiry_forward_and_logs(ledger):
    ev = ledger.add(make_evidence(expires_at=NOW + timedelta(days=30)))
    updated = ledger.expire(ev.id, at=NOW)
    assert updated.expires_at == NOW
    assert updated.is_expired(NOW)
    events = [(r["event"], r["detail"]) for r in ledger.events(ev.id)]
    assert events[0][0] == "added" and events[1][0] == "expired"
    assert "previous_expiry" in events[1][1]


def test_expire_can_never_extend(ledger):
    ev = ledger.add(make_evidence(expires_at=NOW - timedelta(days=1)))
    with pytest.raises(LedgerError, match="already expired"):
        ledger.expire(ev.id, at=NOW)
    assert ledger.get(ev.id).expires_at == NOW - timedelta(days=1)


def test_expire_twice_fails(ledger):
    ev = ledger.add(make_evidence())
    ledger.expire(ev.id, at=NOW)
    with pytest.raises(LedgerError):
        ledger.expire(ev.id, at=NOW + timedelta(seconds=1))


def test_expire_evidence_with_no_expiry(ledger):
    ev = ledger.add(make_evidence(expires_at=None))
    assert ledger.expire(ev.id, at=NOW).expires_at == NOW


def test_revoke(ledger):
    ev = ledger.add(make_evidence())
    updated = ledger.revoke(ev.id, "  eval contaminated  ", at=NOW)
    assert updated.revoked_at == NOW
    assert updated.revocation_reason == "eval contaminated"
    assert [r["event"] for r in ledger.events(ev.id)] == ["added", "revoked"]


def test_revoke_needs_reason_and_happens_once(ledger):
    ev = ledger.add(make_evidence())
    with pytest.raises(LedgerError, match="reason"):
        ledger.revoke(ev.id, "   ", at=NOW)
    ledger.revoke(ev.id, "first", at=NOW)
    with pytest.raises(LedgerError, match="already revoked"):
        ledger.revoke(ev.id, "second", at=NOW)
    assert ledger.get(ev.id).revocation_reason == "first"


def test_expired_evidence_can_still_be_revoked(ledger):
    ev = ledger.add(make_evidence(expires_at=NOW - timedelta(days=1)))
    assert ledger.revoke(ev.id, "found to be fabricated", at=NOW).revoked_at == NOW


def test_withdrawal_of_missing_evidence(ledger):
    with pytest.raises(EvidenceNotFound):
        ledger.expire("ev-nope", at=NOW)
    with pytest.raises(EvidenceNotFound):
        ledger.revoke("ev-nope", "x", at=NOW)


def test_persists_to_disk(tmp_path):
    path = tmp_path / "ledger.db"
    ev = make_evidence()
    with Ledger(path) as led:
        led.add(ev)
        led.revoke(ev.id, "r", at=NOW)
    with Ledger(path) as led:
        assert led.get(ev.id).revoked_at == NOW


def test_source_role_persists(ledger):
    ev = ledger.add(make_evidence(role="external"))
    assert ledger.get(ev.id).source.role == "external"
