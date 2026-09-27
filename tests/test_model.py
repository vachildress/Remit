# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

from datetime import datetime, timedelta, timezone

import pytest

from remit.evidence.model import (
    AdmissionState,
    Capability,
    Evidence,
    EvidenceClass,
    Level,
    Subject,
    hash_artefact,
    parse_timestamp,
)

from .conftest import NOW, make_evidence


def test_subject_parse_and_str():
    s = Subject.parse("agent@2.0.1")
    assert s == Subject("agent", "2.0.1")
    assert str(s) == "agent@2.0.1"
    assert Subject.parse("scoped@agent@1") == Subject("scoped@agent", "1")
    for bad in ("agent", "@1", "agent@"):
        with pytest.raises(ValueError):
            Subject.parse(bad)


def test_orderings():
    assert Level.NONE.rank < Level.LIMITED.rank < Level.FULL.rank
    ranks = [s.rank for s in AdmissionState]
    assert ranks == sorted(ranks)
    assert AdmissionState.PRESENT.rank == 0 and AdmissionState.GATE_ELIGIBLE.rank == 4


def test_naive_timestamps_are_utc_and_aware_ones_are_converted():
    naive = make_evidence(issued_at=datetime(2026, 1, 1, 9, 0))
    assert naive.issued_at.tzinfo == timezone.utc
    plus_one = timezone(timedelta(hours=1))
    aware = make_evidence(issued_at=datetime(2026, 1, 1, 10, 0, tzinfo=plus_one))
    assert aware.issued_at == datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    assert parse_timestamp("2026-01-01T09:00:00Z") == datetime(2026, 1, 1, 9, tzinfo=timezone.utc)


def test_model_rejects_an_unknown_evidence_class():
    # Build a valid object first, so the fixture cannot be what fails.
    valid = make_evidence()
    fields = {**valid.__dict__, "evidence_class": "not_a_class"}
    with pytest.raises(ValueError, match="'not_a_class' is not a valid EvidenceClass"):
        Evidence(**fields)


def test_model_rejects_an_unknown_capability_in_scope():
    valid = make_evidence()
    fields = {**valid.__dict__, "scope": frozenset({"teleportation"})}
    with pytest.raises(ValueError, match="'teleportation' is not a valid Capability"):
        Evidence(**fields)


def test_model_requires_issued_at():
    valid = make_evidence()
    with pytest.raises(ValueError, match="issued_at is required"):
        Evidence(**{**valid.__dict__, "issued_at": None})


def test_dict_round_trip():
    ev = make_evidence(EvidenceClass.CONTAINMENT_TEST, scope=[Capability.CODE_EXECUTION])
    again = Evidence.from_dict(ev.to_dict())
    assert again.to_dict() == ev.to_dict()
    assert again.id == ev.id


def test_from_dict_accepts_short_forms():
    ev = Evidence.from_dict(
        {
            "class": "eval_result",
            "subject": "agent@1",
            "scope": "read_data, budget",
            "source": "lab",
            "issued_at": "2026-01-01T00:00:00Z",
        }
    )
    assert ev.subject == Subject("agent", "1")
    assert ev.scope == {Capability.READ_DATA, Capability.BUDGET}
    assert ev.source.name == "lab" and not ev.source.authorised_classes
    assert ev.id.startswith("ev-")


def test_expiry_and_revocation_boundaries():
    ev = make_evidence(expires_at=NOW, revoked_at=NOW + timedelta(hours=1), revocation_reason="x")
    assert not ev.is_expired(NOW - timedelta(microseconds=1))
    assert ev.is_expired(NOW)  # expiry is exclusive: at the instant it expires, it is gone
    assert not ev.is_revoked(NOW)
    assert ev.is_revoked(NOW + timedelta(hours=1))


def test_hash_artefact():
    assert hash_artefact(b"abc") == (
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
