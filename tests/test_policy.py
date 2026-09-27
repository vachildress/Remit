# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

from datetime import timedelta

import pytest

from remit.evidence.model import Capability, EvidenceClass, Level, Subject
from remit.policy import GrantStore, attenuate, evaluate_envelope, refresh
from remit.policy.evaluator import current_tier

from .conftest import AGENT, NOW, RULES, eval_ev, full_set, make_evidence

C = Capability
E = EvidenceClass
L = Level


def tier(name="4", subject=AGENT, **kwargs):
    return make_evidence(
        E.STANDARDS_EVIDENCE, scope=list(C), subject=subject, role="internal_independent",
        strength={"standard": "Synthetic model risk policy", "clause": "tiering", "tier": name}, **kwargs,
    )


def attest(cap, level, subject=AGENT, issued_at=None, **kwargs):
    return make_evidence(
        E.HUMAN_ATTESTATION, scope=[cap], subject=subject, strength={"grants_level": level},
        issued_at=issued_at or NOW - timedelta(minutes=5), **kwargs,
    )


def envelope(evidence, now=NOW, previous=None, parent=None, subject=AGENT):
    return evaluate_envelope(evidence, RULES, subject, now, previous, parent)


def with_replaced(evidence, cls, replacement):
    """Every record of ``cls`` replaced by the one ``replacement``."""
    return [e for e in evidence if e.evidence_class is not cls] + [replacement]


# --- Expansion needs a human --------------------------------------------------


def test_evidence_alone_does_not_expand_a_grant():
    g = envelope(full_set(C.CODE_EXECUTION) + [tier()])[C.CODE_EXECUTION]
    assert g.supported is L.FULL
    assert g.level is L.NONE
    assert g.held is L.FULL
    assert "no human_attestation names code_execution at full" in g.explanation


def test_matching_attestation_expands_and_is_recorded_on_the_grant():
    a = attest(C.CODE_EXECUTION, "full")
    g = envelope(full_set(C.CODE_EXECUTION) + [tier(), a])[C.CODE_EXECUTION]
    assert g.level is L.FULL
    assert g.attestation == a.id
    assert g.held is None
    assert g.causes[0].kind == "attestation" and g.causes[0].ref == a.id
    assert f"Authorised by attestation {a.id}" in g.explanation


def test_attestation_for_limited_expands_only_to_limited():
    g = envelope(full_set(C.CODE_EXECUTION) + [tier(), attest(C.CODE_EXECUTION, "limited")])[C.CODE_EXECUTION]
    assert g.level is L.LIMITED
    assert g.held is L.FULL


@pytest.mark.parametrize(
    "bad, why",
    [
        (lambda: attest(C.CODE_EXECUTION, "full", issued_at=NOW - timedelta(days=2)), "issued before the evidence"),
        (lambda: attest(C.REPO_WRITE, "full"), "names another capability"),
        (lambda: attest(C.CODE_EXECUTION, "full", subject=Subject(AGENT.agent_id, "0.9.0")), "names another version"),
        (lambda: make_evidence(E.HUMAN_ATTESTATION, scope=[C.CODE_EXECUTION], issued_at=NOW - timedelta(minutes=5)),
         "names no level"),
        (lambda: attest(C.CODE_EXECUTION, "full", revoked_at=NOW - timedelta(minutes=1), revocation_reason="signed in error"),
         "is revoked"),
        (lambda: attest(C.CODE_EXECUTION, "full", authorised=False), "comes from an unauthorised source"),
    ],
)
def test_attestation_that_does_not_match_does_not_expand(bad, why):
    g = envelope(full_set(C.CODE_EXECUTION) + [tier(), bad()])[C.CODE_EXECUTION]
    assert g.level is L.NONE, why


def test_restoring_after_new_evidence_needs_a_fresh_attestation():
    cap = C.CODE_EXECUTION
    old_attest = attest(cap, "full", issued_at=NOW - timedelta(hours=2))
    renewed = [
        make_evidence(E.CONTAINMENT_TEST, scope=[cap], role="external", issued_at=NOW - timedelta(hours=1))
        if e.evidence_class is E.CONTAINMENT_TEST
        else e
        for e in full_set(cap)
    ]
    previous = {cap: (L.NONE, None)}
    # The only containment evidence post-dates the attestation, so the old
    # sign off cannot authorise the rise.
    assert envelope(renewed + [tier(), old_attest], previous=previous)[cap].level is L.NONE
    fresh = attest(cap, "full", issued_at=NOW - timedelta(minutes=1))
    assert envelope(renewed + [tier(), old_attest, fresh], previous=previous)[cap].level is L.FULL


def test_monitor_reports_after_the_attestation_do_not_block_expansion():
    cap = C.CODE_EXECUTION
    a = attest(cap, "full", issued_at=NOW - timedelta(minutes=5))
    # full_set's monitor report is issued a day ago; add a newer heartbeat.
    fresh_heartbeat = make_evidence(
        E.MONITOR_HEALTH, scope=[cap], issued_at=NOW - timedelta(seconds=10),
        strength={"monitor_name": "sandbox-monitor", "last_heartbeat": (NOW - timedelta(seconds=10)).isoformat()},
    )
    assert envelope(full_set(cap) + [tier(), a, fresh_heartbeat])[cap].level is L.FULL


def test_a_grant_already_held_needs_no_new_attestation():
    cap = C.READ_DATA
    g = envelope(full_set(cap) + [tier()], previous={cap: (L.FULL, "ev-earlier")})[cap]
    assert g.level is L.FULL
    assert g.attestation == "ev-earlier"
    assert not g.changed


# --- Contraction is automatic -------------------------------------------------


def full_grant(cap):
    return full_set(cap) + [tier(), attest(cap, "full")]


def test_expiry_contracts_immediately():
    cap = C.CODE_EXECUTION
    expiring = make_evidence(E.CONTAINMENT_TEST, scope=[cap], role="external", expires_at=NOW + timedelta(hours=1))
    evidence = with_replaced(full_grant(cap), E.CONTAINMENT_TEST, expiring)
    prev = {cap: (L.FULL, "ev-a")}
    assert envelope(evidence, previous=prev)[cap].level is L.FULL
    g = envelope(evidence, now=NOW + timedelta(hours=2), previous=prev)[cap]
    assert g.level is L.NONE
    assert g.causes[0].kind == "expiry" and g.causes[0].ref == expiring.id
    assert "Lowered from full" in g.explanation


def test_revocation_contracts_immediately():
    cap = C.WRITE_DATA
    bad_eval = eval_ev(cap, revoked_at=NOW - timedelta(minutes=1), revocation_reason="suite leaked", role="external")
    g = envelope(with_replaced(full_grant(cap), E.EVAL_RESULT, bad_eval), previous={cap: (L.FULL, "ev-a")})[cap]
    assert g.level is L.NONE
    assert g.causes[0].kind == "revocation" and "suite leaked" in g.causes[0].detail


def test_monitor_degradation_contracts_to_the_highest_level_without_it():
    cap = C.CODE_EXECUTION
    degraded = make_evidence(E.MONITOR_HEALTH, scope=[cap], strength={"monitor_name": "sandbox-monitor", "state": "degraded"})
    g = envelope(with_replaced(full_grant(cap), E.MONITOR_HEALTH, degraded), previous={cap: (L.FULL, "ev-a")})[cap]
    assert g.level is L.LIMITED
    assert g.causes[0].kind == "monitor" and g.causes[0].ref == "sandbox-monitor"


def test_monitor_silence_contracts_with_the_clock():
    cap = C.CODE_EXECUTION
    prev = {cap: (L.FULL, "ev-a")}
    g = envelope(full_grant(cap), now=NOW + timedelta(minutes=5), previous=prev)[cap]
    assert g.level is L.LIMITED
    assert g.monitors == ()


# --- Tier ceilings -------------------------------------------------------------


def test_tier_ceiling_binds_whatever_the_evidence():
    cap = C.CODE_EXECUTION
    g = envelope(full_set(cap) + [tier("2"), attest(cap, "full")])[cap]
    assert g.supported is L.FULL
    assert g.level is L.LIMITED
    assert "the tier 2 ceiling" in g.explanation and "caps it at limited" in g.explanation


def test_tier_ceiling_unbinds_when_the_tier_allows():
    cap = C.CODE_EXECUTION
    assert envelope(full_set(cap) + [tier("4"), attest(cap, "full")])[cap].level is L.FULL


def test_tighter_tier_contracts_an_existing_grant():
    cap = C.CODE_EXECUTION
    g = envelope(full_set(cap) + [tier("2"), attest(cap, "full")], previous={cap: (L.FULL, "ev-a")})[cap]
    assert g.level is L.LIMITED
    assert g.causes[0].kind == "ceiling"


def test_no_tier_evidence_means_the_strictest_ceiling():
    cap = C.CODE_EXECUTION
    env = envelope(full_set(cap) + [attest(cap, "full")])
    assert env.ceiling.tier.name == "untiered"
    assert env[cap].level is L.NONE
    assert "the untiered ceiling" in env[cap].explanation


def test_tier_evidence_older_than_its_tier_allows_does_not_count():
    # Tier 2 evidence counts for 180 days.
    stale = tier("2", issued_at=NOW - timedelta(days=200), expires_at=NOW + timedelta(days=100))
    assert current_tier([stale], RULES, AGENT, NOW).tier.name == "untiered"
    fresh = tier("2", issued_at=NOW - timedelta(days=100), expires_at=NOW + timedelta(days=100))
    assert current_tier([fresh], RULES, AGENT, NOW).tier.name == "2"


def test_strictest_current_tier_applies_and_unknown_tiers_do_not_count():
    t4, t2, bogus = tier("4"), tier("2"), tier("9")
    ceiling = current_tier([t4, t2, bogus], RULES, AGENT, NOW)
    assert ceiling.tier.name == "2" and ceiling.evidence_ids == (t2.id,)
    assert current_tier([bogus], RULES, AGENT, NOW).tier.name == "untiered"


# --- Independence and suite pinning reach the grant -------------------------------


def test_developer_certified_sandbox_cannot_reach_full():
    cap = C.CODE_EXECUTION
    own = make_evidence(E.CONTAINMENT_TEST, scope=[cap], role="developer")
    g = envelope(with_replaced(full_grant(cap), E.CONTAINMENT_TEST, own))[cap]
    assert g.level is L.LIMITED
    assert any(u.requirement_id == "exec.contain.full" for u in g.unmet[L.FULL])


def test_eval_on_an_unnamed_suite_grants_nothing():
    cap = C.BUDGET
    trivial = eval_ev(cap, strength={"suite": "trivial-suite", "pass_rate": 1.0})
    g = envelope([trivial, tier(), attest(cap, "full")])[cap]
    assert g.level is L.NONE
    assert "suite 'trivial-suite' is not one of the suites that count here" in g.why_not(L.LIMITED)


# --- Delegation attenuation ------------------------------------------------------


def parent_envelope():
    evidence = full_set(C.DELEGATION) + full_set(C.CODE_EXECUTION) + [
        tier("3"), attest(C.DELEGATION, "limited"), attest(C.CODE_EXECUTION, "full"),
    ]
    env = envelope(evidence)
    assert env[C.DELEGATION].level is L.LIMITED and env[C.CODE_EXECUTION].level is L.FULL
    return env


def test_delegation_within_the_parent_envelope_is_accepted():
    child = Subject("helper-agent", "1.0.0")
    d = attenuate(parent_envelope(), child, {C.CODE_EXECUTION: L.LIMITED})
    assert d.accepted
    assert d.levels[C.CODE_EXECUTION] is L.LIMITED and d.levels[C.NETWORK_OUT] is L.NONE


def test_wider_child_is_rejected():
    child = Subject("helper-agent", "1.0.0")
    d = attenuate(parent_envelope(), child, {C.CODE_EXECUTION: L.FULL, C.NETWORK_OUT: L.LIMITED})
    assert not d.accepted
    assert "asks for network_out at limited, but the parent holds it only at none" in d.explanation
    assert "code_execution" not in d.explanation  # full is within the parent's full grant


def test_parent_without_delegation_cannot_delegate():
    env = envelope(full_grant(C.CODE_EXECUTION))
    d = attenuate(env, Subject("helper-agent", "1.0.0"), {C.CODE_EXECUTION: L.LIMITED})
    assert not d.accepted
    assert "holds no delegation grant" in d.explanation


def test_parent_levels_cap_the_child_whatever_its_own_evidence():
    child = Subject("helper-agent", "1.0.0")
    evidence = full_set(C.CODE_EXECUTION, subject=child) + [
        tier(subject=child), attest(C.CODE_EXECUTION, "full", subject=child),
    ]
    d = attenuate(parent_envelope(), child, {C.CODE_EXECUTION: L.LIMITED})
    g = envelope(evidence, parent=d.levels, subject=child)[C.CODE_EXECUTION]
    assert g.supported is L.FULL
    assert g.level is L.LIMITED
    assert g.ceiling_source == "the delegating parent's grant"


# --- Explanations -----------------------------------------------------------------


@pytest.mark.parametrize("cap", list(C))
def test_every_grant_has_an_explanation_naming_what_binds(cap):
    for evidence in ([], full_set(cap) + [tier()], full_grant(cap), full_set(cap) + [tier("1"), attest(cap, "full")]):
        g = envelope(evidence)[cap]
        assert g.explanation.startswith(f"{cap.value}: granted {g.level.value}.")
        if g.level is not L.FULL:
            why = g.why_not(L.FULL)
            assert why
            named = [u.requirement_id for lvl in (L.LIMITED, L.FULL) for u in g.unmet.get(lvl, ())]
            assert any(n in why for n in named) or "ceiling" in why or "human_attestation" in why


# --- History ----------------------------------------------------------------------


def test_refresh_records_each_change_with_its_cause(ledger):
    cap = C.CODE_EXECUTION
    expiring = make_evidence(E.CONTAINMENT_TEST, scope=[cap], role="external", expires_at=NOW + timedelta(hours=1))
    for e in with_replaced(full_grant(cap), E.CONTAINMENT_TEST, expiring):
        ledger.add(e)
    refresh(ledger, RULES, AGENT, NOW)
    refresh(ledger, RULES, AGENT, NOW + timedelta(seconds=30))  # no change, no event
    refresh(ledger, RULES, AGENT, NOW + timedelta(hours=2))
    events = [e for e in GrantStore(ledger).history(subject=AGENT) if e.capability is cap]
    assert [(e.old_level, e.new_level, e.cause_kind) for e in events] == [
        (L.NONE, L.FULL, "attestation"),
        (L.FULL, L.NONE, "expiry"),
    ]
    assert events[1].cause_ref == expiring.id
    assert GrantStore(ledger).current(AGENT)[cap] == (L.NONE, None)


def test_history_can_be_read_per_agent_across_versions(ledger):
    v2 = Subject(AGENT.agent_id, "2.0.0")
    for subject in (AGENT, v2):
        for e in full_set(C.BUDGET, subject=subject) + [tier(subject=subject), attest(C.BUDGET, "full", subject=subject)]:
            ledger.add(e)
        refresh(ledger, RULES, subject, NOW)
    store = GrantStore(ledger)
    assert {e.subject for e in store.history(agent_id=AGENT.agent_id)} == {AGENT, v2}
    assert {e.subject for e in store.history(subject=v2)} == {v2}
