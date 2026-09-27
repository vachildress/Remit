# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

from datetime import timedelta

import pytest

from remit.enforcement import ALLOW, DENY, HOLD, StubPEP, decide, load_tool_table, make_pep
from remit.enforcement.tools import ToolTableError, parse_tool_table
from remit.evidence.model import Capability, EvidenceClass, Level
from remit.policy import evaluate_envelope

from .conftest import AGENT, NOW, RULES, eval_ev, full_set, make_evidence
from .test_policy import attest, tier

C = Capability
E = EvidenceClass
L = Level
TOOLS = load_tool_table()


def everything_full():
    evidence = [tier("4")]
    for cap in C:
        evidence += full_set(cap) + [attest(cap, "full")]
    return evidence


def load(ledger, evidence):
    for e in evidence:
        ledger.add(e)


# --- The tool table --------------------------------------------------------------


def test_bundled_tool_table_loads_and_json_mirror_is_in_step():
    import json

    import yaml

    from remit.enforcement.tools import bundled_text

    yaml_data = yaml.safe_load(bundled_text("yaml"))
    json_data = {k: v for k, v in json.loads(bundled_text("json")).items() if not k.startswith("_")}
    assert json_data == yaml_data, "tools.json is stale: run `make rules-json`"
    assert load_tool_table(fmt="json") == load_tool_table(fmt="yaml")
    assert TOOLS.tools["git.push_branch"].capability is C.REPO_WRITE
    assert TOOLS.tools["git.push_branch"].level is L.LIMITED
    assert set(TOOLS.red_lines) == {"git.merge_main", "secrets.read_credentials"}


@pytest.mark.parametrize(
    "data, fragment",
    [
        ({"tools": {"x": {"capability": "teleport", "level": "limited"}}}, "teleport"),
        ({"tools": {"x": {"capability": "read_data", "level": "none"}}}, "needs no grant"),
        ({"tools": {"x": {"capability": "read_data", "level": "limited", "colour": 1}}}, "unknown fields"),
        ({"tools": {"x": {"capability": "read_data", "level": "limited"}}, "red_lines": {"x": "no"}}, "both"),
        ({"gadgets": {}}, "unknown top level"),
    ],
)
def test_invalid_tool_tables_are_rejected(data, fragment):
    with pytest.raises(ToolTableError, match=fragment):
        parse_tool_table(data)


# --- Decisions ----------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["git.merge_main", "secrets.read_credentials"])
def test_red_lines_always_deny_even_with_every_grant_at_full(tool):
    env = evaluate_envelope(everything_full(), RULES, AGENT, NOW)
    assert all(g.level is L.FULL for g in env.grants.values())
    d = decide(env, TOOLS, tool)
    assert d.outcome == DENY and d.red_line and d.binding == "red_line"
    assert "red line" in d.explanation


def test_unknown_tools_are_denied():
    env = evaluate_envelope(everything_full(), RULES, AGENT, NOW)
    d = decide(env, TOOLS, "rm.everything")
    assert d.outcome == DENY and d.binding == "unknown_tool"


def test_every_listed_tool_is_allowed_when_every_grant_is_full():
    env = evaluate_envelope(everything_full(), RULES, AGENT, NOW)
    assert {decide(env, TOOLS, t).outcome for t in TOOLS.tools} == {ALLOW}


def test_allow_deny_and_hold(ledger):
    cap = C.REPO_WRITE
    pep = StubPEP(ledger, RULES, TOOLS)
    load(ledger, [tier("4")])
    assert pep.check(AGENT, "git.push_branch", NOW).outcome == DENY
    load(ledger, full_set(cap))
    held = pep.check(AGENT, "git.push_branch", NOW)
    assert held.outcome == HOLD and held.binding == "attestation"
    assert "no human_attestation names repo_write" in held.explanation
    load(ledger, [attest(cap, "limited", issued_at=NOW)])
    assert pep.check(AGENT, "git.push_branch", NOW + timedelta(seconds=1)).outcome == ALLOW
    # Merging a feature branch needs full, which only a full attestation authorises.
    assert pep.check(AGENT, "git.merge_feature_branch", NOW + timedelta(seconds=1)).outcome == HOLD


def test_the_same_call_flips_on_expiry(ledger):
    cap = C.CODE_EXECUTION
    cert = make_evidence(E.CONTAINMENT_TEST, scope=[cap], role="external", expires_at=NOW + timedelta(hours=1))
    load(ledger, [e for e in full_set(cap) if e.evidence_class is not E.CONTAINMENT_TEST] + [cert, tier("4"), attest(cap, "limited")])
    pep = StubPEP(ledger, RULES, TOOLS)
    assert pep.check(AGENT, "tests.run", NOW).outcome == ALLOW
    later = pep.check(AGENT, "tests.run", NOW + timedelta(hours=2))
    assert later.outcome == DENY
    assert later.binding == "exec.contain"
    assert f"{cert.id}: admission state is sufficient, not gate_eligible: expired at" in later.explanation


def test_the_tier_ceiling_denies_and_says_so(ledger):
    cap = C.CODE_EXECUTION
    load(ledger, full_set(cap) + [tier("2"), attest(cap, "full")])
    pep = StubPEP(ledger, RULES, TOOLS)
    assert pep.check(AGENT, "tests.run", NOW).outcome == ALLOW
    d = pep.check(AGENT, "shell.run_networked", NOW)
    assert d.outcome == DENY and d.binding == "ceiling"
    assert "the tier 2 ceiling" in d.explanation


def test_a_ceiling_is_not_something_a_human_can_approve(ledger):
    # Capped by the tier, not waiting on an attestation, so deny not hold.
    cap = C.EXTERNAL_COMMS
    load(ledger, full_set(cap) + [tier("2")])
    assert StubPEP(ledger, RULES, TOOLS).check(AGENT, "email.send_template", NOW).outcome == DENY


def test_developer_certified_sandbox_blocks_full_execution_only(ledger):
    cap = C.CODE_EXECUTION
    own = make_evidence(E.CONTAINMENT_TEST, scope=[cap], role="developer")
    load(ledger, [e for e in full_set(cap) if e.evidence_class is not E.CONTAINMENT_TEST] + [own, tier("4"), attest(cap, "full")])
    pep = StubPEP(ledger, RULES, TOOLS)
    assert pep.check(AGENT, "tests.run", NOW).outcome == ALLOW
    d = pep.check(AGENT, "shell.run_networked", NOW)
    # Both containment requirements fail at full: exec.contain is inherited
    # from limited, and the full-level independence floor applies to it too.
    assert d.outcome == DENY and d.binding in ("exec.contain", "exec.contain.full")
    assert "exec.contain.full" in d.explanation
    assert "must come from a source that is at least internal_independent" in d.explanation


def test_an_unnamed_suite_unlocks_nothing(ledger):
    cap = C.BUDGET
    load(ledger, [eval_ev(cap, strength={"suite": "trivial-suite", "pass_rate": 1.0}), tier("4"), attest(cap, "full")])
    d = StubPEP(ledger, RULES, TOOLS).check(AGENT, "job.run_capped", NOW)
    assert d.outcome == DENY and d.binding == "budget.eval"
    assert "an unknown suite does not count" in d.explanation


def scenarios():
    """Evidence sets covering allow, deny, hold, ceilings and red lines."""
    return {
        "empty": [],
        "untiered": everything_full()[1:],
        "tier 2": [tier("2")] + everything_full()[1:],
        "no attestations": [e for e in everything_full() if e.strength.get("grants_level") is None],
        "everything": everything_full(),
    }


@pytest.mark.parametrize("scenario", list(scenarios()))
def test_every_decision_is_explained_and_names_what_binds(scenario):
    env = evaluate_envelope(scenarios()[scenario], RULES, AGENT, NOW)
    for tool in list(TOOLS.tools) + list(TOOLS.red_lines) + ["no.such.tool"]:
        d = decide(env, TOOLS, tool)
        assert d.explanation.strip()
        assert d.binding
        if d.outcome == DENY and d.binding not in ("red_line", "unknown_tool"):
            if d.binding in ("ceiling", "parent"):
                assert "ceiling" in d.explanation or "parent" in d.explanation
            else:
                assert d.binding in d.explanation


# --- The AGT adapter --------------------------------------------------------------

agt = pytest.importorskip("remit.enforcement.agt")


def test_agt_policy_is_one_rule_per_tool_and_fails_closed():
    env = evaluate_envelope(everything_full(), RULES, AGENT, NOW)
    doc = agt.to_agt_policy(env, TOOLS)
    names = {r.name for r in doc.rules}
    assert len(doc.rules) == len(TOOLS.tools) + len(TOOLS.red_lines)
    assert "remit:red_line:git.merge_main" in names and "remit:allow:tests.run" in names
    assert doc.defaults.action.value == "deny"


@pytest.mark.parametrize("scenario", list(scenarios()))
def test_agt_enforces_exactly_what_remit_decides(scenario, tmp_path):
    from remit.evidence.ledger import Ledger

    evidence = scenarios()[scenario]
    with Ledger(tmp_path / "a.db") as a, Ledger(tmp_path / "b.db") as b:
        load(a, evidence)
        load(b, evidence)
        stub = make_pep(a, RULES, TOOLS, "stub")
        adapter = make_pep(b, RULES, TOOLS, "agt")
        for tool in list(TOOLS.tools) + list(TOOLS.red_lines) + ["no.such.tool"]:
            s, g = stub.check(AGENT, tool, NOW), adapter.check(AGENT, tool, NOW)
            assert (tool, g.outcome) == (tool, s.outcome)
            assert g.explanation == s.explanation
            assert g.enforced_by == "agt"


def test_agt_hold_is_parked_in_the_approval_queue(ledger):
    load(ledger, full_set(C.REPO_WRITE) + [tier("4")])
    adapter = make_pep(ledger, RULES, TOOLS, "agt")
    d = adapter.check(AGENT, "git.push_branch", NOW)
    assert d.outcome == HOLD and d.escalation_id
    pending = adapter.escalations.backend.list_pending()
    assert [p.request_id for p in pending] == [d.escalation_id]
    assert pending[0].action == "git.push_branch" and pending[0].agent_id == str(AGENT)


def test_agt_interceptor_protocol(ledger):
    from agent_os.integrations.base import ToolCallRequest

    load(ledger, full_set(C.CODE_EXECUTION) + [tier("4"), attest(C.CODE_EXECUTION, "limited")])
    adapter = agt.AGTAdapter(ledger, RULES, TOOLS, clock=lambda: NOW)
    ok = adapter.intercept(ToolCallRequest(tool_name="tests.run", arguments={}, agent_id=str(AGENT)))
    assert ok.allowed and ok.audit_entry["remit_decision"] == ALLOW
    held = adapter.intercept(ToolCallRequest(tool_name="shell.run_networked", arguments={}, agent_id=str(AGENT)))
    assert not held.allowed and held.audit_entry["remit_decision"] == HOLD and held.audit_entry["escalation_id"]
    red = adapter.intercept(ToolCallRequest(tool_name="git.merge_main", arguments={}, agent_id=str(AGENT)))
    assert not red.allowed and red.audit_entry["remit_decision"] == DENY
    anon = adapter.intercept(ToolCallRequest(tool_name="tests.run", arguments={}, agent_id="no-version"))
    assert not anon.allowed and "agent@version" in anon.reason


def test_agt_composes_with_other_agt_interceptors(ledger):
    from agent_os.integrations.base import CompositeInterceptor, ToolCallRequest, ToolCallResult

    class BlockEverything:
        def intercept(self, request):
            return ToolCallResult(allowed=False, reason="blocked by another interceptor")

    load(ledger, full_set(C.CODE_EXECUTION) + [tier("4"), attest(C.CODE_EXECUTION, "limited")])
    adapter = agt.AGTAdapter(ledger, RULES, TOOLS, clock=lambda: NOW)
    request = ToolCallRequest(tool_name="tests.run", arguments={}, agent_id=str(AGENT))
    assert CompositeInterceptor([adapter]).intercept(request).allowed
    assert not CompositeInterceptor([adapter, BlockEverything()]).intercept(request).allowed
