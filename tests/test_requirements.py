# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

import copy
import json

import pytest

from remit.evidence.model import WORLD_ACTING_CAPABILITIES, Capability, EvidenceClass, Level
from remit.evidence.requirements import RuleError, default_rules_text, load_rules, parse_rules


@pytest.fixture
def raw():
    return json.loads(default_rules_text())


def test_bundled_rules_load_and_cover_every_capability():
    rules = load_rules()
    assert set(rules.capabilities) == set(Capability)


@pytest.mark.parametrize("cap", sorted(WORLD_ACTING_CAPABILITIES))
def test_world_acting_capabilities_have_containment_at_every_granted_level(cap):
    rules = load_rules()
    for level in (Level.LIMITED, Level.FULL):
        reqs = [r for r, _ in rules[cap].effective(level)]
        assert any(r.containment for r in reqs)
        assert all(r.classes == (EvidenceClass.CONTAINMENT_TEST,) for r in reqs if r.containment)


def test_levels_are_cumulative():
    cap_rules = load_rules()[Capability.CODE_EXECUTION]
    limited = [r.id for r, _ in cap_rules.effective(Level.LIMITED)]
    full = [r.id for r, _ in cap_rules.effective(Level.FULL)]
    assert full[: len(limited)] == limited
    assert len(full) > len(limited)
    assert cap_rules.effective(Level.NONE) == []


def test_monitor_shorthand():
    reqs = {r.id: r for r, _ in load_rules()[Capability.CODE_EXECUTION].effective(Level.FULL)}
    mon = reqs["exec.monitor"]
    assert mon.classes == (EvidenceClass.MONITOR_HEALTH,)
    assert mon.match == {"monitor_name": "sandbox-monitor"}


def test_containment_requirement_cannot_accept_behavioural_evidence(raw):
    req = raw["capabilities"]["network_out"]["limited"][1]
    req["classes"] = ["containment_test", "eval_result"]
    with pytest.raises(RuleError, match="only be satisfied by containment_test"):
        parse_rules(raw)


def test_world_acting_capability_without_containment_is_rejected(raw):
    caps = raw["capabilities"]
    caps["network_out"]["limited"] = [r for r in caps["network_out"]["limited"] if not r.get("containment")]
    with pytest.raises(RuleError, match="network_out acts on the world"):
        parse_rules(raw)


def test_budget_does_not_need_containment(raw):
    assert not any(r.get("containment") for lvl in raw["capabilities"]["budget"].values() for r in lvl)
    parse_rules(raw)


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda c: c.pop("delegation"), "no rules for capability delegation"),
        (lambda c: c.update(teleport={}), "unknown capabilities"),
        (lambda c: c["budget"].update(none=[]), "only 'limited' and 'full'"),
        (lambda c: c["budget"]["limited"][0].update(min={"pass_rat": 0.5}), "no metric 'pass_rat'"),
        (lambda c: c["budget"]["limited"][0].update(min={"pass_rate": "high"}), "needs a number"),
        (lambda c: c["budget"]["limited"][0].update(max_age_days=0), "positive"),
        (lambda c: c["budget"]["limited"][0].update(colour="red"), "unknown fields"),
        (lambda c: c["budget"]["limited"][0].update(classes=["gossip"]), "gossip"),
        (lambda c: c["budget"]["limited"][0].pop("id"), "needs an id"),
        (lambda c: c["budget"]["full"][0].update(id="budget.eval"), "duplicate requirement id"),
        (lambda c: c["read_data"]["full"][0].update(max={"residual_risk": "tiny"}), "must be one of"),
        (lambda c: c["budget"]["full"][0].update(classes=["eval_result"]), "only take monitor_health"),
    ],
)
def test_invalid_rules_are_rejected(raw, mutate, fragment):
    raw = copy.deepcopy(raw)
    mutate(raw["capabilities"])
    with pytest.raises(RuleError, match=fragment):
        parse_rules(raw)


def test_load_rules_from_file(tmp_path, raw):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(raw))
    assert set(load_rules(path).capabilities) == set(Capability)
    path.write_text("{not json")
    with pytest.raises(RuleError, match="not valid JSON"):
        load_rules(path)
