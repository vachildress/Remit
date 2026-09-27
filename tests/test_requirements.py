# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

import copy
import json
import sys

import pytest
import yaml

from remit.evidence.model import WORLD_ACTING_CAPABILITIES, Capability, EvidenceClass, Level
from remit.evidence.requirements import (
    RuleError,
    bundled_rules_text,
    export_json,
    load_rules,
    parse_rules,
)

CLASS_AGE_LIMITS = {
    EvidenceClass.EVAL_RESULT: 30,
    EvidenceClass.RED_TEAM_REPORT: 90,
    EvidenceClass.CONTAINMENT_TEST: 30,
    EvidenceClass.HUMAN_ATTESTATION: 90,
}


@pytest.fixture
def raw():
    return yaml.safe_load(bundled_rules_text("yaml"))


def strip(data):
    return {k: v for k, v in data.items() if not k.startswith("_")}


def test_bundled_yaml_and_json_load_and_cover_every_capability():
    for fmt in ("yaml", "json"):
        rules = load_rules(fmt=fmt)
        assert set(rules.capabilities) == set(Capability)


def test_json_mirror_is_in_step_with_yaml(raw):
    mirror = json.loads(bundled_rules_text("json"))
    assert strip(mirror) == raw, "requirements.json is stale: run `make rules-json`"
    assert json.loads(export_json()) == mirror


def test_json_loader_works_without_pyyaml(monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    rules = load_rules()  # falls back to the JSON mirror
    assert set(rules.capabilities) == set(Capability)
    with pytest.raises(ImportError):
        load_rules(fmt="yaml")


@pytest.mark.parametrize("cap", sorted(WORLD_ACTING_CAPABILITIES))
def test_world_acting_capabilities_have_containment_at_every_granted_level(cap):
    rules = load_rules()
    for level in (Level.LIMITED, Level.FULL):
        reqs = [r for r, _ in rules[cap].effective(level)]
        assert any(r.containment for r in reqs)
        assert all(r.classes == (EvidenceClass.CONTAINMENT_TEST,) for r in reqs if r.containment)


@pytest.mark.parametrize("cap", list(Capability))
def test_no_capability_reaches_full_on_one_class(cap):
    reqs = [r for r, _ in load_rules()[cap].effective(Level.FULL)]
    assert len({c for r in reqs for c in r.classes}) >= 2
    assert not set.intersection(*(set(r.classes) for r in reqs))


@pytest.mark.parametrize("cap", list(Capability))
def test_every_requirement_respects_the_class_age_limits(cap):
    rules = load_rules()
    assert dict(rules.age_limits) == CLASS_AGE_LIMITS
    for level in (Level.LIMITED, Level.FULL):
        for req, _ in rules[cap].effective(level):
            if req.monitor is not None:
                assert req.max_age_days is None
                continue
            assert req.max_age_days is not None
            assert req.max_age_days <= min(CLASS_AGE_LIMITS[c] for c in req.classes)


def test_every_level_names_its_monitors_explicitly(raw):
    for cap, levels in raw["capabilities"].items():
        for level in ("limited", "full"):
            assert "monitors" in levels[level], f"{cap}.{level}"


def test_monitor_requirements_state_what_healthy_means():
    rules = load_rules()
    reqs = {r.id: r for r, _ in rules[Capability.CODE_EXECUTION].effective(Level.FULL)}
    mon = reqs["code_execution.monitor.sandbox-monitor"]
    assert mon.classes == (EvidenceClass.MONITOR_HEALTH,)
    assert mon.match == {"monitor_name": "sandbox-monitor"}
    assert mon.minimum == {"effectiveness": 0.9}
    assert mon.monitor.heartbeat_timeout_seconds == 60
    assert "heartbeat within 60 seconds" in mon.monitor.healthy
    # Not a dependency of limited.
    assert all(r.monitor is None for r, _ in rules[Capability.CODE_EXECUTION].effective(Level.LIMITED))


def test_monitor_listed_at_both_levels_is_introduced_at_limited():
    rules = load_rules()
    pairs = rules[Capability.REPO_WRITE].effective(Level.FULL)
    [(req, introduced)] = [(r, lvl) for r, lvl in pairs if r.monitor is not None]
    assert req.monitor.name == "test-tamper-sensor" and introduced is Level.LIMITED


def test_levels_are_cumulative_for_evidence_requirements():
    cap_rules = load_rules()[Capability.CODE_EXECUTION]
    limited = [r.id for r, _ in cap_rules.effective(Level.LIMITED)]
    full = [r.id for r, _ in cap_rules.effective(Level.FULL)]
    assert full[: len(limited)] == limited
    assert cap_rules.effective(Level.NONE) == []


def test_containment_requirement_cannot_accept_behavioural_evidence(raw):
    req = raw["capabilities"]["network_out"]["limited"]["requirements"][1]
    req["classes"] = ["containment_test", "eval_result"]
    with pytest.raises(RuleError, match="only be satisfied by containment_test"):
        parse_rules(raw)


def test_world_acting_capability_without_containment_is_rejected(raw):
    lim = raw["capabilities"]["network_out"]["limited"]
    lim["requirements"] = [r for r in lim["requirements"] if not r.get("containment")]
    with pytest.raises(RuleError, match="network_out acts on the world"):
        parse_rules(raw)


def test_full_on_a_single_class_is_rejected(raw):
    # Make every read_data requirement a human attestation, so full would rest
    # on that one class.
    read = raw["capabilities"]["read_data"]
    read["limited"]["requirements"] = [{"id": "read.only", "classes": ["human_attestation"], "max_age_days": 90}]
    read["full"]["requirements"] = [r for r in read["full"]["requirements"] if r["id"] == "read.attest"]
    with pytest.raises(RuleError, match="human_attestation alone"):
        parse_rules(raw)


def test_full_without_attestation_is_rejected(raw):
    full = raw["capabilities"]["network_out"]["full"]
    full["requirements"] = [r for r in full["requirements"] if r["id"] != "net.attest"]
    with pytest.raises(RuleError, match="network_out.full needs a human_attestation requirement"):
        parse_rules(raw)


@pytest.mark.parametrize("cap", list(Capability))
def test_every_full_level_needs_an_attestation(cap):
    reqs = [r for r, _ in load_rules()[cap].effective(Level.FULL)]
    assert any(EvidenceClass.HUMAN_ATTESTATION in r.classes for r in reqs)


def test_code_execution_full_needs_a_clean_red_team():
    reqs = {r.id: r for r, _ in load_rules()[Capability.CODE_EXECUTION].effective(Level.FULL)}
    red = reqs["exec.redteam"]
    assert red.maximum == {"residual_risk": "low", "findings_open": 0}
    assert red.includes == {"exercise": ("synthetic-sandbox-escape-exercise-v1",)}


@pytest.mark.parametrize("cap", list(Capability))
def test_eval_and_red_team_requirements_are_pinned(cap):
    for req, _ in load_rules()[cap].effective(Level.FULL):
        if EvidenceClass.EVAL_RESULT in req.classes:
            assert req.includes.get("suite")
        if EvidenceClass.RED_TEAM_REPORT in req.classes:
            assert req.includes.get("exercise")


@pytest.mark.parametrize(
    "rid, cls, field",
    [("budget.eval", "eval_result", "suite"), ("read.redteam", "red_team_report", "exercise")],
)
def test_unpinned_requirement_is_rejected(raw, rid, cls, field):
    for levels in raw["capabilities"].values():
        for level in levels.values():
            for req in level["requirements"]:
                if req["id"] == rid:
                    req["includes"].pop(field)
    with pytest.raises(RuleError, match=f"accepts {cls}, so it must name the {field}s that count"):
        parse_rules(raw)


def test_independence_floor_applies_at_full_only():
    rules = load_rules()
    [req] = [r for r, _ in rules[Capability.WRITE_DATA].effective(Level.LIMITED) if r.containment]
    assert rules.required_independence(req, EvidenceClass.CONTAINMENT_TEST, Level.LIMITED) == "developer"
    assert rules.required_independence(req, EvidenceClass.CONTAINMENT_TEST, Level.FULL) == "internal_independent"


def test_requirement_can_ask_for_more_independence_than_the_floor(raw):
    raw["capabilities"]["read_data"]["full"]["requirements"][0]["min_independence"] = "external"
    rules = parse_rules(raw)
    req = next(r for r, _ in rules[Capability.READ_DATA].effective(Level.FULL) if r.id == "read.redteam")
    assert rules.required_independence(req, EvidenceClass.RED_TEAM_REPORT, Level.FULL) == "external"


def test_looser_age_than_class_limit_is_rejected(raw):
    raw["capabilities"]["budget"]["limited"]["requirements"][0]["max_age_days"] = 31
    with pytest.raises(RuleError, match="looser than the class age limit of 30"):
        parse_rules(raw)


def test_missing_age_inherits_class_limit(raw):
    raw["capabilities"]["budget"]["limited"]["requirements"][0].pop("max_age_days")
    [(req, _)] = parse_rules(raw)[Capability.BUDGET].effective(Level.LIMITED)
    assert req.max_age_days == 30


def test_class_without_age_limit_needs_explicit_age(raw):
    reqs = raw["capabilities"]["budget"]["full"]["requirements"]
    reqs.append({"id": "budget.tier", "classes": ["standards_evidence"]})
    with pytest.raises(RuleError, match="standards_evidence has no class age limit"):
        parse_rules(raw)
    reqs[-1]["max_age_days"] = 365
    parse_rules(raw)


def test_full_must_keep_limited_monitors(raw):
    raw["capabilities"]["repo_write"]["full"]["monitors"] = []
    with pytest.raises(RuleError, match="repo_write.full must also depend on test-tamper-sensor"):
        parse_rules(raw)


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda d: d["capabilities"].pop("delegation"), "no rules for capability delegation"),
        (lambda d: d["capabilities"].update(teleport={}), "unknown capabilities"),
        (lambda d: d.update(colour="red"), "unknown top level fields"),
        (lambda d: d["capabilities"]["budget"].update(none={}), "only 'limited' and 'full'"),
        (lambda d: d["capabilities"]["budget"]["limited"].pop("monitors"), "list its monitors explicitly"),
        (lambda d: d["capabilities"]["budget"]["full"].update(monitors=["ghost"]), "'ghost' is not defined"),
        (lambda d: d["capabilities"]["budget"]["full"].update(monitors=["budget-meter"] * 2), "twice"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(monitor="budget-meter"),
         "declare monitor dependencies"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(classes=["monitor_health"]),
         "through the level's 'monitors' list"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(min={"pass_rat": 0.5}),
         "no metric 'pass_rat'"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(min={"pass_rate": "high"}),
         "needs a number"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(max_age_days=0), "positive"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(colour="red"), "unknown fields"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(classes=["gossip"]), "gossip"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].pop("id"), "needs an id"),
        (lambda d: d["capabilities"]["budget"]["full"]["requirements"][0].update(id="budget.eval"),
         "duplicate requirement id"),
        (lambda d: d["capabilities"]["read_data"]["full"]["requirements"][0].update(max={"residual_risk": "tiny"}),
         "must be one of"),
        (lambda d: d["age_limits"].update(monitor_health=1), "heartbeat timeout"),
        (lambda d: d["age_limits"].update(eval_result=0), "positive number of days"),
        (lambda d: d["monitors"]["budget-meter"].update(heartbeat_timeout_seconds=0), "heartbeat_timeout_seconds"),
        (lambda d: d["monitors"]["budget-meter"].update(min_effectiveness=2), "min_effectiveness"),
        (lambda d: d["independence"].update(none={}), "only 'limited' and 'full' take floors"),
        (lambda d: d["independence"]["full"].update(containment_test="friend"), "must be one of developer"),
        (lambda d: d["capabilities"]["budget"]["limited"]["requirements"][0].update(min_independence="friend"),
         "min_independence must be one of"),
    ],
)
def test_invalid_rules_are_rejected(raw, mutate, fragment):
    raw = copy.deepcopy(raw)
    mutate(raw)
    with pytest.raises(RuleError, match=fragment):
        parse_rules(raw)


def test_load_rules_from_file(tmp_path, raw):
    for suffix, dump in ((".json", json.dumps), (".yaml", yaml.safe_dump)):
        path = tmp_path / f"rules{suffix}"
        path.write_text(dump(raw))
        assert set(load_rules(path).capabilities) == set(Capability)
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json")
    with pytest.raises(RuleError, match="not valid JSON"):
        load_rules(bad_json)
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("capabilities: [unclosed")
    with pytest.raises(RuleError, match="not valid YAML"):
        load_rules(bad_yaml)
