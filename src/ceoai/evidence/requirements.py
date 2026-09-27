# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The CEOAI contributors
"""Capability requirements: which evidence each capability level needs.

The requirements live in a data file (``requirements.json`` by default), not
in code. Loading validates the standing rules:

* a containment requirement may name containment_test and nothing else;
* every world-acting capability has at least one containment requirement at
  limited and at full;
* every constrained metric exists for every class the requirement accepts.

Levels are cumulative: full needs everything limited needs, plus its own.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from .admission import CONTAINMENT_BOUNDARIES, RISK_LEVELS, metric_kinds
from .model import WORLD_ACTING_CAPABILITIES, Capability, EvidenceClass, Level

NUMERIC_KINDS = {"fraction", "count", "seconds"}
ORDERED_KINDS = NUMERIC_KINDS | {"risk"}
MATCH_KINDS = {"text", "risk", "monitor_state"}


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Requirement:
    id: str
    description: str
    classes: tuple[EvidenceClass, ...]
    containment: bool = False
    minimum: Mapping[str, Any] = field(default_factory=dict)
    maximum: Mapping[str, Any] = field(default_factory=dict)
    match: Mapping[str, Any] = field(default_factory=dict)
    includes: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    max_age_days: float | None = None
    monitor: str | None = None


@dataclass(frozen=True)
class CapabilityRules:
    capability: Capability
    levels: Mapping[Level, tuple[Requirement, ...]]

    def own(self, level: Level) -> tuple[Requirement, ...]:
        return self.levels.get(level, ())

    def effective(self, level: Level) -> list[tuple[Requirement, Level]]:
        """All requirements for ``level``, each paired with the level that introduced it."""
        out = []
        for lvl in (Level.LIMITED, Level.FULL):
            if lvl.rank > level.rank:
                break
            out.extend((req, lvl) for req in self.own(lvl))
        return out


@dataclass(frozen=True)
class RuleSet:
    capabilities: Mapping[Capability, CapabilityRules]

    def __getitem__(self, capability: Capability) -> CapabilityRules:
        return self.capabilities[capability]


def default_rules_text() -> str:
    return resources.files("ceoai.evidence").joinpath("requirements.json").read_text()


def load_rules(path: str | Path | None = None) -> RuleSet:
    text = default_rules_text() if path is None else Path(path).read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuleError(f"requirements file is not valid JSON: {exc}") from exc
    return parse_rules(data)


def parse_rules(data: Mapping[str, Any]) -> RuleSet:
    caps = data.get("capabilities")
    if not isinstance(caps, Mapping):
        raise RuleError("requirements file needs a 'capabilities' mapping")
    unknown = set(caps) - {c.value for c in Capability}
    if unknown:
        raise RuleError(f"unknown capabilities: {', '.join(sorted(unknown))}")
    rules: dict[Capability, CapabilityRules] = {}
    seen_ids: set[str] = set()
    for capability in Capability:
        if capability.value not in caps:
            raise RuleError(f"no rules for capability {capability.value}")
        levels_data = caps[capability.value]
        bad_levels = set(levels_data) - {Level.LIMITED.value, Level.FULL.value}
        if bad_levels:
            raise RuleError(
                f"{capability.value}: only 'limited' and 'full' take requirements, "
                f"got {', '.join(sorted(bad_levels))}"
            )
        levels = {}
        for level in (Level.LIMITED, Level.FULL):
            reqs = tuple(
                _parse_requirement(capability, level, raw) for raw in levels_data.get(level.value, [])
            )
            for req in reqs:
                if req.id in seen_ids:
                    raise RuleError(f"duplicate requirement id {req.id}")
                seen_ids.add(req.id)
            levels[level] = reqs
        cap_rules = CapabilityRules(capability, levels)
        if capability in WORLD_ACTING_CAPABILITIES:
            for level in (Level.LIMITED, Level.FULL):
                if not any(req.containment for req, _ in cap_rules.effective(level)):
                    raise RuleError(
                        f"{capability.value} acts on the world, so {level.value} needs at least "
                        "one containment requirement"
                    )
        rules[capability] = cap_rules
    return RuleSet(rules)


def _parse_requirement(capability: Capability, level: Level, raw: Mapping[str, Any]) -> Requirement:
    where = f"{capability.value}.{level.value}"
    req_id = raw.get("id")
    if not req_id:
        raise RuleError(f"{where}: every requirement needs an id")
    where = f"{where}.{req_id}"
    allowed = {
        "id", "description", "classes", "containment", "min", "max", "match",
        "includes", "max_age_days", "monitor",
    }
    extra = set(raw) - allowed
    if extra:
        raise RuleError(f"{where}: unknown fields {', '.join(sorted(extra))}")

    monitor = raw.get("monitor")
    match = dict(raw.get("match", {}))
    if monitor:
        classes_raw = raw.get("classes", [EvidenceClass.MONITOR_HEALTH.value])
        match.setdefault("monitor_name", monitor)
    else:
        classes_raw = raw.get("classes")
    if not classes_raw:
        raise RuleError(f"{where}: needs at least one evidence class")
    try:
        classes = tuple(EvidenceClass(c) for c in classes_raw)
    except ValueError as exc:
        raise RuleError(f"{where}: {exc}") from exc
    if monitor and classes != (EvidenceClass.MONITOR_HEALTH,):
        raise RuleError(f"{where}: a monitor requirement can only take monitor_health evidence")

    containment = bool(raw.get("containment", False))
    if containment and classes != (EvidenceClass.CONTAINMENT_TEST,):
        raise RuleError(
            f"{where}: a containment requirement can only be satisfied by containment_test "
            "evidence; behavioural evidence never substitutes for it"
        )

    minimum = dict(raw.get("min", {}))
    maximum = dict(raw.get("max", {}))
    includes = {k: tuple(v) for k, v in dict(raw.get("includes", {})).items()}
    for key, value in minimum.items():
        _check_metric(where, classes, key, value, ORDERED_KINDS, "min")
    for key, value in maximum.items():
        _check_metric(where, classes, key, value, ORDERED_KINDS, "max")
    for key, value in match.items():
        _check_metric(where, classes, key, value, MATCH_KINDS, "match")
    for key, value in includes.items():
        _check_metric(where, classes, key, value, {"boundaries"}, "includes")

    max_age = raw.get("max_age_days")
    if max_age is not None and (not isinstance(max_age, (int, float)) or max_age <= 0):
        raise RuleError(f"{where}: max_age_days must be a positive number")

    return Requirement(
        id=req_id,
        description=raw.get("description", req_id),
        classes=classes,
        containment=containment,
        minimum=minimum,
        maximum=maximum,
        match=match,
        includes=includes,
        max_age_days=max_age,
        monitor=monitor,
    )


def _check_metric(
    where: str,
    classes: tuple[EvidenceClass, ...],
    key: str,
    value: Any,
    kinds: set[str],
    constraint: str,
) -> None:
    for cls in classes:
        kind = metric_kinds(cls).get(key)
        if kind is None:
            raise RuleError(f"{where}: {cls.value} evidence has no metric '{key}'")
        if kind not in kinds:
            raise RuleError(f"{where}: '{key}' cannot be used in '{constraint}'")
        if kind in NUMERIC_KINDS and not isinstance(value, (int, float)):
            raise RuleError(f"{where}: '{key}' needs a number")
        if kind == "risk" and value not in RISK_LEVELS:
            raise RuleError(f"{where}: '{key}' must be one of {', '.join(RISK_LEVELS)}")
        if kind == "boundaries" and (
            not value or any(b not in CONTAINMENT_BOUNDARIES for b in value)
        ):
            raise RuleError(f"{where}: '{key}' must list known boundaries")
