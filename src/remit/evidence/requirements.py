# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""Capability requirements: which evidence each capability level needs.

The requirements live in a data file, not in code. ``requirements.yaml`` is
the source of truth and carries the reasoning for every value as comments.
``requirements.json`` is generated from it (``make rules-json``) so that the
demo and the tests never depend on the YAML parser. A test keeps the two in
step.

Loading validates the standing rules:

* a containment requirement may name containment_test and nothing else;
* every world-acting capability has at least one containment requirement at
  limited and at full;
* no capability reaches full on a single evidence class;
* every full level needs a human_attestation;
* every requirement that accepts eval_result names the suites that count, and
  every one that accepts red_team_report names the exercises that count;
* no requirement accepts older evidence than the class age limit allows;
* monitor dependencies are declared per level, by name, against a monitor
  definition that says what healthy means, and full depends on every monitor
  that limited depends on.

Levels are cumulative for evidence requirements: full needs everything
limited needs, plus its own. Monitor dependencies are not inherited; each
level lists its monitors explicitly.

Independence is judged per level. The ``independence`` table sets the least
independent source each class may come from at each level, and it applies to
every requirement evaluated at that level, including those inherited from
limited. A requirement may ask for more with ``min_independence``.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from .admission import CONTAINMENT_BOUNDARIES, RISK_LEVELS, metric_kinds
from .model import SOURCE_ROLES, WORLD_ACTING_CAPABILITIES, Capability, EvidenceClass, Level

NUMERIC_KINDS = {"fraction", "count", "seconds"}
ORDERED_KINDS = NUMERIC_KINDS | {"risk"}
MATCH_KINDS = {"text", "risk", "monitor_state"}
# ``includes`` on a list field (boundaries) means the evidence must cover every
# named value; on a text field (suite, exercise) it means the evidence's value
# must be one of the named values.
INCLUDES_KINDS = {"boundaries", "text"}
# Classes whose requirements must name what counts, and the field that names it.
PINNED_FIELDS = {EvidenceClass.EVAL_RESULT: "suite", EvidenceClass.RED_TEAM_REPORT: "exercise"}
GRANTED_LEVELS = (Level.LIMITED, Level.FULL)
PACKAGE = "remit.evidence"


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Monitor:
    name: str
    description: str
    heartbeat_timeout_seconds: float
    min_effectiveness: float

    @property
    def healthy(self) -> str:
        return (
            f"reports healthy, last heartbeat within {_fmt(self.heartbeat_timeout_seconds)} seconds, "
            f"effectiveness at least {_fmt(self.min_effectiveness)}"
        )


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
    min_independence: str | None = None
    # Set only on the monitor requirements generated from a level's monitor list.
    monitor: Monitor | None = None


@dataclass(frozen=True)
class CapabilityRules:
    capability: Capability
    levels: Mapping[Level, tuple[Requirement, ...]]
    monitors: Mapping[Level, tuple[Requirement, ...]]

    def own(self, level: Level) -> tuple[Requirement, ...]:
        return self.levels.get(level, ())

    def effective(self, level: Level) -> list[tuple[Requirement, Level]]:
        """All requirements for ``level``, each paired with the level that introduced it."""
        out = []
        for lvl in GRANTED_LEVELS:
            if lvl.rank > level.rank:
                break
            out.extend((req, lvl) for req in self.own(lvl))
        for req in self.monitors.get(level, ()):
            first = next(lvl for lvl in GRANTED_LEVELS if req in self.monitors.get(lvl, ()))
            out.append((req, first))
        return out


@dataclass(frozen=True)
class RuleSet:
    capabilities: Mapping[Capability, CapabilityRules]
    age_limits: Mapping[EvidenceClass, float]
    monitors: Mapping[str, Monitor]
    # Least independent source role each class may come from, per level.
    independence: Mapping[Level, Mapping[EvidenceClass, str]] = field(default_factory=dict)

    def __getitem__(self, capability: Capability) -> CapabilityRules:
        return self.capabilities[capability]

    def required_independence(self, requirement: Requirement, cls: EvidenceClass, level: Level) -> str:
        """The least independent source role that counts for this requirement at this level."""
        floor = self.independence.get(level, {}).get(cls, SOURCE_ROLES[0])
        own = requirement.min_independence or SOURCE_ROLES[0]
        return max(floor, own, key=SOURCE_ROLES.index)


def yaml_available() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


def bundled_rules_text(fmt: str) -> str:
    name = {"yaml": "requirements.yaml", "json": "requirements.json"}[fmt]
    return resources.files(PACKAGE).joinpath(name).read_text()


def _parse_text(text: str, fmt: str) -> Mapping[str, Any]:
    if fmt == "json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuleError(f"requirements file is not valid JSON: {exc}") from exc
    import yaml  # imported here so that JSON users never need it

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"requirements file is not valid YAML: {exc}") from exc
    if not isinstance(data, Mapping):
        raise RuleError("requirements file must hold a mapping at the top level")
    return data


def load_rules(path: str | Path | None = None, *, fmt: str | None = None) -> RuleSet:
    """Load requirements from ``path``, or the bundled file.

    For the bundled file, ``fmt`` picks "yaml" or "json". It defaults to YAML
    when PyYAML is installed and JSON otherwise.
    """
    if path is None:
        fmt = fmt or ("yaml" if yaml_available() else "json")
        return parse_rules(_parse_text(bundled_rules_text(fmt), fmt))
    path = Path(path)
    if fmt is None:
        fmt = "json" if path.suffix == ".json" else "yaml"
    return parse_rules(_parse_text(path.read_text(), fmt))


def parse_rules(data: Mapping[str, Any]) -> RuleSet:
    data = {k: v for k, v in data.items() if not str(k).startswith("_")}
    unknown_top = set(data) - {"version", "age_limits", "independence", "monitors", "capabilities"}
    if unknown_top:
        raise RuleError(f"unknown top level fields: {', '.join(sorted(unknown_top))}")

    age_limits = _parse_age_limits(data.get("age_limits") or {})
    independence = _parse_independence(data.get("independence") or {})
    monitors = _parse_monitors(data.get("monitors") or {})

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
        cap_rules = _parse_capability(capability, caps[capability.value], age_limits, monitors, seen_ids)
        rules[capability] = cap_rules
    return RuleSet(rules, age_limits, monitors, independence)


def _parse_independence(raw: Mapping[str, Any]) -> dict[Level, dict[EvidenceClass, str]]:
    out: dict[Level, dict[EvidenceClass, str]] = {}
    for level_name, table in raw.items():
        if level_name not in {lvl.value for lvl in GRANTED_LEVELS}:
            raise RuleError(f"independence: only 'limited' and 'full' take floors, got {level_name!r}")
        level = Level(level_name)
        out[level] = {}
        for cls_name, role in (table or {}).items():
            try:
                cls = EvidenceClass(cls_name)
            except ValueError as exc:
                raise RuleError(f"independence.{level_name}: {exc}") from exc
            if role not in SOURCE_ROLES:
                raise RuleError(
                    f"independence.{level_name}.{cls_name}: must be one of {', '.join(SOURCE_ROLES)}"
                )
            out[level][cls] = role
    return out


def _parse_age_limits(raw: Mapping[str, Any]) -> dict[EvidenceClass, float]:
    limits = {}
    for key, value in raw.items():
        try:
            cls = EvidenceClass(key)
        except ValueError as exc:
            raise RuleError(f"age_limits: {exc}") from exc
        if cls is EvidenceClass.MONITOR_HEALTH:
            raise RuleError("age_limits: monitor_health freshness is set by each monitor's heartbeat timeout")
        if not _positive(value):
            raise RuleError(f"age_limits: {key} must be a positive number of days")
        limits[cls] = value
    return limits


def _parse_monitors(raw: Mapping[str, Any]) -> dict[str, Monitor]:
    monitors = {}
    for name, spec in raw.items():
        spec = spec or {}
        extra = set(spec) - {"description", "heartbeat_timeout_seconds", "min_effectiveness"}
        if extra:
            raise RuleError(f"monitor {name}: unknown fields {', '.join(sorted(extra))}")
        timeout = spec.get("heartbeat_timeout_seconds")
        if not _positive(timeout):
            raise RuleError(f"monitor {name}: heartbeat_timeout_seconds must be a positive number")
        eff = spec.get("min_effectiveness")
        if not isinstance(eff, (int, float)) or isinstance(eff, bool) or not 0 <= eff <= 1:
            raise RuleError(f"monitor {name}: min_effectiveness must be a number between 0 and 1")
        monitors[name] = Monitor(name, spec.get("description", name), timeout, eff)
    return monitors


def _parse_capability(
    capability: Capability,
    levels_data: Mapping[str, Any],
    age_limits: Mapping[EvidenceClass, float],
    monitors: Mapping[str, Monitor],
    seen_ids: set[str],
) -> CapabilityRules:
    cap = capability.value
    bad_levels = set(levels_data) - {lvl.value for lvl in GRANTED_LEVELS}
    if bad_levels:
        raise RuleError(
            f"{cap}: only 'limited' and 'full' take requirements, got {', '.join(sorted(bad_levels))}"
        )
    levels: dict[Level, tuple[Requirement, ...]] = {}
    monitor_names: dict[Level, tuple[str, ...]] = {}
    for level in GRANTED_LEVELS:
        where = f"{cap}.{level.value}"
        level_data = levels_data.get(level.value)
        if not isinstance(level_data, Mapping):
            raise RuleError(f"{where}: needs a mapping with 'monitors' and 'requirements'")
        extra = set(level_data) - {"monitors", "requirements"}
        if extra:
            raise RuleError(f"{where}: unknown fields {', '.join(sorted(extra))}")
        if "monitors" not in level_data:
            raise RuleError(f"{where}: must list its monitors explicitly, as [] if it depends on none")
        names = tuple(level_data["monitors"] or ())
        for name in names:
            if name not in monitors:
                raise RuleError(f"{where}: monitor '{name}' is not defined under 'monitors'")
        if len(set(names)) != len(names):
            raise RuleError(f"{where}: lists a monitor twice")
        monitor_names[level] = names
        reqs = tuple(
            _parse_requirement(where, raw, age_limits) for raw in level_data.get("requirements") or ()
        )
        for req in reqs:
            if req.id in seen_ids:
                raise RuleError(f"duplicate requirement id {req.id}")
            seen_ids.add(req.id)
        levels[level] = reqs

    missing = set(monitor_names[Level.LIMITED]) - set(monitor_names[Level.FULL])
    if missing:
        raise RuleError(
            f"{cap}.full must also depend on {', '.join(sorted(missing))}, because limited does"
        )

    generated: dict[str, Requirement] = {}
    monitor_reqs: dict[Level, tuple[Requirement, ...]] = {}
    for level in GRANTED_LEVELS:
        out = []
        for name in monitor_names[level]:
            if name not in generated:
                mon = monitors[name]
                generated[name] = Requirement(
                    id=f"{cap}.monitor.{name}",
                    description=f"Monitor '{name}' is healthy ({mon.description})",
                    classes=(EvidenceClass.MONITOR_HEALTH,),
                    match={"monitor_name": name},
                    minimum={"effectiveness": mon.min_effectiveness},
                    monitor=mon,
                )
            out.append(generated[name])
        monitor_reqs[level] = tuple(out)

    cap_rules = CapabilityRules(capability, levels, monitor_reqs)

    if capability in WORLD_ACTING_CAPABILITIES:
        for level in GRANTED_LEVELS:
            if not any(req.containment for req, _ in cap_rules.effective(level)):
                raise RuleError(
                    f"{cap} acts on the world, so {level.value} needs at least one containment requirement"
                )
    full = [req for req, _ in cap_rules.effective(Level.FULL)]
    if not full:
        raise RuleError(f"{cap}.full has no requirements")
    if not any(EvidenceClass.HUMAN_ATTESTATION in r.classes for r in full):
        raise RuleError(
            f"{cap}.full needs a human_attestation requirement: full is unrestricted authority"
        )
    common = set.intersection(*(set(r.classes) for r in full))
    if common:
        raise RuleError(
            f"{cap}.full could be reached on {', '.join(sorted(c.value for c in common))} alone; "
            "full must need at least two evidence classes"
        )
    return cap_rules


REQUIREMENT_FIELDS = {
    "id", "description", "classes", "containment", "min", "max", "match", "includes", "max_age_days",
    "min_independence",
}


def _parse_requirement(
    level_where: str, raw: Mapping[str, Any], age_limits: Mapping[EvidenceClass, float]
) -> Requirement:
    req_id = raw.get("id")
    if not req_id:
        raise RuleError(f"{level_where}: every requirement needs an id")
    where = f"{level_where}.{req_id}"
    if "monitor" in raw:
        raise RuleError(f"{where}: declare monitor dependencies in the level's 'monitors' list")
    extra = set(raw) - REQUIREMENT_FIELDS
    if extra:
        raise RuleError(f"{where}: unknown fields {', '.join(sorted(extra))}")

    classes_raw = raw.get("classes")
    if not classes_raw:
        raise RuleError(f"{where}: needs at least one evidence class")
    try:
        classes = tuple(EvidenceClass(c) for c in classes_raw)
    except ValueError as exc:
        raise RuleError(f"{where}: {exc}") from exc
    if EvidenceClass.MONITOR_HEALTH in classes:
        raise RuleError(f"{where}: monitor_health is required through the level's 'monitors' list")

    containment = bool(raw.get("containment", False))
    if containment and classes != (EvidenceClass.CONTAINMENT_TEST,):
        raise RuleError(
            f"{where}: a containment requirement can only be satisfied by containment_test "
            "evidence; behavioural evidence never substitutes for it"
        )

    minimum = dict(raw.get("min") or {})
    maximum = dict(raw.get("max") or {})
    match = dict(raw.get("match") or {})
    includes = {k: tuple(v) for k, v in dict(raw.get("includes") or {}).items()}
    for key, value in minimum.items():
        _check_metric(where, classes, key, value, ORDERED_KINDS, "min")
    for key, value in maximum.items():
        _check_metric(where, classes, key, value, ORDERED_KINDS, "max")
    for key, value in match.items():
        _check_metric(where, classes, key, value, MATCH_KINDS, "match")
    for key, value in includes.items():
        _check_metric(where, classes, key, value, INCLUDES_KINDS, "includes")
    for cls, pinned in PINNED_FIELDS.items():
        if cls in classes and not includes.get(pinned):
            raise RuleError(
                f"{where}: accepts {cls.value}, so it must name the {pinned}s that count "
                f"with 'includes: {pinned}: [...]'"
            )

    min_independence = raw.get("min_independence")
    if min_independence is not None and min_independence not in SOURCE_ROLES:
        raise RuleError(f"{where}: min_independence must be one of {', '.join(SOURCE_ROLES)}")

    max_age = raw.get("max_age_days")
    if max_age is not None and not _positive(max_age):
        raise RuleError(f"{where}: max_age_days must be a positive number")
    unlimited = [c.value for c in classes if c not in age_limits]
    limits = [age_limits[c] for c in classes if c in age_limits]
    if max_age is None:
        if unlimited:
            raise RuleError(
                f"{where}: {', '.join(unlimited)} has no class age limit, so max_age_days must be set"
            )
        max_age = min(limits)
    elif limits and max_age > min(limits):
        raise RuleError(
            f"{where}: max_age_days {_fmt(max_age)} is looser than the class age limit of {_fmt(min(limits))}"
        )

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
        min_independence=min_independence,
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
        if kind in NUMERIC_KINDS and (not isinstance(value, (int, float)) or isinstance(value, bool)):
            raise RuleError(f"{where}: '{key}' needs a number")
        if kind == "risk" and value not in RISK_LEVELS:
            raise RuleError(f"{where}: '{key}' must be one of {', '.join(RISK_LEVELS)}")
        if kind == "boundaries" and (
            not value or any(b not in CONTAINMENT_BOUNDARIES for b in value)
        ):
            raise RuleError(f"{where}: '{key}' must list known boundaries")
        if constraint == "includes" and kind == "text" and (
            not value or not all(isinstance(v, str) and v for v in value)
        ):
            raise RuleError(f"{where}: '{key}' must list the names that count")


def _positive(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _fmt(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


JSON_HEADER = {
    "_licence": "SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors.",
    "_generated": "Generated from requirements.yaml by 'make rules-json'. Do not edit by hand; "
    "the reasoning for each value is in the YAML comments.",
}


def export_json() -> str:
    """Render the bundled YAML as the JSON mirror."""
    data = _parse_text(bundled_rules_text("yaml"), "yaml")
    return json.dumps({**JSON_HEADER, **data}, indent=2) + "\n"


def main() -> int:
    target = Path(__file__).with_name("requirements.json")
    text = export_json()
    parse_rules(json.loads(text))
    target.write_text(text)
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
