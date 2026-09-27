# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""Does the ledger currently support each level of a capability, and why?

This is the reasoning behind ``remit evidence explain``. It answers only from the
evidence and the requirements file. Grant policy (tier ceilings, expansion by
attestation, delegation) is applied on top of it by ``remit.policy``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .admission import RISK_LEVELS, assess, metric_kinds, strength_metrics
from .model import (
    LEVEL_ORDER,
    Capability,
    Evidence,
    EvidenceClass,
    Level,
    Subject,
    SOURCE_ROLES,
    format_timestamp,
    independence_rank,
    parse_timestamp,
    utc,
)
from .requirements import Requirement, RuleSet

BEHAVIOURAL_CLASSES = (EvidenceClass.EVAL_RESULT, EvidenceClass.RED_TEAM_REPORT)


@dataclass(frozen=True)
class Rejection:
    evidence: Evidence
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RequirementOutcome:
    requirement: Requirement
    introduced_at: Level
    satisfied_by: tuple[Evidence, ...]
    rejected: tuple[Rejection, ...]
    remedy: str
    # Evidence of an accepted class that is not scoped to this capability.
    out_of_scope: tuple[Evidence, ...] = ()

    @property
    def met(self) -> bool:
        return bool(self.satisfied_by)


@dataclass(frozen=True)
class LevelOutcome:
    level: Level
    requirements: tuple[RequirementOutcome, ...]

    @property
    def supported(self) -> bool:
        return all(r.met for r in self.requirements)


@dataclass(frozen=True)
class CapabilityExplanation:
    capability: Capability
    subject: Subject
    as_of: datetime
    levels: tuple[LevelOutcome, ...]

    @property
    def highest_supported(self) -> Level:
        best = Level.NONE
        for outcome in self.levels:
            if outcome.supported and outcome.level.rank > best.rank:
                best = outcome.level
        return best


def rejection_reasons(
    evidence: Evidence,
    requirement: Requirement,
    capability: Capability,
    now: datetime,
    required_role: str = SOURCE_ROLES[0],
) -> list[str]:
    """Why this evidence does not satisfy the requirement. Empty means it does.

    ``required_role`` is the least independent source that counts, which
    depends on the level being evaluated (see ``RuleSet.required_independence``).
    """
    cls = evidence.evidence_class
    if requirement.containment and cls is not EvidenceClass.CONTAINMENT_TEST:
        return [
            f"{cls.value} can never satisfy a containment requirement: behavioural results "
            "cannot show containment, because a model can detect that it is being evaluated"
        ]
    if cls not in requirement.classes:
        return [f"{cls.value} does not count towards this requirement"]
    reasons = []
    if capability not in evidence.scope:
        scope = ", ".join(sorted(c.value for c in evidence.scope)) or "nothing"
        reasons.append(f"not scoped to {capability.value} (scope: {scope})")
    assessment = assess(evidence, now)
    if not assessment.gate_eligible:
        reasons.append(
            f"admission state is {assessment.state.value}, not gate_eligible: "
            + "; ".join(assessment.blockers)
        )
    if requirement.max_age_days is not None:
        age = now - evidence.issued_at
        if age > timedelta(days=requirement.max_age_days):
            reasons.append(
                f"issued {_days(age)} ago, older than the {_fmt_num(requirement.max_age_days)} day limit"
            )
    reasons.extend(_strength_reasons(evidence, requirement))
    if independence_rank(evidence.source.role) < independence_rank(required_role):
        reasons.append(
            f"source '{evidence.source.name}' is {evidence.source.role}, and at this level "
            f"{cls.value} must come from a source that is at least {required_role}"
        )
    if requirement.monitor is not None:
        heartbeat = _heartbeat(evidence)
        timeout = requirement.monitor.heartbeat_timeout_seconds
        if heartbeat is not None and (now - heartbeat).total_seconds() > timeout:
            silent = int((now - heartbeat).total_seconds())
            reasons.append(
                f"last heartbeat {silent} seconds ago, beyond this monitor's "
                f"{_fmt_num(timeout)} second timeout"
            )
    return reasons


def _heartbeat(evidence: Evidence) -> datetime | None:
    try:
        return parse_timestamp(str(evidence.strength.get("last_heartbeat")))
    except ValueError:
        return None


def latest_reports(records: Iterable[Evidence], monitor_name: str) -> tuple[Evidence | None, list[Evidence]]:
    """The latest unrevoked report from a monitor, and the reports it supersedes.

    Only the latest report counts, so a monitor that reports degraded cannot
    be propped up by an earlier healthy report that is still inside its
    heartbeat window. Revoked reports are skipped, since revocation says the
    report was wrong.
    """
    mine = [
        e
        for e in records
        if e.evidence_class is EvidenceClass.MONITOR_HEALTH
        and e.strength.get("monitor_name") == monitor_name
        and e.revoked_at is None
    ]
    if not mine:
        return None, []
    far_past = datetime.min.replace(tzinfo=timezone.utc)
    mine.sort(key=lambda e: (_heartbeat(e) or far_past, e.issued_at))
    return mine[-1], mine[:-1]


def _strength_reasons(evidence: Evidence, req: Requirement) -> list[str]:
    metrics = strength_metrics(evidence)
    kinds = metric_kinds(evidence.evidence_class)
    reasons = []
    for key, bound in req.minimum.items():
        value = metrics.get(key)
        if value is None:
            reasons.append(f"no {key} recorded")
        elif _rank(kinds[key], value) < _rank(kinds[key], bound):
            reasons.append(f"{key} is {_fmt_num(value)}, needs at least {_fmt_num(bound)}")
    for key, bound in req.maximum.items():
        value = metrics.get(key)
        if value is None:
            reasons.append(f"no {key} recorded")
        elif _rank(kinds[key], value) > _rank(kinds[key], bound):
            reasons.append(f"{key} is {_fmt_num(value)}, must be at most {_fmt_num(bound)}")
    for key, expected in req.match.items():
        value = metrics.get(key)
        if value != expected:
            reasons.append(f"{key} is {value!r}, needs {expected!r}")
    for key, needed in req.includes.items():
        value = metrics.get(key)
        if kinds[key] == "text":
            if value not in needed:
                reasons.append(
                    f"{key} {value!r} is not one of the {key}s that count here "
                    f"({', '.join(needed)}); an unknown {key} does not count"
                )
            continue
        missing = [b for b in needed if b not in (value or [])]
        if missing:
            reasons.append(f"{key} does not cover {', '.join(missing)}")
    return reasons


def _rank(kind: str, value: object) -> float:
    if kind == "risk":
        return RISK_LEVELS.index(value)  # type: ignore[arg-type]
    return float(value)  # type: ignore[arg-type]


def remedy(
    requirement: Requirement,
    capability: Capability,
    subject: Subject,
    required_role: str = SOURCE_ROLES[0],
) -> str:
    if requirement.monitor is not None:
        mon = requirement.monitor
        return (
            f"Record monitor_health evidence for {subject} scoped to {capability.value} showing "
            f"monitor '{mon.name}' healthy, which here means it {mon.healthy}."
        )
    classes = " or ".join(c.value for c in requirement.classes)
    parts = [f"Add gate eligible {classes} evidence for {subject} scoped to {capability.value}"]
    conditions = []
    for key, bound in requirement.minimum.items():
        conditions.append(f"{key} at least {_fmt_num(bound)}")
    for key, bound in requirement.maximum.items():
        conditions.append(f"{key} at most {_fmt_num(bound)}")
    for key, needed in requirement.includes.items():
        if key in ("suite", "exercise"):
            conditions.append(f"{key} {' or '.join(needed)}")
        else:
            conditions.append(f"{key} covering {', '.join(needed)}")
    for key, expected in requirement.match.items():
        conditions.append(f"{key} equal to {expected!r}")
    if conditions:
        parts.append(" with " + ", ".join(conditions))
    if requirement.max_age_days is not None:
        parts.append(f", issued within the last {_fmt_num(requirement.max_age_days)} days")
    if required_role != SOURCE_ROLES[0]:
        parts.append(f", from a source that is at least {required_role}")
    text = "".join(parts) + "."
    if requirement.containment:
        text += " Only containment_test evidence counts; eval_result and red_team_report never do."
    return text


def explain_capability(
    evidence: Iterable[Evidence],
    rules: RuleSet,
    capability: Capability,
    subject: Subject,
    now: datetime,
) -> CapabilityExplanation:
    now = utc(now)
    pool = [e for e in evidence if e.subject == subject]
    cap_rules = rules[capability]
    levels = []
    for level in LEVEL_ORDER[1:]:
        outcomes = []
        for req, introduced_at in cap_rules.effective(level):
            in_scope = [e for e in pool if capability in e.scope]
            satisfied, rejected = [], []
            if req.monitor is not None:
                latest, superseded = latest_reports(in_scope, req.monitor.name)
                candidates = [latest] if latest else []
                rejected.extend(
                    Rejection(e, (f"superseded by the later report {latest.id}",)) for e in superseded
                )
                out_of_scope = tuple(
                    e
                    for e in pool
                    if capability not in e.scope
                    and e.evidence_class is EvidenceClass.MONITOR_HEALTH
                    and e.strength.get("monitor_name") == req.monitor.name
                )
            else:
                candidates = [
                    e
                    for e in in_scope
                    if e.evidence_class in req.classes
                    or (req.containment and e.evidence_class in BEHAVIOURAL_CLASSES)
                ]
                out_of_scope = tuple(
                    e for e in pool if capability not in e.scope and e.evidence_class in req.classes
                )
            for e in candidates:
                role = rules.required_independence(req, e.evidence_class, level)
                reasons = rejection_reasons(e, req, capability, now, role)
                if reasons:
                    rejected.append(Rejection(e, tuple(reasons)))
                else:
                    satisfied.append(e)
            outcomes.append(
                RequirementOutcome(
                    requirement=req,
                    introduced_at=introduced_at,
                    satisfied_by=tuple(satisfied),
                    rejected=tuple(rejected),
                    remedy=remedy(
                        req,
                        capability,
                        subject,
                        rules.required_independence(req, req.classes[0], level),
                    ),
                    out_of_scope=out_of_scope,
                )
            )
        levels.append(LevelOutcome(level, tuple(outcomes)))
    return CapabilityExplanation(capability, subject, now, tuple(levels))


def render(explanation: CapabilityExplanation) -> str:
    e = explanation
    lines = [
        f"{e.capability.value} for {e.subject}, as of {format_timestamp(e.as_of)}",
        "",
        "  none     SUPPORTED      no evidence needed",
    ]
    shown: dict[tuple[str, Level], bool] = {}
    for outcome in e.levels:
        verdict = "SUPPORTED" if outcome.supported else "NOT SUPPORTED"
        lines.append(f"  {outcome.level.value:<8} {verdict}")
        for r in outcome.requirements:
            req = r.requirement
            tag = "[met]  " if r.met else "[unmet]"
            shown[(req.id, outcome.level)] = r.met
            if r.introduced_at is not outcome.level and shown.get((req.id, r.introduced_at)) == r.met:
                # Same outcome as under the level that introduced it, shown in full there.
                lines.append(f"    {tag} {req.id}: {req.description} (see {r.introduced_at.value})")
                continue
            containment = " [containment]" if req.containment else ""
            lines.append(f"    {tag} {req.id}: {req.description}{containment}")
            if req.monitor is not None:
                lines.append(f"            healthy means: {req.monitor.healthy}")
            for ev in r.satisfied_by:
                lines.append(f"            supported by {_describe(ev, e.as_of)}")
            if r.met:
                continue
            classes = " or ".join(c.value for c in req.classes)
            if not r.rejected:
                what = f"report from monitor '{req.monitor.name}'" if req.monitor else f"{classes} evidence"
                lines.append(f"            no {what} for {e.subject} is scoped to {e.capability.value}")
            for rej in r.rejected:
                lines.append(f"            {_describe(rej.evidence, e.as_of)} does not count:")
                for reason in rej.reasons:
                    lines.append(f"              - {reason}")
            if r.out_of_scope:
                ids = ", ".join(ev.id for ev in r.out_of_scope)
                lines.append(f"            (evidence not scoped to {e.capability.value} was ignored: {ids})")
            lines.append(f"            To meet it: {r.remedy}")
    lines.append("")
    lines.append(f"  Highest level the evidence supports: {e.highest_supported.value}")
    return "\n".join(lines)


def _describe(ev: Evidence, now: datetime) -> str:
    s = ev.strength
    cls = ev.evidence_class
    if cls is EvidenceClass.EVAL_RESULT:
        detail = f"suite {s.get('suite')!r}, pass rate {s.get('pass_rate')} on {s.get('samples')} samples"
    elif cls is EvidenceClass.RED_TEAM_REPORT:
        findings = s.get("findings_open")
        detail = (
            f"exercise {s.get('exercise')!r}, residual risk {s.get('residual_risk')}, "
            f"{findings} open finding{'' if findings == 1 else 's'}"
        )
    elif cls is EvidenceClass.CONTAINMENT_TEST:
        boundaries = ", ".join(s.get("boundaries_tested") or [])
        detail = (
            f"{s.get('escape_attempts_blocked')} of {s.get('escape_attempts')} escape attempts "
            f"blocked across {boundaries}"
        )
    elif cls is EvidenceClass.MONITOR_HEALTH:
        detail = f"monitor {s.get('monitor_name')!r} {s.get('state')}"
    elif cls is EvidenceClass.HUMAN_ATTESTATION:
        smf = f", {s['smf_function']}" if s.get("smf_function") else ""
        level = f", signing off {s['grants_level']}" if s.get("grants_level") else ""
        detail = f"{s.get('person')} ({s.get('role')}{smf}) attests to {s.get('attests_to')!r}{level}"
    else:
        tier = f", tier {s['tier']}" if s.get("tier") else ""
        detail = f"{s.get('standard')} {s.get('clause')}{tier}"
    age = _days(now - ev.issued_at)
    return f"{ev.id} ({cls.value}: {detail}; issued {age} ago by {ev.source.name}, {ev.source.role})"


def _days(delta: timedelta) -> str:
    seconds = delta.total_seconds()
    if seconds < 0:
        return "in the future, " + _days(-delta)
    if seconds < 60:
        return "under a minute"
    if seconds < 3600:
        minutes = int(seconds // 60)
        return "1 minute" if minutes == 1 else f"{minutes} minutes"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return "1 hour" if hours == 1 else f"{hours} hours"
    days = int(seconds // 86400)
    return "1 day" if days == 1 else f"{days} days"


def _fmt_num(value: object) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
