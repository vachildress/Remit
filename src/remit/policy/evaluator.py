# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""The policy evaluator: from ledger and rules to a live grant per capability.

``remit evidence explain`` says what the evidence supports. This module turns
that into grants, which is what enforcement consumes, by applying the grant
rules:

* Contraction is automatic. If the evidence, the tier ceiling or a parent's
  delegation no longer reach the current level, the grant drops at once.
* Expansion needs a human. A grant only rises to a level when a
  human_attestation names the agent version (by its subject), the
  capability (by its scope) and at least that level (``grants_level``), and
  was issued after a set of evidence sufficient for that level already
  existed. Monitor health is a live precondition, not evidence of ability,
  so it is left out of that timing test.
* Tier ceilings. The strictest current tier caps every capability, whatever
  other evidence exists. With no current tier evidence the untiered row
  applies.
* Delegation attenuation. A delegated envelope must be a subset of the
  parent's at the time of delegation; the parent's levels act as a further
  ceiling on the child.

The evaluator is pure: it takes the previous levels as input and returns the
new envelope. ``remit.policy.history`` persists levels and records changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Mapping

from ..evidence.admission import assess
from ..evidence.model import (
    LEVEL_ORDER,
    Capability,
    Evidence,
    EvidenceClass,
    Level,
    Subject,
    format_timestamp,
    utc,
)
from ..evidence.requirements import UNTIERED, RuleSet, Tier
from ..evidence.support import CapabilityExplanation, LevelOutcome, RequirementOutcome, explain_capability


@dataclass(frozen=True)
class Cause:
    """Why a grant is where it is, or why it changed."""

    kind: str  # expiry, revocation, monitor, requirement, ceiling, parent, attestation
    ref: str | None
    detail: str


@dataclass(frozen=True)
class Unmet:
    """A requirement that is not met at some level, and what would meet it."""

    requirement_id: str
    description: str
    remedy: str
    # Why the evidence on record does not meet it, one line per record.
    reasons: tuple[str, ...] = ()

    def summary(self) -> str:
        return "; ".join(self.reasons[:2]) if self.reasons else "no evidence on record"


@dataclass(frozen=True)
class TierCeiling:
    tier: Tier
    # Evidence ids that set the tier; empty when the untiered row applies.
    evidence_ids: tuple[str, ...]

    def describe(self) -> str:
        if self.tier.name == UNTIERED:
            return "the untiered ceiling (no current tier evidence)"
        return f"the tier {self.tier.name} ceiling ({', '.join(self.evidence_ids)})"


@dataclass(frozen=True)
class Grant:
    capability: Capability
    level: Level
    previous: Level
    # Highest level the evidence alone supports.
    supported: Level
    # Highest level the tier allows, and the parent's level if delegated.
    ceiling: Level
    ceiling_source: str
    parent_level: Level | None
    # Evidence ids supporting the granted level.
    supporting: tuple[str, ...]
    # Monitors the granted level relies on.
    monitors: tuple[str, ...]
    # The attestation that authorised a rise to this level, when there was one.
    attestation: str | None
    # A higher level the evidence and ceilings allow but no attestation has
    # authorised yet. Enforcement holds calls needing it for a human.
    held: Level | None
    # Unmet requirements per level above the granted level.
    unmet: Mapping[Level, tuple[Unmet, ...]]
    causes: tuple[Cause, ...]
    explanation: str

    @property
    def changed(self) -> bool:
        return self.level is not self.previous

    def why_not(self, level: Level) -> str:
        """Plain English: why this grant does not reach ``level``. Names what binds."""
        if self.level.rank >= level.rank:
            return f"{self.capability.value} is granted at {self.level.value}, which covers {level.value}"
        parts = []
        if self.ceiling.rank < level.rank:
            if self.parent_level is not None and self.parent_level.rank < level.rank:
                parts.append(
                    f"the delegating parent holds {self.capability.value} only at {self.parent_level.value}"
                )
            else:
                parts.append(f"{self.ceiling_source} caps {self.capability.value} at {self.ceiling.value}")
        for lvl in LEVEL_ORDER[1:]:
            if lvl.rank > level.rank:
                break
            for u in self.unmet.get(lvl, ()):
                parts.append(
                    f"requirement {u.requirement_id} ({u.description}) is not met at {lvl.value} "
                    f"({u.summary()}). {u.remedy.rstrip('.')}"
                )
        if self.held is not None and self.held.rank >= level.rank and not parts:
            parts.append(
                f"the evidence supports {self.held.value}, but no human_attestation names "
                f"{self.capability.value} at {self.held.value} for this agent version, issued after "
                "that evidence. Record one to expand the grant"
            )
        return "; ".join(parts) or f"{self.capability.value} is at {self.level.value}"


@dataclass(frozen=True)
class Envelope:
    subject: Subject
    as_of: datetime
    grants: Mapping[Capability, Grant]
    ceiling: TierCeiling | None = None

    def __getitem__(self, capability: Capability) -> Grant:
        return self.grants[capability]

    def levels(self) -> dict[Capability, Level]:
        return {cap: g.level for cap, g in self.grants.items()}


def _min(*levels: Level) -> Level:
    return min(levels, key=lambda lvl: lvl.rank)


def current_tier(evidence: Iterable[Evidence], rules: RuleSet, subject: Subject, now: datetime) -> TierCeiling | None:
    """The tier whose ceiling applies now, or None if the rules define no tiers."""
    if not rules.tiers:
        return None
    counted: list[tuple[Tier, Evidence]] = []
    for e in evidence:
        if e.subject != subject or e.evidence_class is not EvidenceClass.STANDARDS_EVIDENCE:
            continue
        name = e.strength.get("tier")
        tier = rules.tiers.get(str(name)) if name is not None else None
        if tier is None or tier.name == UNTIERED or not assess(e, now).gate_eligible:
            continue
        if now - e.issued_at > timedelta(days=tier.max_age_days):
            continue
        counted.append((tier, e))
    if not counted:
        return TierCeiling(rules.tiers[UNTIERED], ())
    # The strictest current tier applies: the one with the lowest ceilings.
    strictest = min(counted, key=lambda te: sum(lvl.rank for lvl in te[0].ceilings.values()))[0]
    ids = tuple(e.id for t, e in counted if t.name == strictest.name)
    return TierCeiling(strictest, ids)


def _level_outcome(ex: CapabilityExplanation, level: Level) -> LevelOutcome | None:
    return next((o for o in ex.levels if o.level is level), None)


def _supporting(ex: CapabilityExplanation, level: Level) -> tuple[str, ...]:
    outcome = _level_outcome(ex, level)
    if outcome is None:
        return ()
    ids: list[str] = []
    for r in outcome.requirements:
        for e in r.satisfied_by:
            if e.id not in ids:
                ids.append(e.id)
    return tuple(ids)


def _monitors(ex: CapabilityExplanation, level: Level) -> tuple[str, ...]:
    outcome = _level_outcome(ex, level)
    if outcome is None:
        return ()
    return tuple(r.requirement.monitor.name for r in outcome.requirements if r.requirement.monitor)


def expansion_attestation(
    evidence: Iterable[Evidence],
    rules: RuleSet,
    ex: CapabilityExplanation,
    target: Level,
    now: datetime,
) -> Evidence | None:
    """The attestation that authorises raising ``ex.capability`` to ``target``, if any.

    It must name the agent version and capability and at least the target
    level, be gate eligible and within the attestation age limit, and have
    been issued after evidence sufficient for every non-monitor requirement
    of the target level already existed. The attestation may itself be the
    evidence meeting an attestation requirement.
    """
    outcome = _level_outcome(ex, target)
    if outcome is None or not outcome.supported:
        return None
    max_age = rules.age_limits.get(EvidenceClass.HUMAN_ATTESTATION)
    candidates = []
    for e in evidence:
        if e.subject != ex.subject or e.evidence_class is not EvidenceClass.HUMAN_ATTESTATION:
            continue
        if ex.capability not in e.scope:
            continue
        named = e.strength.get("grants_level")
        if named not in ("limited", "full") or Level(named).rank < target.rank:
            continue
        if not assess(e, now).gate_eligible:
            continue
        if max_age is not None and now - e.issued_at > timedelta(days=max_age):
            continue
        timely = all(
            any(s.id == e.id or s.issued_at < e.issued_at for s in r.satisfied_by)
            for r in outcome.requirements
            if r.requirement.monitor is None
        )
        if timely:
            candidates.append(e)
    # Prefer the most recent sign off.
    return max(candidates, key=lambda e: e.issued_at, default=None)


def _reasons(r: RequirementOutcome) -> tuple[str, ...]:
    """One line per rejected record, records of an accepted class first."""
    lines = []
    ordered = sorted(r.rejected, key=lambda rej: rej.evidence.evidence_class not in r.requirement.classes)
    for rej in ordered:
        if any(reason.startswith("superseded by") for reason in rej.reasons):
            continue
        lines.append(f"{rej.evidence.id}: {'; '.join(rej.reasons)}")
    return tuple(lines)


def _unmet(ex: CapabilityExplanation) -> dict[Level, tuple[Unmet, ...]]:
    out = {}
    for outcome in ex.levels:
        out[outcome.level] = tuple(
            Unmet(r.requirement.id, r.requirement.description, r.remedy, _reasons(r))
            for r in outcome.requirements
            if not r.met
        )
    return out


def _loss_causes(ex: CapabilityExplanation, previous: Level, now: datetime) -> list[Cause]:
    """Why the evidence no longer supports ``previous``."""
    causes: list[Cause] = []
    for outcome in ex.levels:
        if outcome.level.rank > previous.rank:
            break
        for r in outcome.requirements:
            if r.met:
                continue
            req = r.requirement
            if req.monitor is not None:
                why = "; ".join(_reasons(r)) or "no report on record"
                causes.append(
                    Cause("monitor", req.monitor.name, f"monitor '{req.monitor.name}' is not healthy ({why})")
                )
                continue
            rejected = [rej.evidence for rej in r.rejected]
            revoked = [e for e in rejected if e.is_revoked(now)]
            expired = [e for e in rejected if e.is_expired(now) and not e.is_revoked(now)]
            if revoked:
                e = revoked[0]
                causes.append(Cause("revocation", e.id, f"{e.id} was revoked: {e.revocation_reason}"))
            elif expired:
                e = expired[0]
                assert e.expires_at is not None
                causes.append(Cause("expiry", e.id, f"{e.id} expired at {format_timestamp(e.expires_at)}"))
            else:
                causes.append(Cause("requirement", req.id, f"requirement {req.id} is no longer met"))
    # One cause per reference is enough.
    seen, unique = set(), []
    for c in causes:
        if (c.kind, c.ref) not in seen:
            seen.add((c.kind, c.ref))
            unique.append(c)
    return unique


def evaluate_capability(
    evidence: list[Evidence],
    rules: RuleSet,
    capability: Capability,
    subject: Subject,
    now: datetime,
    previous: Level = Level.NONE,
    previous_attestation: str | None = None,
    tier: TierCeiling | None = None,
    parent_level: Level | None = None,
) -> Grant:
    now = utc(now)
    ex = explain_capability(evidence, rules, capability, subject, now)
    supported = ex.highest_supported
    tier_level = tier.tier.ceilings[capability] if tier else Level.FULL
    ceiling = tier_level if parent_level is None else _min(tier_level, parent_level)
    if parent_level is not None and parent_level.rank < tier_level.rank:
        ceiling_source = "the delegating parent's grant"
    elif tier is not None:
        ceiling_source = tier.describe()
    else:
        ceiling_source = "no ceiling"
    allowed = _min(supported, ceiling)

    causes: list[Cause] = []
    attestation = None
    held = None
    if allowed.rank <= previous.rank:
        level = allowed
        if level is previous:
            attestation = previous_attestation
        else:
            if ceiling.rank < previous.rank:
                if parent_level is not None and parent_level.rank < previous.rank:
                    causes.append(Cause("parent", None, f"the delegating parent now holds only {parent_level.value}"))
                else:
                    causes.append(Cause("ceiling", tier.tier.name if tier else None, f"{ceiling_source} caps it at {ceiling.value}"))
            if supported.rank < previous.rank:
                causes.extend(_loss_causes(ex, previous, now))
    else:
        level = previous
        for target in reversed(LEVEL_ORDER):
            if target.rank > allowed.rank or target.rank <= previous.rank:
                continue
            att = expansion_attestation(evidence, rules, ex, target, now)
            if att is not None:
                level = target
                attestation = att.id
                causes.append(Cause("attestation", att.id, f"{att.id} authorised {target.value}"))
                break
        if level is previous:
            attestation = previous_attestation
        if level.rank < allowed.rank:
            held = allowed

    grant = Grant(
        capability=capability,
        level=level,
        previous=previous,
        supported=supported,
        ceiling=ceiling,
        ceiling_source=ceiling_source,
        parent_level=parent_level,
        supporting=_supporting(ex, level),
        monitors=_monitors(ex, level),
        attestation=attestation,
        held=held,
        unmet=_unmet(ex),
        causes=tuple(causes),
        explanation="",
    )
    return _with_explanation(grant)


def _with_explanation(g: Grant) -> Grant:
    cap = g.capability.value
    lines = [f"{cap}: granted {g.level.value}."]
    if g.level is not Level.NONE:
        lines.append(f"Supported by {', '.join(g.supporting)}.")
        if g.monitors:
            lines.append(f"Relies on monitors: {', '.join(g.monitors)}.")
        if g.attestation:
            lines.append(f"Authorised by attestation {g.attestation}.")
    if g.changed:
        verb = "Raised" if g.level.rank > g.previous.rank else "Lowered"
        why = "; ".join(c.detail for c in g.causes) or "no recorded cause"
        lines.append(f"{verb} from {g.previous.value}: {why}.")
    if g.ceiling.rank < g.supported.rank:
        lines.append(f"The evidence supports {g.supported.value}, but {g.ceiling_source} caps it at {g.ceiling.value}.")
    if g.held is not None:
        lines.append(f"Held below {g.held.value}: {g.why_not(g.held)}.")
    next_up = next((lvl for lvl in LEVEL_ORDER if lvl.rank == g.level.rank + 1), None)
    if next_up is not None and g.held is None:
        lines.append(f"To reach {next_up.value}: {g.why_not(next_up)}.")
    return Grant(**{**g.__dict__, "explanation": " ".join(lines)})


def evaluate_envelope(
    evidence: Iterable[Evidence],
    rules: RuleSet,
    subject: Subject,
    now: datetime,
    previous: Mapping[Capability, tuple[Level, str | None]] | None = None,
    parent_levels: Mapping[Capability, Level] | None = None,
) -> Envelope:
    """The grant for every capability for ``subject`` at ``now``.

    ``previous`` maps each capability to its last recorded level and the
    attestation behind it; a capability never recorded starts at none.
    ``parent_levels`` is the delegation ceiling for a delegated agent.
    """
    now = utc(now)
    pool = [e for e in evidence if e.subject == subject]
    tier = current_tier(pool, rules, subject, now)
    previous = previous or {}
    grants = {}
    for cap in Capability:
        prev_level, prev_att = previous.get(cap, (Level.NONE, None))
        grants[cap] = evaluate_capability(
            pool,
            rules,
            cap,
            subject,
            now,
            previous=prev_level,
            previous_attestation=prev_att,
            tier=tier,
            parent_level=None if parent_levels is None else parent_levels.get(cap, Level.NONE),
        )
    return Envelope(subject, now, grants, tier)


@dataclass(frozen=True)
class Delegation:
    """The result of asking to delegate part of an envelope to another agent."""

    parent: Subject
    child: Subject
    requested: Mapping[Capability, Level]
    accepted: bool
    # The child's delegation ceiling, when accepted.
    levels: Mapping[Capability, Level] = field(default_factory=dict)
    violations: tuple[str, ...] = ()

    @property
    def explanation(self) -> str:
        if self.accepted:
            granted = ", ".join(f"{c.value} {lvl.value}" for c, lvl in self.levels.items() if lvl is not Level.NONE)
            return f"Delegation from {self.parent} to {self.child} accepted: {granted or 'nothing'}."
        return f"Delegation from {self.parent} to {self.child} rejected: " + "; ".join(self.violations) + "."


def attenuate(parent: Envelope, child: Subject, requested: Mapping[Capability, Level]) -> Delegation:
    """Check a delegation request against the parent's envelope at this moment.

    The child's envelope must be a subset of the parent's: every requested
    level at or below the parent's grant. The parent must also hold the
    delegation capability. A wider request is rejected whole, not trimmed,
    so the caller sees exactly what was asked for and refused.
    """
    violations = []
    delegation = parent[Capability.DELEGATION]
    if delegation.level is Level.NONE:
        violations.append(f"{parent.subject} holds no delegation grant ({delegation.why_not(Level.LIMITED)})")
    for cap, lvl in requested.items():
        have = parent[cap].level
        if lvl.rank > have.rank:
            violations.append(f"asks for {cap.value} at {lvl.value}, but the parent holds it only at {have.value}")
    if violations:
        return Delegation(parent.subject, child, dict(requested), False, violations=tuple(violations))
    levels = {cap: requested.get(cap, Level.NONE) for cap in Capability}
    return Delegation(parent.subject, child, dict(requested), True, levels=levels)
