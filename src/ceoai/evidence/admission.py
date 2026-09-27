# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The CEOAI contributors
"""Admission state: how far a piece of evidence gets up the admission hierarchy.

The rules, applied in order. Evidence stops at the first stage it fails and the
reasons are kept, so every state can be explained.

present
    The evidence is recorded in the ledger.
complete
    Every field the class needs is filled in: subject, scope, source, expiry,
    a sha256 content hash, and the class-specific strength fields.
sufficient
    The strength fields are well formed and in range (fractions between 0 and
    1, counts not negative, known enum values, blocked attempts not exceeding
    attempts, and so on). Whether the strength is high enough for a particular
    capability is decided later, against a requirement.
admissible
    The source is authorised to produce this class, the evidence has been
    issued, and it is neither expired nor revoked.
gate_eligible
    The evidence can gate a capability right now. For monitor_health this
    needs a live, healthy monitor whose last heartbeat is inside its timeout.
    Every other class is gate eligible once admissible.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

from .model import (
    CONTENT_HASH_PATTERN,
    AdmissionState,
    Evidence,
    EvidenceClass,
    format_timestamp,
    parse_timestamp,
    utc,
)

RISK_LEVELS = ("low", "medium", "high")
MONITOR_STATES = ("healthy", "degraded", "down")
CONTAINMENT_BOUNDARIES = ("filesystem", "network_egress", "credential_access", "process_escape")
DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str  # text, fraction, count, risk, monitor_state, boundaries, timestamp, seconds
    required: bool = True


CLASS_FIELDS: dict[EvidenceClass, tuple[FieldSpec, ...]] = {
    EvidenceClass.EVAL_RESULT: (
        FieldSpec("suite", "text"),
        FieldSpec("pass_rate", "fraction"),
        FieldSpec("samples", "count"),
        FieldSpec("log_ref", "text", required=False),
    ),
    EvidenceClass.RED_TEAM_REPORT: (
        FieldSpec("scope_tested", "text"),
        FieldSpec("findings_open", "count"),
        FieldSpec("residual_risk", "risk"),
    ),
    EvidenceClass.CONTAINMENT_TEST: (
        FieldSpec("boundaries_tested", "boundaries"),
        FieldSpec("escape_attempts", "count"),
        FieldSpec("escape_attempts_blocked", "count"),
    ),
    EvidenceClass.MONITOR_HEALTH: (
        FieldSpec("monitor_name", "text"),
        FieldSpec("state", "monitor_state"),
        FieldSpec("last_heartbeat", "timestamp"),
        FieldSpec("effectiveness", "fraction"),
        FieldSpec("heartbeat_timeout_seconds", "seconds", required=False),
    ),
    EvidenceClass.HUMAN_ATTESTATION: (
        FieldSpec("person", "text"),
        FieldSpec("role", "text"),
        FieldSpec("attests_to", "text"),
        FieldSpec("smf_function", "text", required=False),
    ),
    EvidenceClass.STANDARDS_EVIDENCE: (
        FieldSpec("standard", "text"),
        FieldSpec("clause", "text"),
        FieldSpec("tier", "text", required=False),
    ),
}

# Metrics computed from the stored strength fields. Kind as for FieldSpec.
DERIVED_METRICS: dict[EvidenceClass, dict[str, str]] = {
    EvidenceClass.CONTAINMENT_TEST: {"block_rate": "fraction"},
}


def metric_kinds(evidence_class: EvidenceClass) -> dict[str, str]:
    """Every metric a requirement may constrain for this class, with its kind."""
    kinds = {spec.name: spec.kind for spec in CLASS_FIELDS[evidence_class]}
    kinds.update(DERIVED_METRICS.get(evidence_class, {}))
    return kinds


def strength_metrics(evidence: Evidence) -> dict[str, Any]:
    """The stored strength fields plus derived metrics such as block_rate."""
    metrics = dict(evidence.strength)
    if evidence.evidence_class is EvidenceClass.CONTAINMENT_TEST:
        attempts = metrics.get("escape_attempts")
        blocked = metrics.get("escape_attempts_blocked")
        if _is_count(attempts) and _is_count(blocked) and attempts > 0:
            metrics["block_rate"] = blocked / attempts
    return metrics


@dataclass(frozen=True)
class Assessment:
    state: AdmissionState
    # Why the evidence did not reach the next state. Empty at gate_eligible.
    blockers: tuple[str, ...]
    expired: bool
    revoked: bool

    @property
    def gate_eligible(self) -> bool:
        return self.state is AdmissionState.GATE_ELIGIBLE

    @property
    def status(self) -> str:
        if self.revoked:
            return "revoked"
        if self.expired:
            return "expired"
        return "live"


def assess(evidence: Evidence, now: datetime) -> Assessment:
    now = utc(now)
    stages: tuple[tuple[AdmissionState, Callable[[], list[str]]], ...] = (
        (AdmissionState.COMPLETE, lambda: _completeness_problems(evidence)),
        (AdmissionState.SUFFICIENT, lambda: _sufficiency_problems(evidence)),
        (AdmissionState.ADMISSIBLE, lambda: _admissibility_problems(evidence, now)),
        (AdmissionState.GATE_ELIGIBLE, lambda: _gate_problems(evidence, now)),
    )
    state = AdmissionState.PRESENT
    for next_state, check in stages:
        problems = check()
        if problems:
            break
        state = next_state
    else:
        problems = []
    return Assessment(
        state=state,
        blockers=tuple(problems),
        expired=evidence.is_expired(now),
        revoked=evidence.is_revoked(now),
    )


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, (str, list, tuple, set, frozenset)) and len(value) == 0)


def _completeness_problems(ev: Evidence) -> list[str]:
    problems = []
    if _blank(ev.subject.agent_id) or _blank(ev.subject.version):
        problems.append("subject needs both an agent id and a version")
    if not ev.scope:
        problems.append("scope is empty, so it cannot support any capability")
    if _blank(ev.source.name):
        problems.append("source is not named")
    if ev.expires_at is None:
        problems.append("no expiry date")
    if _blank(ev.content_hash):
        problems.append("no content hash of the underlying artefact")
    elif not CONTENT_HASH_PATTERN.match(ev.content_hash or ""):
        problems.append("content hash is not in the form sha256:<64 hex digits>")
    for spec in CLASS_FIELDS[ev.evidence_class]:
        if spec.required and _blank(ev.strength.get(spec.name)):
            problems.append(f"strength field '{spec.name}' is missing")
    return problems


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _value_problem(spec: FieldSpec, value: Any) -> str | None:
    name = spec.name
    if spec.kind == "text":
        if not isinstance(value, str):
            return f"'{name}' should be text"
    elif spec.kind == "fraction":
        if not _is_number(value) or not 0 <= value <= 1:
            return f"'{name}' should be a number between 0 and 1, got {value!r}"
    elif spec.kind == "count":
        if not _is_count(value):
            return f"'{name}' should be a whole number of zero or more, got {value!r}"
    elif spec.kind == "seconds":
        if not _is_number(value) or value <= 0:
            return f"'{name}' should be a positive number of seconds, got {value!r}"
    elif spec.kind == "risk":
        if value not in RISK_LEVELS:
            return f"'{name}' should be one of {', '.join(RISK_LEVELS)}, got {value!r}"
    elif spec.kind == "monitor_state":
        if value not in MONITOR_STATES:
            return f"'{name}' should be one of {', '.join(MONITOR_STATES)}, got {value!r}"
    elif spec.kind == "boundaries":
        if not isinstance(value, (list, tuple)) or not value:
            return f"'{name}' should be a non-empty list of boundaries"
        unknown = [b for b in value if b not in CONTAINMENT_BOUNDARIES]
        if unknown:
            return (
                f"'{name}' has unknown boundaries {', '.join(map(str, unknown))}; "
                f"known boundaries are {', '.join(CONTAINMENT_BOUNDARIES)}"
            )
    elif spec.kind == "timestamp":
        try:
            parse_timestamp(str(value))
        except ValueError:
            return f"'{name}' should be an ISO 8601 timestamp, got {value!r}"
    return None


def _sufficiency_problems(ev: Evidence) -> list[str]:
    problems = []
    for spec in CLASS_FIELDS[ev.evidence_class]:
        value = ev.strength.get(spec.name)
        if value is None:
            continue
        problem = _value_problem(spec, value)
        if problem:
            problems.append(problem)
    if problems:
        return problems
    s = ev.strength
    if ev.evidence_class is EvidenceClass.EVAL_RESULT and s["samples"] == 0:
        problems.append("evaluation ran on zero samples")
    if ev.evidence_class is EvidenceClass.CONTAINMENT_TEST:
        if s["escape_attempts"] == 0:
            problems.append("containment test made no escape attempts, so it shows nothing")
        elif s["escape_attempts_blocked"] > s["escape_attempts"]:
            problems.append("more escape attempts blocked than were made")
    return problems


def _admissibility_problems(ev: Evidence, now: datetime) -> list[str]:
    problems = []
    if not ev.source.is_authorised_for(ev.evidence_class):
        problems.append(
            f"source '{ev.source.name}' has no recorded authority to produce {ev.evidence_class.value}"
        )
    if ev.issued_at > now:
        problems.append(f"not issued until {format_timestamp(ev.issued_at)}")
    assert ev.expires_at is not None  # guaranteed by completeness
    if ev.expires_at <= ev.issued_at:
        problems.append("expires before it was issued")
    elif ev.is_expired(now):
        problems.append(f"expired at {format_timestamp(ev.expires_at)}")
    if ev.is_revoked(now):
        assert ev.revoked_at is not None
        reason = f": {ev.revocation_reason}" if ev.revocation_reason else ""
        problems.append(f"revoked at {format_timestamp(ev.revoked_at)}{reason}")
    return problems


def heartbeat_timeout(ev: Evidence) -> timedelta:
    seconds = ev.strength.get("heartbeat_timeout_seconds", DEFAULT_HEARTBEAT_TIMEOUT_SECONDS)
    return timedelta(seconds=seconds)


def _gate_problems(ev: Evidence, now: datetime) -> list[str]:
    if ev.evidence_class is not EvidenceClass.MONITOR_HEALTH:
        return []
    problems = []
    name = ev.strength["monitor_name"]
    state = ev.strength["state"]
    if state != "healthy":
        problems.append(f"monitor '{name}' reports {state}")
    heartbeat = parse_timestamp(str(ev.strength["last_heartbeat"]))
    timeout = heartbeat_timeout(ev)
    if heartbeat > now:
        problems.append(f"monitor '{name}' heartbeat is in the future ({format_timestamp(heartbeat)})")
    elif now - heartbeat > timeout:
        silent = int((now - heartbeat).total_seconds())
        problems.append(
            f"monitor '{name}' has been silent for {silent} seconds "
            f"(timeout {int(timeout.total_seconds())} seconds)"
        )
    return problems
