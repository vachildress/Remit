# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""Evidence schema: the typed, provenance-carrying objects the ledger stores.

Constructing an Evidence object only checks structure (types, known enum
values, timezone-aware timestamps). Whether the evidence is complete, fresh or
fit to gate a capability is a separate judgement made in ``admission``, so that
incomplete evidence can still be recorded and explained.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping


class EvidenceClass(str, Enum):
    EVAL_RESULT = "eval_result"
    RED_TEAM_REPORT = "red_team_report"
    CONTAINMENT_TEST = "containment_test"
    MONITOR_HEALTH = "monitor_health"
    HUMAN_ATTESTATION = "human_attestation"
    STANDARDS_EVIDENCE = "standards_evidence"

    def __str__(self) -> str:
        return self.value


class Capability(str, Enum):
    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    NETWORK_OUT = "network_out"
    CODE_EXECUTION = "code_execution"
    REPO_WRITE = "repo_write"
    EXTERNAL_COMMS = "external_comms"
    DELEGATION = "delegation"
    BUDGET = "budget"

    def __str__(self) -> str:
        return self.value


# Capabilities that act on the world. Each must carry a containment
# requirement at limited and above.
WORLD_ACTING_CAPABILITIES = frozenset(
    {
        Capability.WRITE_DATA,
        Capability.NETWORK_OUT,
        Capability.CODE_EXECUTION,
        Capability.REPO_WRITE,
        Capability.EXTERNAL_COMMS,
        Capability.DELEGATION,
    }
)


class Level(str, Enum):
    NONE = "none"
    LIMITED = "limited"
    FULL = "full"

    @property
    def rank(self) -> int:
        return LEVEL_ORDER.index(self)

    def __str__(self) -> str:
        return self.value


LEVEL_ORDER = (Level.NONE, Level.LIMITED, Level.FULL)


class AdmissionState(str, Enum):
    """Evidence admission hierarchy, after the Agile-V Assurance Spine.

    Each state implies all the states before it.
    """

    PRESENT = "present"
    COMPLETE = "complete"
    SUFFICIENT = "sufficient"
    ADMISSIBLE = "admissible"
    GATE_ELIGIBLE = "gate_eligible"

    @property
    def rank(self) -> int:
        return ADMISSION_ORDER.index(self)

    def __str__(self) -> str:
        return self.value


ADMISSION_ORDER = tuple(AdmissionState)

CONTENT_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def utc(value: datetime) -> datetime:
    """Normalise a datetime to UTC. Naive values are taken to be UTC already."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(text: str) -> datetime:
    return utc(datetime.fromisoformat(text))


def format_timestamp(value: datetime) -> str:
    """Human-facing timestamp, to the second."""
    return utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_artefact(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def new_evidence_id() -> str:
    return "ev-" + uuid.uuid4().hex[:12]


@dataclass(frozen=True)
class Subject:
    """The agent, at a specific version, that a piece of evidence is about."""

    agent_id: str
    version: str

    @classmethod
    def parse(cls, text: str) -> "Subject":
        agent_id, sep, version = text.rpartition("@")
        if not sep or not agent_id or not version:
            raise ValueError(f"subject must look like agent@version, got {text!r}")
        return cls(agent_id, version)

    def __str__(self) -> str:
        return f"{self.agent_id}@{self.version}"


@dataclass(frozen=True)
class Source:
    """Who produced the evidence, and which classes they are authorised to produce."""

    name: str
    authorised_classes: frozenset[EvidenceClass] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "authorised_classes",
            frozenset(EvidenceClass(c) for c in self.authorised_classes),
        )

    def is_authorised_for(self, evidence_class: EvidenceClass) -> bool:
        return evidence_class in self.authorised_classes


def _optional_utc(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        return parse_timestamp(value)
    return utc(value)


@dataclass(frozen=True)
class Evidence:
    evidence_class: EvidenceClass
    subject: Subject
    scope: frozenset[Capability]
    source: Source
    strength: Mapping[str, Any]
    issued_at: datetime
    expires_at: datetime | None
    content_hash: str | None
    id: str = field(default_factory=new_evidence_id)
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "evidence_class", EvidenceClass(self.evidence_class))
        set_(self, "scope", frozenset(Capability(c) for c in self.scope))
        set_(self, "strength", dict(self.strength))
        issued = _optional_utc(self.issued_at)
        if issued is None:
            raise ValueError("issued_at is required")
        set_(self, "issued_at", issued)
        set_(self, "expires_at", _optional_utc(self.expires_at))
        set_(self, "revoked_at", _optional_utc(self.revoked_at))
        if not self.id:
            raise ValueError("id must not be empty")

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and utc(now) >= self.expires_at

    def is_revoked(self, now: datetime) -> bool:
        return self.revoked_at is not None and self.revoked_at <= utc(now)

    def to_dict(self) -> dict[str, Any]:
        def ts(value: datetime | None) -> str | None:
            return None if value is None else format_timestamp(value)

        return {
            "id": self.id,
            "class": self.evidence_class.value,
            "subject": {"agent_id": self.subject.agent_id, "version": self.subject.version},
            "scope": sorted(c.value for c in self.scope),
            "source": {
                "name": self.source.name,
                "authorised_classes": sorted(c.value for c in self.source.authorised_classes),
            },
            "strength": dict(self.strength),
            "issued_at": ts(self.issued_at),
            "expires_at": ts(self.expires_at),
            "revoked_at": ts(self.revoked_at),
            "revocation_reason": self.revocation_reason,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Evidence":
        subject = data["subject"]
        if isinstance(subject, str):
            subject = Subject.parse(subject)
        else:
            subject = Subject(subject["agent_id"], subject["version"])
        source = data.get("source") or {}
        if isinstance(source, str):
            source = {"name": source}
        kwargs: dict[str, Any] = {}
        if data.get("id"):
            kwargs["id"] = data["id"]
        return cls(
            evidence_class=EvidenceClass(data["class"]),
            subject=subject,
            scope=frozenset(_as_iterable(data.get("scope", ()))),
            source=Source(source.get("name", ""), frozenset(source.get("authorised_classes", ()))),
            strength=data.get("strength") or {},
            issued_at=data["issued_at"],
            expires_at=data.get("expires_at"),
            content_hash=data.get("content_hash"),
            revoked_at=data.get("revoked_at"),
            revocation_reason=data.get("revocation_reason"),
            **kwargs,
        )


def _as_iterable(value: Any) -> Iterable[Any]:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return value
