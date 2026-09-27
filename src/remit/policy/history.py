# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""Grant state and grant history, stored alongside the evidence ledger.

``refresh`` is the one way grants move: it reads the last recorded level of
every capability, evaluates the envelope, records every change of level with
its cause in the append-only ``grant_events`` table, and returns the
envelope. Changes are recorded when an evaluation first observes them (on a
tool check or a ``grant show``); the event says what caused the change, for
example which evidence expired and when.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from ..evidence.ledger import Ledger
from ..evidence.model import Capability, Level, Subject, parse_timestamp, utc
from ..evidence.requirements import RuleSet
from .evaluator import Envelope, evaluate_envelope

SCHEMA = """
CREATE TABLE IF NOT EXISTS grant_state (
    agent_id       TEXT NOT NULL,
    agent_version  TEXT NOT NULL,
    capability     TEXT NOT NULL,
    level          TEXT NOT NULL,
    attestation_id TEXT,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (agent_id, agent_version, capability)
);
CREATE TABLE IF NOT EXISTS grant_events (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id       TEXT NOT NULL,
    agent_version  TEXT NOT NULL,
    capability     TEXT NOT NULL,
    old_level      TEXT NOT NULL,
    new_level      TEXT NOT NULL,
    cause_kind     TEXT NOT NULL,
    cause_ref      TEXT,
    detail         TEXT NOT NULL,
    causes         TEXT NOT NULL,
    at             TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class GrantEvent:
    seq: int
    subject: Subject
    capability: Capability
    old_level: Level
    new_level: Level
    cause_kind: str
    cause_ref: str | None
    detail: str
    at: datetime


def _ts(value: datetime) -> str:
    return utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class GrantStore:
    def __init__(self, ledger: Ledger) -> None:
        self._conn: sqlite3.Connection = ledger.connection
        self._conn.executescript(SCHEMA)

    def current(self, subject: Subject) -> dict[Capability, tuple[Level, str | None]]:
        rows = self._conn.execute(
            "SELECT capability, level, attestation_id FROM grant_state WHERE agent_id = ? AND agent_version = ?",
            (subject.agent_id, subject.version),
        ).fetchall()
        return {Capability(r["capability"]): (Level(r["level"]), r["attestation_id"]) for r in rows}

    def record(self, envelope: Envelope) -> list[GrantEvent]:
        """Store the envelope's levels and append an event for every change."""
        s = envelope.subject
        at = _ts(envelope.as_of)
        known = self.current(s)
        with self._conn:
            for cap, g in envelope.grants.items():
                stored = known.get(cap)
                if stored is None or stored != (g.level, g.attestation):
                    self._conn.execute(
                        """INSERT INTO grant_state (agent_id, agent_version, capability, level, attestation_id, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?)
                           ON CONFLICT (agent_id, agent_version, capability)
                           DO UPDATE SET level = excluded.level, attestation_id = excluded.attestation_id,
                                         updated_at = excluded.updated_at""",
                        (s.agent_id, s.version, cap.value, g.level.value, g.attestation, at),
                    )
                if not g.changed:
                    continue
                primary = g.causes[0] if g.causes else None
                self._conn.execute(
                    """INSERT INTO grant_events (agent_id, agent_version, capability, old_level, new_level,
                           cause_kind, cause_ref, detail, causes, at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        s.agent_id,
                        s.version,
                        cap.value,
                        g.previous.value,
                        g.level.value,
                        primary.kind if primary else "unknown",
                        primary.ref if primary else None,
                        "; ".join(c.detail for c in g.causes) or "no recorded cause",
                        json.dumps([c.__dict__ for c in g.causes]),
                        at,
                    ),
                )
        return self.history(s)

    def history(self, subject: Subject | None = None, agent_id: str | None = None) -> list[GrantEvent]:
        clauses, params = [], []
        if subject is not None:
            clauses += ["agent_id = ?", "agent_version = ?"]
            params += [subject.agent_id, subject.version]
        elif agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(f"SELECT * FROM grant_events {where} ORDER BY seq", params).fetchall()
        return [
            GrantEvent(
                seq=r["seq"],
                subject=Subject(r["agent_id"], r["agent_version"]),
                capability=Capability(r["capability"]),
                old_level=Level(r["old_level"]),
                new_level=Level(r["new_level"]),
                cause_kind=r["cause_kind"],
                cause_ref=r["cause_ref"],
                detail=r["detail"],
                at=parse_timestamp(r["at"]),
            )
            for r in rows
        ]


def refresh(
    ledger: Ledger,
    rules: RuleSet,
    subject: Subject,
    now: datetime,
    parent_levels: Mapping[Capability, Level] | None = None,
) -> Envelope:
    """Evaluate the envelope from the ledger and record any change of level."""
    store = GrantStore(ledger)
    envelope = evaluate_envelope(
        ledger.for_subject(subject), rules, subject, now, store.current(subject), parent_levels
    )
    store.record(envelope)
    return envelope
