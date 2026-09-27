# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""SQLite evidence ledger.

Evidence is append-only apart from two withdrawals: expiry can be brought
forward and evidence can be revoked. Neither can be undone. Every change is
also written to an append-only event log so the history can be audited.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .model import (
    Capability,
    Evidence,
    EvidenceClass,
    Source,
    Subject,
    format_timestamp,
    parse_timestamp,
    utc,
    utcnow,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    id                TEXT PRIMARY KEY,
    evidence_class    TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    agent_version     TEXT NOT NULL,
    scope             TEXT NOT NULL,
    source            TEXT NOT NULL,
    strength          TEXT NOT NULL,
    issued_at         TEXT NOT NULL,
    expires_at        TEXT,
    content_hash      TEXT,
    revoked_at        TEXT,
    revocation_reason TEXT,
    recorded_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_subject_class
    ON evidence (agent_id, agent_version, evidence_class);
CREATE TABLE IF NOT EXISTS ledger_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    event       TEXT NOT NULL,
    at          TEXT NOT NULL,
    detail      TEXT
);
"""


class LedgerError(Exception):
    pass


class EvidenceNotFound(LedgerError):
    pass


def _db_ts(value: datetime | None) -> str | None:
    # Fixed width so that text order matches time order.
    return None if value is None else utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _from_db_ts(value: str | None) -> datetime | None:
    return None if value is None else parse_timestamp(value)


class Ledger:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def add(self, evidence: Evidence, recorded_at: datetime | None = None) -> Evidence:
        at = recorded_at or utcnow()
        source = {
            "name": evidence.source.name,
            "authorised_classes": sorted(c.value for c in evidence.source.authorised_classes),
            "role": evidence.source.role,
        }
        try:
            with self._conn:
                self._conn.execute(
                    """INSERT INTO evidence (id, evidence_class, agent_id, agent_version, scope,
                           source, strength, issued_at, expires_at, content_hash, revoked_at,
                           revocation_reason, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        evidence.id,
                        evidence.evidence_class.value,
                        evidence.subject.agent_id,
                        evidence.subject.version,
                        json.dumps(sorted(c.value for c in evidence.scope)),
                        json.dumps(source),
                        json.dumps(dict(evidence.strength), sort_keys=True),
                        _db_ts(evidence.issued_at),
                        _db_ts(evidence.expires_at),
                        evidence.content_hash,
                        _db_ts(evidence.revoked_at),
                        evidence.revocation_reason,
                        _db_ts(at),
                    ),
                )
                self._log(evidence.id, "added", at, None)
        except sqlite3.IntegrityError as exc:
            raise LedgerError(f"evidence {evidence.id} is already in the ledger") from exc
        return evidence

    def get(self, evidence_id: str) -> Evidence:
        row = self._conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise EvidenceNotFound(f"no evidence with id {evidence_id}")
        return self._to_evidence(row)

    def query(
        self,
        agent_id: str | None = None,
        version: str | None = None,
        evidence_class: EvidenceClass | str | None = None,
    ) -> list[Evidence]:
        clauses, params = [], []
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if version is not None:
            clauses.append("agent_version = ?")
            params.append(version)
        if evidence_class is not None:
            clauses.append("evidence_class = ?")
            params.append(EvidenceClass(evidence_class).value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM evidence {where} ORDER BY issued_at, id", params
        ).fetchall()
        return [self._to_evidence(r) for r in rows]

    def for_subject(self, subject: Subject) -> list[Evidence]:
        return self.query(agent_id=subject.agent_id, version=subject.version)

    def expire(self, evidence_id: str, at: datetime | None = None) -> Evidence:
        """Bring the expiry forward to ``at``. Expiry can never be extended."""
        at = utc(at or utcnow())
        current = self.get(evidence_id)
        if current.expires_at is not None and current.expires_at <= at:
            raise LedgerError(
                f"evidence {evidence_id} already expired at {format_timestamp(current.expires_at)}"
            )
        with self._conn:
            self._conn.execute(
                "UPDATE evidence SET expires_at = ? WHERE id = ?", (_db_ts(at), evidence_id)
            )
            previous = None if current.expires_at is None else format_timestamp(current.expires_at)
            self._log(evidence_id, "expired", at, json.dumps({"previous_expiry": previous}))
        return self.get(evidence_id)

    def revoke(self, evidence_id: str, reason: str, at: datetime | None = None) -> Evidence:
        if not reason or not reason.strip():
            raise LedgerError("a revocation needs a reason")
        at = utc(at or utcnow())
        current = self.get(evidence_id)
        if current.revoked_at is not None:
            raise LedgerError(
                f"evidence {evidence_id} was already revoked at {format_timestamp(current.revoked_at)}"
            )
        with self._conn:
            self._conn.execute(
                "UPDATE evidence SET revoked_at = ?, revocation_reason = ? WHERE id = ?",
                (_db_ts(at), reason.strip(), evidence_id),
            )
            self._log(evidence_id, "revoked", at, json.dumps({"reason": reason.strip()}))
        return self.get(evidence_id)

    def events(self, evidence_id: str | None = None) -> Iterator[sqlite3.Row]:
        if evidence_id is None:
            yield from self._conn.execute("SELECT * FROM ledger_events ORDER BY seq")
        else:
            yield from self._conn.execute(
                "SELECT * FROM ledger_events WHERE evidence_id = ? ORDER BY seq", (evidence_id,)
            )

    def _log(self, evidence_id: str, event: str, at: datetime, detail: str | None) -> None:
        self._conn.execute(
            "INSERT INTO ledger_events (evidence_id, event, at, detail) VALUES (?, ?, ?, ?)",
            (evidence_id, event, _db_ts(at), detail),
        )

    @staticmethod
    def _to_evidence(row: sqlite3.Row) -> Evidence:
        source = json.loads(row["source"])
        return Evidence(
            id=row["id"],
            evidence_class=EvidenceClass(row["evidence_class"]),
            subject=Subject(row["agent_id"], row["agent_version"]),
            scope=frozenset(Capability(c) for c in json.loads(row["scope"])),
            source=Source(source["name"], frozenset(source["authorised_classes"]), source.get("role", "developer")),
            strength=json.loads(row["strength"]),
            issued_at=_from_db_ts(row["issued_at"]),
            expires_at=_from_db_ts(row["expires_at"]),
            content_hash=row["content_hash"],
            revoked_at=_from_db_ts(row["revoked_at"]),
            revocation_reason=row["revocation_reason"],
        )
