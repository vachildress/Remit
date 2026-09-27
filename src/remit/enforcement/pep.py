# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""The policy enforcement point (PEP) interface, and a stub PEP for tests.

remit does not intercept tool calls. A PEP is whatever sits in front of the
agent's tools: in production the Microsoft Agent Governance Toolkit, reached
through ``remit.enforcement.agt``. Every PEP recomputes the envelope from the
ledger on every call; nothing is cached.
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping, Protocol

from ..evidence.ledger import Ledger
from ..evidence.model import Capability, Level, Subject, utcnow
from ..evidence.requirements import RuleSet
from ..policy.history import refresh
from .decision import Decision, decide
from .tools import ToolTable


class PolicyEnforcementPoint(Protocol):
    name: str

    def check(self, subject: Subject, tool: str, now: datetime | None = None) -> Decision:
        """Decide one tool call for ``subject`` from the ledger as it is now."""
        ...


class StubPEP:
    """Applies remit's decisions directly. For tests and environments without AGT."""

    name = "stub"

    def __init__(
        self,
        ledger: Ledger,
        rules: RuleSet,
        table: ToolTable,
        parent_levels: Mapping[Capability, Level] | None = None,
    ) -> None:
        self.ledger = ledger
        self.rules = rules
        self.table = table
        self.parent_levels = parent_levels

    def check(self, subject: Subject, tool: str, now: datetime | None = None) -> Decision:
        envelope = refresh(self.ledger, self.rules, subject, now or utcnow(), self.parent_levels)
        decision = decide(envelope, self.table, tool)
        return Decision(**{**decision.__dict__, "enforced_by": self.name})
