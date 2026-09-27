# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""Enforcement: remit's decisions put in front of tool calls through an existing PEP."""

from __future__ import annotations

from typing import Mapping

from ..evidence.ledger import Ledger
from ..evidence.model import Capability, Level
from ..evidence.requirements import RuleSet
from .decision import ALLOW, DENY, HOLD, Decision, decide
from .pep import PolicyEnforcementPoint, StubPEP
from .tools import ToolSpec, ToolTable, load_tool_table


def agt_available() -> bool:
    try:
        import agent_os.policies  # noqa: F401
    except ImportError:
        return False
    return True


def make_pep(
    ledger: Ledger,
    rules: RuleSet,
    table: ToolTable,
    kind: str | None = None,
    parent_levels: Mapping[Capability, Level] | None = None,
) -> PolicyEnforcementPoint:
    """The AGT adapter when AGT is installed, otherwise the stub, unless ``kind`` says."""
    kind = kind or ("agt" if agt_available() else "stub")
    if kind == "agt":
        from .agt import AGTAdapter

        return AGTAdapter(ledger, rules, table, parent_levels=parent_levels)
    if kind == "stub":
        return StubPEP(ledger, rules, table, parent_levels=parent_levels)
    raise ValueError(f"unknown enforcement point {kind!r}; use agt or stub")


__all__ = [
    "ALLOW",
    "DENY",
    "HOLD",
    "Decision",
    "PolicyEnforcementPoint",
    "StubPEP",
    "ToolSpec",
    "ToolTable",
    "agt_available",
    "decide",
    "load_tool_table",
    "make_pep",
]
