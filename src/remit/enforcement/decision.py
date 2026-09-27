# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""What remit decides about one tool call, given an envelope and the tool table.

This is the decision, not the enforcement. An enforcement point (the AGT
adapter, or the stub used in tests) turns these decisions into its own policy
and applies them to calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..evidence.model import Capability, Level
from ..policy.evaluator import Envelope
from .tools import ToolTable

ALLOW = "allow"
DENY = "deny"
HOLD = "hold"


@dataclass(frozen=True)
class Decision:
    tool: str
    outcome: str  # allow, deny or hold
    explanation: str
    capability: Capability | None = None
    required: Level | None = None
    granted: Level | None = None
    red_line: bool = False
    # What decided it, for the audit trail: "red_line", "unknown_tool",
    # "grant", "attestation" (held for one) or a requirement or ceiling.
    binding: str = ""
    # Set by an enforcement point that parks held calls in an approval queue.
    escalation_id: str | None = None
    enforced_by: str = ""


def decide(envelope: Envelope, table: ToolTable, tool: str) -> Decision:
    subject = envelope.subject
    if tool in table.red_lines:
        return Decision(
            tool, DENY, f"Denied: {tool} is a red line ({table.red_lines[tool]}). No grant unlocks it.",
            red_line=True, binding="red_line",
        )
    spec = table.tools.get(tool)
    if spec is None:
        return Decision(
            tool, DENY, f"Denied: {tool} is not in the tool table, and unknown tools are denied.",
            binding="unknown_tool",
        )
    grant = envelope[spec.capability]
    need = f"{tool} needs {spec.capability.value} at {spec.level.value}"
    base = dict(capability=spec.capability, required=spec.level, granted=grant.level)
    if grant.level.rank >= spec.level.rank:
        support = ", ".join(grant.supporting) or "no evidence"
        extra = f" Relies on monitors {', '.join(grant.monitors)}." if grant.monitors else ""
        return Decision(
            tool, ALLOW,
            f"Allowed: {need}; {subject} holds {grant.level.value}, supported by {support}.{extra}",
            binding="grant", **base,
        )
    if grant.held is not None and grant.held.rank >= spec.level.rank:
        return Decision(
            tool, HOLD,
            f"Held for a human: {need}; {subject} holds {grant.level.value}. {_sentence(grant.why_not(spec.level))}.",
            binding="attestation", **base,
        )
    return Decision(
        tool, DENY,
        f"Denied: {need}; {subject} holds {grant.level.value}. Because {grant.why_not(spec.level)}.",
        binding=_binding(envelope, spec.capability, spec.level), **base,
    )


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:]


def _binding(envelope: Envelope, capability: Capability, level: Level) -> str:
    grant = envelope[capability]
    if grant.ceiling.rank < level.rank:
        return "parent" if grant.parent_level is not None and grant.parent_level.rank < level.rank else "ceiling"
    for lvl in (Level.LIMITED, Level.FULL):
        if lvl.rank > level.rank:
            break
        if grant.unmet.get(lvl):
            return grant.unmet[lvl][0].requirement_id
    return "grant"
