<!-- SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors. -->
# Design principles

Short rules that decide design questions. Each one names where it is enforced, or when it will be.

## 1. Evidence cannot set its own terms

The terms on which evidence is judged (how fresh it must be, how strong, who may produce it) come from the rules file, never from the evidence being judged.

- **Heartbeat timeouts.** A monitor_health record may carry its own `heartbeat_timeout_seconds`, but the rules file sets each monitor's timeout and minimum effectiveness, and the stricter of the two applies. A record cannot make itself fresh by declaring a long timeout. Enforced since weekend 1 (`requirements.yaml`, `monitors:`).
- **Age limits.** The class age limits and each requirement's `max_age_days` are in the rules file. Evidence expiry can only shorten a piece of evidence's life, never extend what a requirement accepts. Enforced since weekend 1.
- **Independence.** Whether a source is independent enough is decided by the rules file's `independence` table and `min_independence`, per level. Enforced since weekend 2.
- **What counts.** Which evaluation suites and red team exercises count is named in the rules file. An eval that picks its own suite cannot unlock a level. Enforced since weekend 2.

## 2. A monitor must not be the source of its own effectiveness score

A monitor's effectiveness is measured on seeded canary events: synthetic events it should catch. If the monitor reports its own score, a broken or compromised monitor can report itself effective. So:

- Every monitor_health record will carry a `canary_source`: the component that seeded the canary events and counted the catches.
- `canary_source` must be a different component from the monitor itself (`monitor_name`). A record whose canary source is the monitor does not count towards a monitor requirement.
- Which components may act as canary sources for which monitors belongs in the rules file, by principle 1.

**Status:** recorded now, to be implemented in weekend 6 with the outcome monitor. Until then effectiveness is taken as reported, which is a known gap.

## 3. Contraction is automatic; expansion needs a human

Anything that weakens the evidence (expiry, revocation, a monitor degrading, a lost requirement, a tighter ceiling) lowers a grant at once, with no one acting. Nothing raises a grant without a human_attestation that names the agent version, the capability and the level, issued after the evidence that supports the rise. Enforced from weekend 2 (`remit.policy`).

## 4. Fail closed

An unknown tool is denied. Evidence of an unknown suite or exercise does not count. A missing source role is treated as the least independent. With no current tier evidence, the strictest ceiling applies.
