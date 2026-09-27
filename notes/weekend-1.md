<!-- SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors. -->
# Weekend 1: evidence model and ledger

## What was built

- `evidence/model.py`: the six evidence classes, eight capabilities, three levels and five admission states, plus the `Evidence`, `Subject` and `Source` dataclasses. Construction checks structure only, so incomplete evidence can still be recorded and explained.
- `evidence/admission.py`: the admission hierarchy (present, complete, sufficient, admissible, gate_eligible). Each stage records why evidence stopped there. Class-specific strength fields are declared in one table (`CLASS_FIELDS`), and `block_rate` is derived for containment tests.
- `evidence/ledger.py`: SQLite ledger with add, get, query by subject and class, expire and revoke, plus an append-only `ledger_events` table. Expiry can only be brought forward, never extended. Revocation needs a reason and happens once.
- `evidence/requirements.py` and `requirements.json`: a draft of the evidence each capability level needs. Loading enforces the standing rules: a containment requirement accepts only `containment_test`, and every world-acting capability has a containment requirement at limited and full.
- `evidence/support.py`: the reasoning behind `remit evidence explain`. For each level it lists the evidence that met each requirement, why each candidate failed, and what evidence would change the outcome.
- `cli.py`: `remit evidence add | list | show | expire | revoke | explain`.
- `demo.py`: `make demo` / `uv run demo`, on a synthetic coding agent.
- 133 pytest tests, including edges: expiry is exclusive at the instant of expiry, revocation takes effect from its timestamp, monitors time out exactly after their heartbeat window, and expiring already expired evidence is refused rather than extending it.

## How the four claims show up so far

1. Per capability: `explain` answers per capability and level, not a single verdict.
2. Containment gate: behavioural evidence is rejected for a containment requirement in two places, at rules load time and again at evaluation time, so a loosened rules file still cannot let an eval through. The explanation says why.
3. Monitor health: a monitor_health record is only gate eligible while healthy and within its heartbeat timeout, so support contracts as time passes without anyone acting.
4. UK profile: `human_attestation` carries an optional `smf_function` and `standards_evidence` an optional `tier`. Their use as ceilings and restoration triggers is weekend 2 and 7 work.

## Decisions and open questions

- **No new dependencies.** Standard library only (dataclasses, sqlite3, argparse), with pytest as a dev dependency. Pydantic was not needed.
- **Requirements are JSON, not YAML, for now.** The brief says rules live in YAML, but PyYAML is not on the approved list. JSON is a subset of YAML, so the file can be renamed and parsed with PyYAML unchanged once that dependency is approved.
- **`explain` is not the policy evaluator.** It reports what the ledger supports against the requirements file. It does not apply tier ceilings, the "restoring needs a human attestation" rule, or enforcement. Those belong to weekend 2.
- **Source authority is a list of classes on the source record.** That is enough to make admissibility checkable, but it is self-declared. A registry of authorised producers is a question for later.
- **Evidence is per agent version.** Evidence about 0.9.0 never supports 1.0.0.
- **Monitor live state is a snapshot.** A heartbeat is currently a new monitor_health record. A proper heartbeat feed is weekend 6 work.

## What broke

- The first `explain` output listed every candidate for every requirement, including evidence scoped to other capabilities, and repeated inherited requirements under full. Unreadable. It now shows only in-scope candidates, lists ignored out-of-scope ids on one line, and collapses inherited requirements to one line.
- Two tests were wrong rather than the code: one assumed `read_data` could not reach full on an eval and a red team report (it can, as the rules say), and one fed a bad class into the test fixture instead of the model.
