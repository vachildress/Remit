<!-- SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors. -->
# Weekend 1: evidence model and ledger

## What was built

- `evidence/model.py`: the six evidence classes, eight capabilities, three levels and five admission states, plus the `Evidence`, `Subject` and `Source` dataclasses. Construction checks structure only, so incomplete evidence can still be recorded and explained.
- `evidence/admission.py`: the admission hierarchy (present, complete, sufficient, admissible, gate_eligible). Each stage records why evidence stopped there. Class-specific strength fields are declared in one table (`CLASS_FIELDS`), and `block_rate` is derived for containment tests.
- `evidence/ledger.py`: SQLite ledger with add, get, query by subject and class, expire and revoke, plus an append-only `ledger_events` table. Expiry can only be brought forward, never extended. Revocation needs a reason and happens once.
- `evidence/requirements.yaml`: the evidence each capability level needs, with a comment explaining every threshold, age limit and monitor dependency. `requirements.json` is generated from it (`make rules-json`) so the demo never depends on PyYAML, and a test fails if the two drift.
- `evidence/requirements.py`: the loader. It enforces the standing rules: containment requirements accept only `containment_test`; every world-acting capability has containment at limited and full; no capability reaches full on a single evidence class; no requirement is looser than its class age limit; every level lists its monitors explicitly against a monitor definition that says what healthy means; full depends on every monitor limited depends on.
- `evidence/support.py`: the reasoning behind `remit evidence explain`. For each level it lists the evidence that met each requirement, why each candidate failed, and what evidence would change the outcome.
- `cli.py`: `remit evidence add | list | show | expire | revoke | explain`.
- `demo.py`: `make demo` / `uv run demo`, on a synthetic coding agent.
- `docs/uk-mapping.md`: a stub recording the three intended UK mappings, to be completed in weekend 7.
- 176 pytest tests, including edges: expiry is exclusive at the instant of expiry, revocation takes effect from its timestamp, monitors time out exactly after their heartbeat window, and expiring already expired evidence is refused rather than extending it.

## How the four claims show up so far

1. Per capability: `explain` answers per capability and level, not a single verdict.
2. Containment gate: behavioural evidence is rejected for a containment requirement in two places, at rules load time and again at evaluation time, so a loosened rules file still cannot let an eval through. The explanation says why.
3. Monitor health: a real check against the ledger, not a stub. Each monitor_health record in the ledger carries a state, a last heartbeat and a measured effectiveness. At evaluation time the latest report from each monitor must say healthy, its heartbeat must be within the timeout the rules set for that monitor, and its effectiveness must meet the rules' minimum. Support contracts as the clock moves, with no one acting. What does not exist yet is a heartbeat feed: a heartbeat is recorded by adding a new monitor_health record. That feed, and the outcome monitor, are weekend 6.
4. UK profile: `human_attestation` carries an optional `smf_function` and `standards_evidence` an optional `tier`. No logic uses them yet. The intended mappings are in `docs/uk-mapping.md`.

## What broke

- **Unreadable `explain` output.** The first version listed every candidate for every requirement, including evidence scoped to other capabilities, and repeated inherited requirements under full. It now shows only in-scope candidates, lists ignored out-of-scope ids on one line, and collapses inherited requirements to one line.
- **Two test failures on the first run, both fixed by changing the test, not the code.**
  - `test_structural_validation` passed an unknown class to the test fixture `make_evidence`, which failed with a `KeyError` while looking up default strength fields, before the model was ever reached. The test was checking nothing. It was rewritten to build a valid object first and then pass the bad class straight to `Evidence`. In the follow-up it was split into three tests that each assert the specific rejection message. I checked by hand that the class test fails when the model's class validation is removed.
  - `test_eval_alone_never_opens_a_world_acting_capability[read_data]` assumed `read_data` could not reach full on an eval plus a red team report. Under the draft rules it can, correctly: `read_data` is not world acting and full needed exactly those two classes. The test was rewritten to cover only world-acting capabilities and to include every other class of evidence except containment, which makes it stronger. That dropped coverage of `read_data` and `budget`, so `test_eval_alone_does_not_reach_full_read_data` was added in the follow-up.
- **Tag push failed.** `git push origin weekend-1` was cut off with "unexpected disconnect while reading sideband packet" four times, while the branch push succeeded. The session's git proxy most likely allows pushes only to the session branch. The tag exists only in the container; weekend-1 will be tagged on main from GitHub after merge instead.
- **Remote rename not reachable from the session.** After the repository was renamed to remit on GitHub, this session's GitHub access still only knows it by its old name: attaching `vachildress/remit` was refused and the proxy did not authenticate the new URL. The remote was left on the old URL, which GitHub redirects, so pushes still work. A new session started against `remit` will pick up the new name.
- **A real bug found while tightening monitors.** Any healthy monitor_health record inside its heartbeat window satisfied a monitor requirement, even if a newer record from the same monitor said degraded. A monitor that reported its own failure could be propped up for up to a heartbeat window by its previous report. Now only the latest unrevoked report per monitor counts, and earlier ones are shown as superseded.

## Tests changed in the follow-up, and why

- `test_requirements.py` was rewritten because the file format changed (per-level `monitors` lists, `age_limits`, monitor definitions). It gained tests for each new loader rule.
- The `full_set` helper in `test_support.py` read `requirement.monitor` as a string; it is now a monitor definition. The helper also now sets each monitor's effectiveness exactly at that monitor's minimum, so the boundary is exercised.
- `test_wrong_monitor_does_not_count` asserted the old message "needs 'sandbox-monitor'". Reports from other monitors are no longer listed as candidates, so it now asserts "no report from monitor 'sandbox-monitor' ... is scoped to code_execution". The outcome it checks (the capability drops to limited) is unchanged.
- `test_full_on_a_single_class_is_rejected` first failed because the mutation also broke the age limit, so the loader rejected it for the wrong reason. The mutation now sets a valid age, so the test reaches the single-class check.

## Decisions, and what I changed my mind about

- **No new dependencies beyond PyYAML.** Standard library (dataclasses, sqlite3, argparse), pytest, and PyYAML once approved. Pydantic was not needed.
- **JSON, then YAML with a JSON mirror.** Weekend 1 started with JSON because PyYAML was not approved. With it approved, YAML is the source of truth because it can carry comments, and the JSON mirror keeps the demo independent of the parser.
- **Monitor timeouts belong to the rules, not the evidence.** At first the heartbeat timeout came only from the monitor_health record itself, defaulting to 300 seconds, which let the evidence declare its own freshness. The rules file now sets each monitor's timeout and minimum effectiveness; the evidence's own timeout still applies, and the stricter of the two wins.
- **Monitor dependencies are explicit per level.** At first a monitor was just another requirement and inherited implicitly from limited to full. Each level now lists its monitors, as `[]` when it has none.
- **Age limits tightened.** The first draft allowed evals up to 180 days and attestations up to 365. The class limits are now eval_result 30, red_team_report 90, containment_test 30 and human_attestation 90 days, enforced by the loader.
- **`explain` is not the policy evaluator.** It reports what the ledger supports against the requirements. It does not apply tier ceilings, the "restoring needs a human attestation" rule, or enforcement. Those belong to weekend 2.
- **Source authority is a list of classes on the source record.** Enough to make admissibility checkable, but self-declared. A registry of authorised producers is a question for later.
- **Evidence is per agent version.** Evidence about 0.9.0 never supports 1.0.0.

## Where the requirements rules could not be applied exactly

- `standards_evidence` age "per its tier": tiers are not modelled yet and no requirement uses standards evidence, so no tier-based limit exists. The loader instead forces any requirement that uses a class without an age limit to set `max_age_days` explicitly.
- `code_execution` full uses a 14 day limit for its all-boundary containment test, stricter than the 30 day class limit. It is more conservative, not less, but it departs from the stated number.
