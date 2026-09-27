<!-- SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors. -->
# Weekend 2: grant policy and enforcement adapter

## What was built

**Requirements review (first commit).**
- Every full level needs a `human_attestation`: `read.attest`, `net.attest` and `exec.attest` were added, and the loader rejects a full level without one.
- `code_execution` full also needs a sandbox escape red team with residual risk low and no open findings (`exec.redteam`).
- Evaluations are pinned to named suites and red teams to named exercises (`includes: suite:` and `includes: exercise:`; `exercise` is a new required field on `red_team_report`). The loader rejects an unpinned eval or red team requirement. Unknown suites and exercises do not count, and the explanation says so.
- Sources carry a `role`: developer, internal_independent or external. A missing role counts as developer. An `independence` table sets a floor per level, which also applies to requirements inherited from limited. Full containment and red team evidence must be at least internal_independent. Requirements may ask for more with `min_independence`.
- `docs/design-principles.md` records "evidence cannot set its own terms" and the canary source rule for monitors, which is to be implemented in weekend 6.

**Weekend 2 (second commit).**
- `policy/evaluator.py` computes the envelope: a `Grant` per capability with:
  - the level, and the level the evidence alone supports
  - the ceiling and where it comes from
  - the supporting evidence ids and the monitors relied on
  - the attestation that authorised the level, and any held level
  - the unmet requirements per level, with the reasons each record failed and a remedy
  - the causes of any change, and a plain-English explanation
- The grant rules it applies:
  - **Contraction is automatic.** Expiry, revocation, monitor degradation, a lost requirement, a tighter ceiling or a narrower parent all lower the grant at once.
  - **Expansion needs a human.** A level only rises when a `human_attestation` for that agent version, scoped to the capability, with `grants_level` at or above the target, is gate eligible, within the 90 day attestation limit, and was issued after a set of evidence sufficient for the target level already existed.
  - **Tier ceilings.** A `tiers:` table in `requirements.yaml` has placeholder tiers 1 to 4 plus an `untiered` row. Each gives a ceiling per capability and a `max_age_days` for its standards evidence, which makes "standards_evidence age per its tier" real.
  - **Delegation attenuation.** `attenuate(parent, child, requested)` rejects any request wider than the parent's envelope, or any request from a parent without a delegation grant. Parent levels act as a ceiling on the child's own evaluation.
- `policy/history.py` holds grant state and an append-only `grant_events` table, stored in the ledger database. `refresh` evaluates the envelope, records each change of level with its cause (evidence id, expiry, monitor, attestation, ceiling, parent) and returns the envelope.
- `enforcement/`:
  - the tool table (`tools.yaml`, with a JSON mirror)
  - `decide()`, returning allow, deny or hold with an explanation and the binding requirement
  - a `PolicyEnforcementPoint` protocol, and a `StubPEP` for tests
  - `AGTAdapter`, backed by Microsoft's Agent Governance Toolkit
- New CLI commands: `remit grant show <agent@version>`, `remit grant history <agent>` and `remit check <agent@version> <tool> [--pep agt|stub]`.
- `make demo` now runs two acts:
  - Act 1 is the evidence view from weekend 1.
  - Act 2 is enforced through AGT. It shows a tier 2 ceiling capping `code_execution` at limited, `git.push_branch` going deny to hold to allow, `tests.run` going allow to deny when its three hour sandbox certificate expires, a red line, and the grant history.
- 286 tests.

## The tool-to-capability table

| Tool | Capability | Level |
|---|---|---|
| `repo.read_file` | read_data | limited |
| `records.read_bulk` | read_data | full |
| `records.write` | write_data | limited |
| `records.bulk_update` | write_data | full |
| `http.get_allowlisted` | network_out | limited |
| `http.request_any` | network_out | full |
| `tests.run` | code_execution | limited |
| `shell.run_networked` | code_execution | full |
| `git.push_branch` | repo_write | limited |
| `git.open_pr` | repo_write | limited |
| `git.merge_feature_branch` | repo_write | full |
| `email.send_template` | external_comms | limited |
| `email.send_freeform` | external_comms | full |
| `agent.spawn_sandboxed` | delegation | limited |
| `agent.spawn_unsupervised` | delegation | full |
| `job.run_capped` | budget | limited |
| `job.extend_unattended` | budget | full |
| `git.merge_main` | red line | always denied |
| `secrets.read_credentials` | red line | always denied |

Unknown tools are denied. A call is **held** only when the evidence and the ceiling already allow the level and the one thing missing is an attestation. A tier ceiling is not something a human can approve at the tool call, so a capped call is denied, not held.

## How the AGT integration works, and where its interfaces forced compromises

The dependency is `agent-os-kernel` (MIT), which is AGT's policy kernel from the `microsoft/agent-governance-toolkit` repository. It is not the full `agent-governance-toolkit-core`, which pulls in cryptography, aiohttp, httpx and more. It is an optional extra (`agt`) and is included in the dev dependencies, so `make demo` and the tests use it on a fresh clone. The evidence and policy layers still need only the standard library and PyYAML.

remit decides and AGT enforces. On every call the adapter:
1. recomputes the envelope from the ledger
2. writes an AGT `PolicyDocument` with one rule per tool
3. has AGT's `PolicyEvaluator` evaluate the call

The adapter implements AGT's `ToolCallInterceptor` protocol, so AGT's framework integrations call it in front of the agent's tools, and it composes with other AGT interceptors. It does not intercept anything itself. A test checks that AGT's decision matches the stub's for every tool across five scenarios.

The compromises:
1. **No hold action.** AGT policy actions are allow, deny, audit and block. A held tool is written as a deny rule named `remit:hold:<tool>`, and the adapter recognises that name, files the call in AGT's `EscalationHandler` approval queue and reports it as held.
2. **Conditions are single-field comparisons.** AGT conditions cannot express evidence, time or grant logic. So the policy is regenerated from the envelope on every call, matching only on `tool_name`. AGT enforces a policy remit wrote; it does not reason about evidence. That is the intended split, but it means the AGT policy on its own is a snapshot, not the rules.
3. **`ToolCallResult` is binary.** Hold and deny are both `allowed=False`, told apart by `audit_entry["remit_decision"]`. A framework integration that reads only `allowed` treats a hold as a deny, which fails safe but loses the "ask a human" signal.
4. **AGT's default action is allow.** The adapter sets the policy document's default to deny, so unknown tools fail closed.
5. **`ToolCallRequest` carries no time.** `intercept` uses the adapter's clock (the wall clock by default, injectable for tests). `check` accepts an explicit time. AGT's own audit timestamps and escalation timeouts use the wall clock.
6. **Pydantic deprecation warnings** come from inside AGT's own models. They are filtered in the pytest configuration, and remit's code raises none.

## How the four claims show up now

1. **Per-capability runtime grants.** `remit grant show` gives a live level per capability. `remit check` allows, denies or holds a single call from the ledger and rules alone.
2. **Containment gate.** It is unchanged and still enforced in two places. It also reaches the tool call: `tests.run` is denied the moment the sandbox certificate expires, whatever the evals say.
3. **Monitor health.** Monitor degradation or silence contracts a grant immediately and is recorded with the monitor's name as the cause. In the demo history, `repo_write` drops with `[monitor test-tamper-sensor]`.
4. **UK profile.** The mechanisms for the SS1/23 tier ceiling and for the attestation behind every expansion now exist, with placeholder values. The mapping itself is still weekend 7.

## What broke

- **The explanation hid the real cause.** For the expiry flip, the summary of why `exec.contain` failed led with the eval and red team ("can never satisfy a containment requirement") and cut off before the expired certificate. Rejections of the requirement's own class are now listed first. This was a code fix.
- **The CLI rejected options after the subcommand.** `remit grant show --db ...` failed, and so did the command the demo printed as a hint. The shared options are now accepted before or after the subcommand. This was a code fix.
- **The interceptor used the real clock.** The first interceptor tests failed because AGT's `ToolCallRequest` has no timestamp, so `intercept` evaluated test evidence against the wall clock. The adapter now takes an injectable clock (compromise 5). This was a code fix.
- **A held explanation started a sentence in lower case.** This was a code fix.
- **Tests I changed to make them pass:**
  - Weekend 1 test helpers built evidence without suites, exercises or independence, which the new rules correctly reject. `full_set` is now generated from the rules (one record per requirement, each carrying the suite or exercise that requirement names, from an external source) and moved into `conftest.py`. `eval_ev` and `redteam_ev` pin the right suite or exercise.
  - `test_explain_tracks_the_ledger` used an eval with suite `synthetic`, which no longer counts. It now names the budget suite, and a new test asserts that an unknown suite is rejected with the reason.
  - `test_full_on_a_single_class_is_rejected` no longer produced a single-class full level once every full level needs an attestation. The mutation now makes every `read_data` requirement an attestation.
  - Two Weekend 1 tests replaced containment evidence with developer-sourced records, which would now also fail the full-level independence floor and pass for the wrong reason. They now use external sources.
  - The demo tests asserted strings from the old demo. They now assert the new sequence of flips (allow, deny, deny, hold, allow, deny) and the expiry cause in the history.
  - `test_developer_certified_sandbox_blocks_full_execution_only` expected the binding requirement to be `exec.contain.full`. In fact the inherited `exec.contain` also fails the full-level independence floor, and it is reported first. That behaviour is correct, so the test now accepts either and checks that both are named.
  - Two bugs in the new tests themselves: `with_replaced` put the same replacement record in twice (duplicate id in the ledger), and the AGT agreement test generated the scenario evidence twice with different ids.
- **The repository.** It turned out to be a new, empty repository rather than a rename (see the weekend 1 notes). The full history was pushed to it unchanged.

## Checking the tests guard the rules

I broke each rule in turn and ran the suite. Every change was caught:
- ignoring the attestation timing
- expanding without an attestation
- ignoring the tier ceiling
- ignoring independence
- removing red lines
- leaving AGT's default as allow
- ignoring suite pinning

## Decisions, and open questions for review

- **Untiered means the strictest ceiling.** With no current tier evidence, the `untiered` row applies, which is the same as tier 1. So letting tier evidence lapse contracts grants rather than lifting a ceiling. The alternative, no ceiling when untiered, would let an expired tier certificate widen authority.
- **Tier evidence applies to the whole model.** Tier evidence is not matched on scope, because a model risk tier is a property of the model. If several tiers are current, the strictest applies.
- **The attestation timing test is "sufficient evidence existed before the signature", not "after the newest evidence".** A newer duplicate eval does not undo a sign-off, but a sign-off cannot pre-date the evidence it relies on. Monitor reports are left out of the timing test: heartbeats arrive every minute, so including them would make every rise race the next heartbeat. The attestation may itself satisfy an attestation requirement, so one sign-off can serve both purposes.
- **`grants_level` at or above the target counts.** Signing off full also authorises limited.
- **Grant history records changes when an evaluation first observes them**, on a tool check or a `grant show`, since there is no background process. The cause names what happened and when (for example the expiry time), and the event time is the observation time.
- **Delegation attenuation is modelled but not persisted.** `attenuate` checks a request against the parent's envelope at that moment and rejects a wider request whole, rather than trimming it. There is no delegation record in the ledger yet; that comes with the delegation monitor.
- **Grant rules that are invariants stay in code**, not as switches in the rules file: automatic contraction, attestation for expansion, attenuation and red lines. The values they use are data in the rules file: tiers, independence floors, age limits and the tool table. A switch to turn off "expansion needs a human" would defeat the point.
- **Explanations are long.** They are complete (every unmet requirement, every failing record, the remedy), which is right for `explain` and the audit trail but heavy in a CLI. A short form is a candidate for weekend 8's dashboard.

## Where I departed from the brief

- **The PEP interface and the stub PEP.** The brief allowed these if proper AGT integration was more than a weekend. The integration fitted in the weekend, but I built both anyway. The stub is what tests compare AGT against, and it keeps remit usable without the optional dependency.
