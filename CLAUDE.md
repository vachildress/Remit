# Project brief: evidence-gated authority for AI agents

Read this file fully before writing any code. It defines what we are building, what we are deliberately not building, and the order of work. When in doubt, ask before adding scope.

## What this is

An open-source assurance layer that decides, per capability, what an AI agent is permitted to do, based on typed assurance evidence with provenance and expiry. It plugs into an existing enforcement point rather than replacing one.

Metaphor used in docs: a nervous system. Sensors (monitors), reflexes (automatic contraction of permissions), brain (deliberate grants against evidence). This layer is the brain plus the evidence it reasons over.

## The four claims the code must demonstrate

1. Per-capability runtime grants derived from AI-assurance evidence, not a single deploy/no-deploy verdict.
2. Containment evidence is a separate, non-substitutable gate. Behavioural evaluation results can never satisfy a containment requirement, because models can detect evaluation.
3. Monitor health is a live precondition. When a monitor degrades or stops, the permissions that depend on it contract automatically.
4. The evidence model can be expressed in UK financial-services terms: a named senior manager attestation (SM&CR) with expiry, a model risk tier (PRA SS1/23) as a permission ceiling, and consumer outcome monitoring (Consumer Duty) as a monitor-health source.

Every design decision should serve one of these. If a feature serves none, leave it out.

## What we are NOT building

- Not a new permission broker, gateway, or policy engine. Enforcement is delegated to Microsoft's Agent Governance Toolkit (MIT). Progent is the documented alternative. Do not reimplement tool-call interception.
- Not a behavioural trust or reputation score. Trust scores computed from runtime traces already exist (Microsoft AGT). Our grants derive from evidence objects, not track record.
- Not a deployment certificate system. Signed deploy/no-deploy certificates with expiry already exist (ADAS, arXiv 2601.08869; Trust Certificate, arXiv 2606.04037). We operate at capability granularity at runtime.
- Not an identity or delegation system. No DIDs, no OAuth flows, no agent-to-agent protocol work.
- Not a product. No auth, no multi-tenancy, no cloud deployment.

## Prior art to reuse vocabulary from (do not reinvent)

- Agile-V Assurance Spine (arXiv 2609.28216): evidence admission hierarchy (present, complete, sufficient, admissible, gate-eligible). Use these words for evidence states.
- OSCAL for AI (arXiv 2604.13767): field names for standards evidence.
- Cognitive Admission Control (arXiv 2609.16313): obligations with predicates, evidence classes, scope, freshness.
- AISI control safety case (arXiv 2501.17315) and AI Control Levels (arXiv 2504.05259): the basis for the containment gate.
- Black-Box Simplex (arXiv 2102.12981): monitor-gated authority.

## Stack

- Python 3.11+, uv for environment and dependencies.
- Microsoft Agent Governance Toolkit as the enforcement point (policy engine and middleware).
- LangGraph for demo agents.
- SQLite for the evidence ledger, via a thin repository layer. No ORM beyond sqlite3 or sqlmodel.
- FastAPI for the read-only API the dashboard consumes.
- React plus Vite for the dashboard (weekend 8 only).
- Docker for sandboxed code execution in the containment tests.
- pytest for everything. Every module gets tests before it is considered done.

Ask before adding any dependency not listed here.

## Repository layout

```
<REPO_NAME>/
  README.md
  CLAUDE.md
  pyproject.toml
  src/<pkg>/
    evidence/      # schema, ledger, admission states
    policy/        # capability definitions, grant rules, evaluator
    enforcement/   # adapter to Microsoft AGT
    monitors/      # monitor health as evidence
    sensors/       # injection detector, scope drift, test tampering
    scenarios/     # coding, security, consumer demo agents
    api/           # FastAPI read-only endpoints
  dashboard/       # React app, weekend 8
  tests/
  notes/           # one markdown file per weekend: what was built, what broke
  docs/            # prior-art table, evidence model, UK mapping
```

## Evidence model

Six evidence classes. Every evidence object has:

- id, class, subject (agent id and version), scope (which capabilities it can support)
- source (who produced it, and their authority to produce that class)
- strength (class-specific; for example pass rate, coverage, escape attempts blocked)
- issued_at, expires_at, revoked_at, revocation_reason
- admission_state: present, complete, sufficient, admissible, gate_eligible
- content_hash of the underlying artefact

Classes:

1. eval_result: behavioural evaluation on a named suite, Inspect-compatible output preferred.
2. red_team_report: adversarial testing findings with scope and residual risk.
3. containment_test: sandbox and boundary tests (file system, network egress, credential access, process escape). This class alone can satisfy a containment requirement.
4. monitor_health: heartbeat and effectiveness of a named monitor. Has a live state, not just a timestamp.
5. human_attestation: a named person, their role, what they attest to, expiry. UK profile: SMF role and function.
6. standards_evidence: mapping to a standard clause or regulatory tier. UK profile: SS1/23 model tier, which acts as a ceiling on permission level.

## Capabilities and levels

Eight capabilities, each at none, limited or full:

read_data, write_data, network_out, code_execution, repo_write, external_comms, delegation, budget (compute plus unattended time)

## Grant rules

- Each capability level names required evidence: classes, minimum strength, maximum age, and whether the requirement is containment-class. Rules live in a YAML file, not code.
- A requirement marked containment can only be satisfied by containment_test evidence. eval_result and red_team_report never count towards it.
- Any capability that acts on the world (write_data, network_out, code_execution, repo_write, external_comms, delegation) requires at least one containment requirement at limited and above.
- A capability level that depends on a monitor requires monitor_health in a healthy state. If the monitor degrades, the level drops to the highest level that does not depend on it. This is automatic.
- Expiry and revocation withdraw grants automatically. Restoring or expanding a grant always needs a human_attestation event.
- standards_evidence with a tier sets a ceiling: no capability may exceed the level allowed for that tier regardless of other evidence.
- The evaluator must produce an explanation for every decision: which evidence supported it, which requirement failed, and what would change the outcome.

## Scenarios (build order)

1. Coding agent: read repo, run tests, write branch, open PR, merge. Branch write and PR earned from eval_result and human review agreement. Sensor: test file edits revoke repo_write. Red line: no merge to main, no credential reads.
2. Security triage agent: read logs, enrich, recommend, block IP, isolate host. Injection detector on ingested log content. Demonstrates the containment gate: perfect eval_result, no host isolation until containment_test exists. The poisoned log line contracts permissions and holds the action for a human.
3. Consumer switching agent (generic: insurance, energy, broadband; rotate the product in docs): read profile, fetch quotes, compare, recommend, submit switch. Outcome monitoring feeds monitor_health; degradation drops submit_switch to recommend-only. Uses the three UK evidence profiles.

All data synthetic. No real customer data, no real company names, no real logs.

## Standing rules

- Synthetic data only. No material from any employer, past or present.
- MIT licence. Every file gets the header.
- UK spelling in all docs and comments. No em dashes in any prose.
- One command runs everything: `make demo` (or `uv run demo`) must work on a fresh clone.
- Every weekend ends with a notes/weekend-N.md file and a tagged commit.
- Re-check prior art before writing any "nobody has done this" sentence in docs.
- Do not write the LinkedIn posts. Those are written by hand after the build.

## Weekend 1 scope (do this first, nothing else)

Goal: the evidence model and ledger.

1. Implement the evidence schema above as dataclasses or pydantic models.
2. SQLite ledger with add, get, query by subject and class, expire, revoke.
3. Admission state computed from completeness and freshness rules.
4. A CLI: `evidence add`, `evidence list`, `evidence expire`, `evidence revoke`, `evidence explain <capability>` which prints, in plain English, whether the ledger currently supports each level of a capability and why.
5. Tests for all of the above, including expiry and revocation edge cases.
6. notes/weekend-1.md.

Done when the CLI can add, expire and revoke evidence and `explain` gives a correct, readable answer for every capability. Do not start on the policy evaluator or the AGT adapter until this is done and tested.

## Weekends 2 to 8 (summary, detail to follow each week)

2. Grant policy and AGT adapter. 3. Coding agent demo. 4. Containment tests and gate. 5. Security agent demo. 6. Monitor health and consumer agent. 7. UK evidence profiles and mapping doc. 8. Dashboard, README, v0.1 tag.
