<!-- SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors. -->
# remit: evidence-gated authority for AI agents

An assurance layer that decides, per capability, what an AI agent may do, based on typed assurance evidence with provenance and expiry. It is designed to sit behind an existing enforcement point rather than replace one. See `CLAUDE.md` for the full brief.

Status: weekend 2 of 8. The evidence model and ledger (weekend 1), and grant policy with enforcement through Microsoft's Agent Governance Toolkit (weekend 2), exist.

## Quick start

```sh
make demo          # or: uv run demo
make test          # or: uv run pytest
make rules-json    # regenerate requirements.json after editing requirements.yaml
```

The demo seeds a synthetic ledger for a coding agent and shows:

- a perfect `eval_result` does not open `network_out`, because containment is a separate gate;
- `code_execution` drops from full to limited when its sandbox monitor stops sending heartbeats;
- a tier ceiling capping `code_execution` at limited although the evidence supports full;
- `git.push_branch` going from deny to hold when the only thing missing is a human attestation, then to allow once it is recorded;
- `tests.run` going from allow to deny when its sandbox certificate expires;
- `git.merge_main` denied as a red line, and the grant history with the cause of every change.

## The `remit evidence` CLI

```sh
uv run remit evidence add --class eval_result --agent coder --version 1.0 \
    --scope code_execution,repo_write --source eval-lab --source-authority eval_result \
    --strength suite=synthetic-coding --strength pass_rate=0.94 --strength samples=400 \
    --expires-in-days 90 --artefact path/to/eval-log.json
uv run remit evidence list [--agent coder] [--version 1.0] [--class eval_result]
uv run remit evidence show <id>
uv run remit evidence expire <id>
uv run remit evidence revoke <id> --reason "suite leaked into training data"
uv run remit evidence explain code_execution --agent coder --version 1.0   # or: explain all
```

The ledger is `./evidence.db` unless `--db` or `$REMIT_LEDGER` says otherwise. `--now` evaluates as if at another time. `add --file` accepts a JSON object or a list of them.

## Grants and enforcement

`remit.policy` turns the ledger into a grant per capability: the level, the evidence supporting it, the monitors it relies on, the attestation that authorised it, and a plain-English explanation. Contraction is automatic; expansion needs a `human_attestation` naming the agent version, capability and level, issued after the supporting evidence; a model risk tier caps every capability; a delegated envelope must be a subset of its parent's. Every change of level is recorded with its cause.

`remit.enforcement` maps tools to capabilities and levels (`src/remit/enforcement/tools.yaml`) and decides allow, deny or hold. remit does not intercept calls. The AGT adapter translates the envelope into an AGT policy document on every call, AGT's policy evaluator makes the decision, and held calls go to AGT's approval queue. It plugs into AGT's framework integrations as a `ToolCallInterceptor`. AGT's policy kernel is the optional `agt` extra (installed with the dev dependencies); without it remit uses a stub enforcement point.

```sh
uv run remit grant show coder-agent@0.2.0
uv run remit grant history coder-agent
uv run remit check coder-agent@0.2.0 git.push_branch [--pep agt|stub]
```

## Evidence admission states

After the Agile-V Assurance Spine, each piece of evidence reaches one of:

| State | Meaning |
|---|---|
| present | recorded in the ledger |
| complete | subject, scope, source, expiry, sha256 content hash and the class-specific strength fields are all filled in |
| sufficient | strength fields are well formed and in range |
| admissible | the source is authorised for the class, and the evidence is issued, unexpired and unrevoked |
| gate_eligible | usable to gate a capability now; monitor_health must also be healthy with a heartbeat inside its timeout |

Only gate eligible evidence counts towards a capability requirement.

## Requirements

The evidence each capability level needs is in `src/remit/evidence/requirements.yaml`, with the reasoning for every threshold, age limit and monitor dependency as comments. `requirements.json` is generated from it with `make rules-json`, so the demo never depends on the YAML parser; a test fails if the two drift apart. The loader enforces the standing rules: containment requirements accept only `containment_test`, every world-acting capability needs containment at limited and full, no capability reaches full on a single evidence class, no requirement is looser than its class age limit, and every level names its monitors explicitly.

The UK financial services mapping is recorded in `docs/uk-mapping.md` (a stub until weekend 7). Design principles, including "evidence cannot set its own terms", are in `docs/design-principles.md`.

## Licence

MIT. See `LICENSE`.
