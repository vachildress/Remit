<!-- SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors. -->
# remit: evidence-gated authority for AI agents

An assurance layer that decides, per capability, what an AI agent may do, based on typed assurance evidence with provenance and expiry. It is designed to sit behind an existing enforcement point rather than replace one. See `CLAUDE.md` for the full brief.

Status: weekend 1 of 8. The evidence model, ledger, admission states and the `remit evidence` CLI exist. Grant policy and enforcement come next.

## Quick start

```sh
make demo          # or: uv run demo
make test          # or: uv run pytest
```

The demo seeds a synthetic ledger for one coding agent and shows three things:

- a perfect `eval_result` does not open `network_out`, because containment is a separate gate;
- `code_execution` drops from full to limited when its sandbox monitor stops sending heartbeats;
- revoking containment evidence withdraws the capability entirely, whatever the evals say.

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

## Evidence admission states

After the Agile-V Assurance Spine, each piece of evidence reaches one of:

| State | Meaning |
|---|---|
| present | recorded in the ledger |
| complete | subject, scope, source, expiry, sha256 content hash and the class-specific strength fields are all filled in |
| sufficient | strength fields are well formed and in range |
| admissible | the source is authorised for the class, and the evidence is issued, unexpired and unrevoked |
| gate_eligible | usable to gate a capability now; monitor_health must also be healthy with a heartbeat inside its timeout |

Only gate eligible evidence counts towards a capability requirement. The draft requirements live in `src/remit/evidence/requirements.json`.

## Licence

MIT. See `LICENSE`.
