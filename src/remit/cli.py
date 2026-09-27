# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""The ``remit`` command line tool: ``remit evidence``, ``remit grant`` and ``remit check``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Sequence

from .evidence.admission import assess
from .evidence.ledger import Ledger, LedgerError
from .evidence.model import (
    SOURCE_ROLES,
    Capability,
    Evidence,
    EvidenceClass,
    Source,
    Subject,
    format_timestamp,
    hash_artefact,
    parse_timestamp,
    utcnow,
)
from .evidence.admission import metric_kinds
from .evidence.requirements import RuleError, load_rules
from .evidence.support import explain_capability, render
from .enforcement import agt_available, load_tool_table, make_pep
from .enforcement.tools import ToolTableError
from .policy.history import GrantStore, refresh

LIST_FIELDS = {"boundaries_tested"}


class CliError(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db",
        default=os.environ.get("REMIT_LEDGER", "evidence.db"),
        help="ledger file (default: $REMIT_LEDGER or ./evidence.db)",
    )
    common.add_argument("--rules", help="requirements file (default: the bundled one)")
    common.add_argument("--now", help="evaluate as if it were this ISO 8601 time")
    # The same options, accepted after the subcommand too. SUPPRESS keeps a
    # subcommand from overwriting a value given before it with its default.
    leaf = argparse.ArgumentParser(add_help=False)
    for action in common._actions:
        leaf.add_argument(*action.option_strings, default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    root = argparse.ArgumentParser(prog="remit", description="Evidence-gated authority for AI agents.")
    groups = root.add_subparsers(dest="group", required=True)

    grant = groups.add_parser("grant", parents=[common], help="show live grants and their history")
    gsub = grant.add_subparsers(dest="command", required=True)
    gshow = gsub.add_parser("show", parents=[leaf], help="the current grant for every capability")
    gshow.add_argument("agent", help="agent@version")
    ghist = gsub.add_parser("history", parents=[leaf], help="every change of level, with its cause")
    ghist.add_argument("agent", help="agent, or agent@version")

    check = groups.add_parser("check", parents=[common], help="decide one tool call: allow, deny or hold")
    check.add_argument("agent", help="agent@version")
    check.add_argument("tool", help="tool name, as in the tool table")
    check.add_argument("--tools", help="tool table file (default: the bundled one)")
    check.add_argument(
        "--pep",
        choices=["agt", "stub"],
        help="enforcement point (default: agt when installed, otherwise stub)",
    )
    check.set_defaults(command="check")

    parser = groups.add_parser(
        "evidence", parents=[common], help="record assurance evidence and explain what it supports"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", parents=[leaf], help="add evidence to the ledger")
    add.add_argument("--file", help="JSON file holding one evidence object, or a list of them")
    add.add_argument("--class", dest="evidence_class", choices=[c.value for c in EvidenceClass])
    add.add_argument("--agent", help="agent id of the subject")
    add.add_argument("--version", help="agent version of the subject")
    add.add_argument("--scope", default="", help="comma separated capabilities it can support")
    add.add_argument("--source", default="", help="who produced it")
    add.add_argument(
        "--source-role",
        default="developer",
        choices=list(SOURCE_ROLES),
        help="how independent the source is of the agent's developer (default: developer)",
    )
    add.add_argument(
        "--source-authority",
        default="",
        help="comma separated classes the source is authorised to produce",
    )
    add.add_argument(
        "--strength",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="class specific strength field; repeatable. Values are parsed as JSON where possible",
    )
    add.add_argument("--issued-at", help="ISO 8601 issue time (default: now)")
    expiry = add.add_mutually_exclusive_group()
    expiry.add_argument("--expires-at", help="ISO 8601 expiry time")
    expiry.add_argument("--expires-in-days", type=float, help="expiry, in days after issue")
    content = add.add_mutually_exclusive_group()
    content.add_argument("--artefact", help="path to the underlying artefact, hashed with sha256")
    content.add_argument("--content-hash", help="sha256:<hex> of the underlying artefact")
    add.add_argument("--id", help="evidence id (default: generated)")

    lst = sub.add_parser("list", parents=[leaf], help="list evidence with its admission state")
    lst.add_argument("--agent")
    lst.add_argument("--version")
    lst.add_argument("--class", dest="evidence_class", choices=[c.value for c in EvidenceClass])

    show = sub.add_parser("show", parents=[leaf], help="show one piece of evidence in full")
    show.add_argument("id")

    exp = sub.add_parser("expire", parents=[leaf], help="expire evidence now; expiry can never be extended")
    exp.add_argument("id")

    rev = sub.add_parser("revoke", parents=[leaf], help="revoke evidence")
    rev.add_argument("id")
    rev.add_argument("--reason", required=True)

    ex = sub.add_parser("explain", parents=[leaf], help="explain which levels of a capability the ledger supports")
    ex.add_argument("capability", choices=[c.value for c in Capability] + ["all"])
    ex.add_argument("--agent", required=True)
    ex.add_argument("--version", required=True)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = parse_timestamp(args.now) if args.now else utcnow()
    try:
        with Ledger(args.db) as ledger:
            handler = COMMANDS[(args.group, args.command)]
            return handler(args, ledger, now)
    except (CliError, LedgerError, RuleError, ToolTableError, ValueError, KeyError, OSError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        print(f"remit {args.group}: {message}", file=sys.stderr)
        return 1


def _parse_value(key: str, raw: str, kinds: dict[str, str] | None = None) -> Any:
    if kinds and kinds.get(key) in ("text", "level", "timestamp"):
        # Keep text as typed, so a tier of 2 stays the text "2".
        return raw
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = raw
    if key in LIST_FIELDS and isinstance(value, str):
        value = [v.strip() for v in value.split(",") if v.strip()]
    return value


def _split(text: str) -> list[str]:
    return [t.strip() for t in text.split(",") if t.strip()]


def _evidence_from_flags(args: argparse.Namespace, now) -> Evidence:
    missing = [
        flag
        for flag, value in (("--class", args.evidence_class), ("--agent", args.agent), ("--version", args.version))
        if not value
    ]
    if missing:
        raise CliError(f"add needs --file or {', '.join(missing)}")
    strength = {}
    for item in args.strength:
        key, sep, raw = item.partition("=")
        if not sep or not key:
            raise CliError(f"--strength expects KEY=VALUE, got {item!r}")
        strength[key.strip()] = _parse_value(key.strip(), raw, metric_kinds(EvidenceClass(args.evidence_class)))
    issued = parse_timestamp(args.issued_at) if args.issued_at else now
    if args.expires_at:
        expires = parse_timestamp(args.expires_at)
    elif args.expires_in_days is not None:
        expires = issued + timedelta(days=args.expires_in_days)
    else:
        expires = None
    content_hash = args.content_hash
    if args.artefact:
        content_hash = hash_artefact(Path(args.artefact).read_bytes())
    kwargs = {"id": args.id} if args.id else {}
    return Evidence(
        evidence_class=EvidenceClass(args.evidence_class),
        subject=Subject(args.agent, args.version),
        scope=frozenset(Capability(c) for c in _split(args.scope)),
        source=Source(
            args.source,
            frozenset(EvidenceClass(c) for c in _split(args.source_authority)),
            args.source_role,
        ),
        strength=strength,
        issued_at=issued,
        expires_at=expires,
        content_hash=content_hash,
        **kwargs,
    )


def cmd_add(args: argparse.Namespace, ledger: Ledger, now) -> int:
    if args.file:
        data = json.loads(Path(args.file).read_text())
        items = data if isinstance(data, list) else [data]
        evidence = [Evidence.from_dict(item) for item in items]
    else:
        evidence = [_evidence_from_flags(args, now)]
    for ev in evidence:
        ledger.add(ev, recorded_at=now)
        a = assess(ev, now)
        print(f"Added {ev.id}: {ev.evidence_class.value} for {ev.subject}. Admission state: {a.state.value}")
        for blocker in a.blockers:
            print(f"  held back because {blocker}")
    return 0


def cmd_list(args: argparse.Namespace, ledger: Ledger, now) -> int:
    rows = ledger.query(agent_id=args.agent, version=args.version, evidence_class=args.evidence_class)
    if not rows:
        print("No evidence recorded.")
        return 0
    table = [("ID", "CLASS", "SUBJECT", "SCOPE", "STATE", "STATUS", "EXPIRES")]
    for ev in rows:
        a = assess(ev, now)
        table.append(
            (
                ev.id,
                ev.evidence_class.value,
                str(ev.subject),
                ",".join(sorted(c.value for c in ev.scope)) or "-",
                a.state.value,
                a.status,
                format_timestamp(ev.expires_at) if ev.expires_at else "-",
            )
        )
    widths = [max(len(row[i]) for row in table) for i in range(len(table[0]))]
    for row in table:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip())
    return 0


def cmd_show(args: argparse.Namespace, ledger: Ledger, now) -> int:
    ev = ledger.get(args.id)
    a = assess(ev, now)
    print(json.dumps(ev.to_dict(), indent=2))
    print(f"Admission state: {a.state.value} ({a.status})")
    for blocker in a.blockers:
        print(f"  held back because {blocker}")
    return 0


def cmd_expire(args: argparse.Namespace, ledger: Ledger, now) -> int:
    ev = ledger.expire(args.id, at=now)
    print(f"Expired {ev.id} at {format_timestamp(now)}. It no longer supports any capability.")
    return 0


def cmd_revoke(args: argparse.Namespace, ledger: Ledger, now) -> int:
    ev = ledger.revoke(args.id, args.reason, at=now)
    print(f"Revoked {ev.id} at {format_timestamp(now)}: {ev.revocation_reason}")
    return 0


def cmd_explain(args: argparse.Namespace, ledger: Ledger, now) -> int:
    rules = load_rules(args.rules)
    subject = Subject(args.agent, args.version)
    evidence = ledger.for_subject(subject)
    capabilities = list(Capability) if args.capability == "all" else [Capability(args.capability)]
    blocks = [render(explain_capability(evidence, rules, cap, subject, now)) for cap in capabilities]
    print("\n\n".join(blocks))
    return 0


def _subject(text: str) -> Subject:
    return Subject.parse(text)


def cmd_grant_show(args: argparse.Namespace, ledger: Ledger, now) -> int:
    subject = _subject(args.agent)
    envelope = refresh(ledger, load_rules(args.rules), subject, now)
    print(f"Grants for {subject}, as of {format_timestamp(envelope.as_of)}")
    if envelope.ceiling is not None:
        print(f"Ceiling: {envelope.ceiling.describe()}")
    print()
    width = max(len(c.value) for c in Capability)
    for cap in Capability:
        g = envelope[cap]
        flags = []
        if g.ceiling.rank < g.supported.rank:
            flags.append(f"capped, evidence supports {g.supported.value}")
        if g.held is not None:
            flags.append(f"{g.held.value} held for attestation")
        suffix = f"  ({'; '.join(flags)})" if flags else ""
        print(f"  {cap.value:<{width}}  {g.level.value:<8}{suffix}")
    print()
    for cap in Capability:
        print(f"- {envelope[cap].explanation}")
    return 0


def cmd_grant_history(args: argparse.Namespace, ledger: Ledger, now) -> int:
    store = GrantStore(ledger)
    if "@" in args.agent:
        events = store.history(subject=_subject(args.agent))
    else:
        events = store.history(agent_id=args.agent)
    if not events:
        print(f"No grant changes recorded for {args.agent}.")
        return 0
    for e in events:
        ref = f" {e.cause_ref}" if e.cause_ref else ""
        print(
            f"{format_timestamp(e.at)}  {e.subject}  {e.capability.value}: "
            f"{e.old_level.value} -> {e.new_level.value}  [{e.cause_kind}{ref}] {e.detail}"
        )
    return 0


def cmd_check(args: argparse.Namespace, ledger: Ledger, now) -> int:
    if args.pep == "agt" and not agt_available():
        raise CliError("the AGT enforcement point needs the 'agt' extra: uv sync --extra agt")
    pep = make_pep(ledger, load_rules(args.rules), load_tool_table(args.tools), args.pep)
    d = pep.check(_subject(args.agent), args.tool, now)
    print(f"{d.outcome.upper()}  {args.tool} for {args.agent}  (enforced by {d.enforced_by})")
    print(d.explanation)
    if d.escalation_id:
        print(f"Parked for a human as escalation {d.escalation_id}.")
    return 0


COMMANDS = {
    ("evidence", "add"): cmd_add,
    ("evidence", "list"): cmd_list,
    ("evidence", "show"): cmd_show,
    ("evidence", "expire"): cmd_expire,
    ("evidence", "revoke"): cmd_revoke,
    ("evidence", "explain"): cmd_explain,
    ("grant", "show"): cmd_grant_show,
    ("grant", "history"): cmd_grant_history,
    ("check", "check"): cmd_check,
}

if __name__ == "__main__":
    sys.exit(main())
