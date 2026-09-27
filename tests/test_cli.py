# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

import json
from datetime import timedelta

import pytest

from remit.cli import main
from remit.evidence.model import Capability

from .conftest import NOW, make_evidence

NOW_ARG = NOW.isoformat()


@pytest.fixture
def run(tmp_path, capsys):
    db = tmp_path / "ledger.db"

    def _run(*args, now=NOW_ARG):
        code = main(["evidence", "--db", str(db), "--now", now, *args])
        out, err = capsys.readouterr()
        return code, out, err

    return _run


def add_eval(run, *extra):
    return run(
        "add", "--id", "ev-cli-eval", "--class", "eval_result", "--agent", "cli-agent", "--version", "1",
        "--scope", "budget,read_data", "--source", "lab", "--source-authority", "eval_result",
        "--strength", "suite=synthetic-long-horizon-v1", "--strength", "pass_rate=0.9", "--strength", "samples=120",
        "--expires-in-days", "30", "--content-hash", "sha256:" + "a" * 64, *extra,
    )


def test_add_from_flags_and_list(run):
    code, out, _ = add_eval(run)
    assert code == 0
    assert "Added ev-cli-eval" in out and "gate_eligible" in out
    code, out, _ = run("list")
    assert code == 0
    assert "ev-cli-eval" in out and "gate_eligible" in out and "live" in out


def test_add_reports_why_evidence_is_held_back(run):
    code, out, _ = run(
        "add", "--class", "containment_test", "--agent", "a", "--version", "1", "--scope", "network_out",
        "--source", "lab", "--strength", "boundaries_tested=filesystem,network_egress",
        "--strength", "escape_attempts=5", "--strength", "escape_attempts_blocked=5", "--expires-in-days", "5",
    )
    assert code == 0
    assert "Admission state: present" in out
    assert "no content hash" in out


def test_add_hashes_artefact(run, tmp_path):
    artefact = tmp_path / "report.json"
    artefact.write_text("{}")
    code, _, _ = add_eval(run)
    code, out, _ = run(
        "add", "--id", "ev-art", "--class", "human_attestation", "--agent", "a", "--version", "1",
        "--scope", "budget", "--source", "board", "--source-authority", "human_attestation",
        "--strength", "person=Synthetic Person", "--strength", "role=Director",
        "--strength", "attests_to=extended running", "--expires-in-days", "365", "--artefact", str(artefact),
    )
    assert code == 0
    code, out, _ = run("show", "ev-art")
    assert "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" in out


def test_add_from_file(run, tmp_path):
    items = [make_evidence(scope=[Capability.BUDGET]).to_dict(), make_evidence(scope=[Capability.BUDGET]).to_dict()]
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(items))
    code, out, _ = run("add", "--file", str(path))
    assert code == 0
    assert out.count("Added") == 2


def test_add_needs_class_agent_version(run):
    code, _, err = run("add", "--class", "eval_result")
    assert code == 1
    assert "--agent" in err and "--version" in err


def test_bad_strength_flag(run):
    code, _, err = run("add", "--class", "eval_result", "--agent", "a", "--version", "1", "--strength", "oops")
    assert code == 1 and "KEY=VALUE" in err


def test_expire_and_revoke(run):
    add_eval(run)
    code, out, _ = run("expire", "ev-cli-eval")
    assert code == 0 and "Expired ev-cli-eval" in out
    code, out, _ = run("list")
    assert "expired" in out and "sufficient" in out
    code, _, err = run("expire", "ev-cli-eval")
    assert code == 1 and "already expired" in err
    code, out, _ = run("revoke", "ev-cli-eval", "--reason", "suite contaminated")
    assert code == 0 and "suite contaminated" in out
    code, _, err = run("revoke", "ev-cli-eval", "--reason", "again")
    assert code == 1 and "already revoked" in err


def test_revoke_requires_reason(run):
    add_eval(run)
    with pytest.raises(SystemExit):
        run("revoke", "ev-cli-eval")


def test_unknown_id(run):
    code, _, err = run("expire", "ev-missing")
    assert code == 1 and "no evidence with id ev-missing" in err


def test_explain_tracks_the_ledger(run):
    add_eval(run)
    code, out, _ = run("explain", "budget", "--agent", "cli-agent", "--version", "1")
    assert code == 0
    assert "Highest level the evidence supports: limited" in out
    run("revoke", "ev-cli-eval", "--reason", "withdrawn by the lab")
    code, out, _ = run("explain", "budget", "--agent", "cli-agent", "--version", "1")
    assert "Highest level the evidence supports: none" in out
    assert "withdrawn by the lab" in out


def test_explain_expiry_is_automatic_with_time(run):
    add_eval(run)
    later = (NOW + timedelta(days=31)).isoformat()
    code, out, _ = run("explain", "budget", "--agent", "cli-agent", "--version", "1", now=later)
    assert "Highest level the evidence supports: none" in out
    assert "expired at" in out


def test_explain_all(run):
    add_eval(run)
    code, out, _ = run("explain", "all", "--agent", "cli-agent", "--version", "1")
    assert code == 0
    for cap in Capability:
        assert f"{cap.value} for cli-agent@1" in out


def test_list_empty_and_filtered(run):
    code, out, _ = run("list")
    assert "No evidence recorded" in out
    add_eval(run)
    code, out, _ = run("list", "--class", "containment_test")
    assert "No evidence recorded" in out
    code, out, _ = run("list", "--agent", "cli-agent")
    assert "ev-cli-eval" in out


def test_demo_runs(tmp_path, monkeypatch, capsys):
    from remit import demo

    monkeypatch.chdir(tmp_path)
    assert demo.main() == 0
    out = capsys.readouterr().out
    # Act 1: the containment gate and monitor silence.
    assert "can never satisfy a containment requirement" in out
    assert "has been silent for" in out
    # Act 2: the tier ceiling, the three flips and the history.
    assert "evidence supports full, capped by the tier" in out
    flips = [line.split()[0] for line in out.splitlines() if line.strip().startswith(("ALLOW ", "DENY ", "HOLD "))]
    assert flips == ["ALLOW", "DENY", "DENY", "HOLD", "ALLOW", "DENY"]
    assert "[expiry ev2-sandbox-cert]" in out


def test_demo_runs_without_pyyaml(tmp_path, monkeypatch, capsys):
    import sys

    from remit import demo

    monkeypatch.setitem(sys.modules, "yaml", None)
    monkeypatch.chdir(tmp_path)
    assert demo.main() == 0
    assert "Grant history" in capsys.readouterr().out


def seed_grants(tmp_path):
    from remit.evidence.ledger import Ledger

    from .conftest import full_set
    from .test_policy import attest, tier

    db = tmp_path / "ledger.db"
    with Ledger(db) as led:
        for e in full_set(Capability.CODE_EXECUTION) + [tier("2"), attest(Capability.CODE_EXECUTION, "full")]:
            led.add(e)
    return db


def test_grant_show_history_and_check(tmp_path, capsys):
    db = seed_grants(tmp_path)

    code = main(["grant", "--db", str(db), "--now", NOW_ARG, "show", "test-agent@1.0.0"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Ceiling: the tier 2 ceiling" in out
    assert "code_execution" in out and "capped, evidence supports full" in out

    code = main(["check", "--db", str(db), "--now", NOW_ARG, "--pep", "stub", "test-agent@1.0.0", "tests.run"])
    out = capsys.readouterr().out
    assert code == 0 and out.startswith("ALLOW  tests.run") and "enforced by stub" in out

    code = main(["check", "--db", str(db), "--now", NOW_ARG, "test-agent@1.0.0", "shell.run_networked"])
    out = capsys.readouterr().out
    assert out.startswith("DENY") and "the tier 2 ceiling" in out

    code = main(["check", "--db", str(db), "--now", NOW_ARG, "test-agent@1.0.0", "git.merge_main"])
    assert "red line" in capsys.readouterr().out

    code = main(["grant", "--db", str(db), "history", "test-agent"])
    out = capsys.readouterr().out
    assert "code_execution: none -> limited  [attestation" in out


def test_grant_history_empty_and_bad_subject(tmp_path, capsys):
    db = tmp_path / "empty.db"
    assert main(["grant", "--db", str(db), "history", "nobody"]) == 0
    assert "No grant changes recorded" in capsys.readouterr().out
    assert main(["grant", "--db", str(db), "show", "no-version"]) == 1
    assert "agent@version" in capsys.readouterr().err


def test_check_with_agt_is_enforced_by_agt(tmp_path, capsys):
    pytest.importorskip("agent_os")
    db = seed_grants(tmp_path)
    main(["check", "--db", str(db), "--now", NOW_ARG, "--pep", "agt", "test-agent@1.0.0", "tests.run"])
    assert "enforced by agt" in capsys.readouterr().out


def test_tier_given_on_the_command_line_stays_text(run):
    code, out, _ = run(
        "add", "--id", "ev-tier", "--class", "standards_evidence", "--agent", "a", "--version", "1",
        "--scope", "budget", "--source", "office", "--source-authority", "standards_evidence",
        "--strength", "standard=Synthetic", "--strength", "clause=tiering", "--strength", "tier=2",
        "--expires-in-days", "30", "--content-hash", "sha256:" + "d" * 64,
    )
    assert "gate_eligible" in out
    code, out, _ = run("show", "ev-tier")
    assert '"tier": "2"' in out
