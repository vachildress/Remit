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
        "--strength", "suite=synthetic", "--strength", "pass_rate=0.9", "--strength", "samples=120",
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
    assert "can never satisfy a containment requirement" in out
    assert "has been silent for" in out
    assert "escape found in the shared sandbox image" in out
