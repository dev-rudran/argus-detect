"""End-to-end CLI tests."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from conftest import ATTACK_DIR, BENIGN_DIR, PROJECT_ROOT, RULES_DIR

from argus.cli import main


def run_cli(capsys, *args):
    code = main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def scan_jsonl(capsys, path, *extra):
    code, out, err = run_cli(
        capsys,
        "scan",
        str(path),
        "--rules",
        str(RULES_DIR),
        "--format",
        "jsonl",
        "--year",
        "2026",
        *extra,
    )
    records = [json.loads(line) for line in out.splitlines() if line.strip()]
    return code, records, err


def test_version_commands(capsys):
    assert run_cli(capsys, "version")[0:2] == (0, "argus 0.1.0\n")
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "argus 0.1.0" in capsys.readouterr().out


def test_python_module_entrypoint():
    result = subprocess.run(
        [sys.executable, "-m", "argus", "version"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "argus 0.1.0"


def test_no_command_is_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_rules_list(capsys):
    code, out, _ = run_cli(capsys, "rules", "list", "--rules", str(RULES_DIR))
    assert code == 0
    assert "ARGUS-0001" in out
    assert "ARGUS-0036" in out
    assert "36 rules from" in out


def test_rules_show_and_explain(capsys):
    code, shown, _ = run_cli(capsys, "rules", "show", "ARGUS-0001", "--rules", str(RULES_DIR))
    assert code == 0
    assert "# ARGUS-0001 SSH brute force from a single source" in shown
    assert "# compiled condition:" in shown
    assert "# correlation: count() >= 6" in shown

    code, explained, _ = run_cli(capsys, "explain", "ARGUS-0004", "--rules", str(RULES_DIR))
    assert code == 0
    assert "Detection" in explained
    assert "sequence:" in explained
    assert "T1078  Valid Accounts" in explained
    assert "False positives" in explained


def test_rules_show_unknown_rule_returns_two(capsys):
    code, _, err = run_cli(capsys, "rules", "show", "ARGUS-9999", "--rules", str(RULES_DIR))
    assert code == 2
    assert "rule not found" in err


def test_rules_lint_and_validate_bundled_pack(capsys):
    code, out, _ = run_cli(capsys, "rules", "lint", "--rules", str(RULES_DIR))
    assert code == 0
    assert "36 rules checked, 0 error(s), 0 warning(s)" in out
    code, out, _ = run_cli(capsys, "rules", "validate", "--rules", str(RULES_DIR))
    assert code == 0
    assert out.strip() == "36 rules valid"


def test_rules_lint_and_validate_broken_pack(capsys, tmp_path):
    (tmp_path / "bad.yml").write_text("id: broken\n", encoding="utf-8")
    code, out, _ = run_cli(capsys, "rules", "lint", "--rules", str(tmp_path))
    assert code == 1
    assert "ERROR" in out
    assert "0 rules checked, 1 error(s)" in out
    code, out, _ = run_cli(capsys, "rules", "validate", "--rules", str(tmp_path))
    assert code == 1
    assert "0 rules checked, 1 error(s)" in out


def test_attack_matrix_text_and_output_file(capsys, tmp_path):
    code, out, _ = run_cli(capsys, "attack-matrix", "--rules", str(RULES_DIR))
    assert code == 0
    assert "36 rules cover 48/48 catalogued techniques (100.0%)" in out
    assert "T1110" in out
    target = tmp_path / "matrix.txt"
    code, out, _ = run_cli(capsys, "attack-matrix", "--rules", str(RULES_DIR), "-o", str(target))
    assert code == 0
    assert out == ""
    assert "ATT&CK coverage" in target.read_text(encoding="utf-8")


def test_attack_matrix_html(capsys, tmp_path):
    target = tmp_path / "matrix.html"
    code, out, _ = run_cli(
        capsys,
        "attack-matrix",
        "--rules",
        str(RULES_DIR),
        "--format",
        "html",
        "-o",
        str(target),
    )
    assert code == 0
    assert out == ""
    html = target.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "48 of 48 catalogued techniques" in html
    assert "<script" not in html


def test_benign_corpus_has_no_medium_or_higher_alerts(capsys):
    code, out, _ = run_cli(
        capsys,
        "scan",
        str(BENIGN_DIR),
        "--rules",
        str(RULES_DIR),
        "--min-severity",
        "medium",
        "--stats",
        "--year",
        "2026",
    )
    assert code == 0
    assert "No alerts at or above medium." in out
    assert "events 88" in out
    assert "malformed 0" in out


def test_attack_corpus_fires_every_bundled_rule(capsys):
    code, records, _ = scan_jsonl(capsys, ATTACK_DIR)
    assert code == 0
    assert {record["rule_id"] for record in records} == {
        f"ARGUS-{index:04d}" for index in range(1, 37)
    }
    assert len(records) > 36


def test_attack_corpus_fail_on_exit_codes(capsys):
    base = ["scan", str(ATTACK_DIR), "--rules", str(RULES_DIR), "--year", "2026"]
    code, _, _ = run_cli(capsys, *base, "--fail-on", "high")
    assert code == 1
    code, _, _ = run_cli(capsys, *base, "--fail-on", "critical")
    assert code == 1
    code, _, _ = run_cli(capsys, *base)
    assert code == 0


def test_benign_fail_on_medium_does_not_fail(capsys):
    code, _, _ = run_cli(
        capsys,
        "scan",
        str(BENIGN_DIR),
        "--rules",
        str(RULES_DIR),
        "--fail-on",
        "medium",
        "--year",
        "2026",
    )
    assert code == 0


def test_severity_filter_and_alert_fields(capsys):
    code, records, _ = scan_jsonl(capsys, ATTACK_DIR, "--min-severity", "critical")
    assert code == 0
    assert len(records) == 3
    assert {record["severity"] for record in records} == {"critical"}
    assert {record["rule_id"] for record in records} == {"ARGUS-0004", "ARGUS-0018", "ARGUS-0020"}
    for record in records:
        assert record["group"]
        assert record["attack"]
        assert record["events"]


def test_scan_report_formats(capsys, tmp_path):
    common = ["scan", str(ATTACK_DIR), "--rules", str(RULES_DIR), "--year", "2026"]
    code, out, _ = run_cli(capsys, *common, "--format", "md", "--min-severity", "critical")
    assert code == 0
    assert out.startswith("# argus incident report")
    assert "## Alerts" in out

    target = tmp_path / "report.html"
    code, out, _ = run_cli(
        capsys, *common, "--format", "html", "--min-severity", "critical", "-o", str(target)
    )
    assert code == 0
    assert out == ""
    html = target.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "ARGUS-0004" in html


def test_scan_output_dash_writes_stdout(capsys):
    code, out, _ = run_cli(
        capsys,
        "scan",
        str(ATTACK_DIR),
        "--rules",
        str(RULES_DIR),
        "--format",
        "jsonl",
        "--min-severity",
        "critical",
        "-o",
        "-",
        "--year",
        "2026",
    )
    assert code == 0
    assert len([line for line in out.splitlines() if line.strip()]) == 3


def test_since_until_filters_events(capsys):
    code, records, _ = scan_jsonl(
        capsys,
        ATTACK_DIR,
        "--since",
        "2026-11-10T03:00:00",
        "--until",
        "2026-11-10T03:00:30",
    )
    assert code == 0
    assert "ARGUS-0001" not in {record["rule_id"] for record in records}
    assert records
    for record in records:
        assert "2026-11-10T03:00:00" <= record["first_seen"] <= "2026-11-10T03:00:30"


def test_suppression_cli(capsys):
    code, out, _ = run_cli(
        capsys,
        "scan",
        str(ATTACK_DIR),
        "--rules",
        str(RULES_DIR),
        "--suppress",
        "ARGUS-0001:*:1h",
        "--stats",
        "--year",
        "2026",
    )
    assert code == 0
    assert "ARGUS-0001" not in out
    assert "suppressed: 1" in out


def test_forced_log_type(capsys):
    code, records, _ = scan_jsonl(capsys, ATTACK_DIR / "app.jsonl", "--type", "jsonl")
    assert code == 0
    assert records
    assert {record["rule_id"] for record in records} <= {
        "ARGUS-0021",
        "ARGUS-0022",
        "ARGUS-0023",
        "ARGUS-0024",
        "ARGUS-0025",
        "ARGUS-0035",
    }


def test_sample_events_bounds_jsonl_evidence(capsys):
    code, records, _ = scan_jsonl(capsys, ATTACK_DIR, "--sample-events", "1")
    assert code == 0
    assert all(len(record["events"]) <= 1 for record in records)


def test_invalid_cli_values_return_two(capsys, tmp_path):
    for args in (
        ("scan", str(ATTACK_DIR), "--min-severity", "urgent"),
        ("scan", str(ATTACK_DIR), "--fail-on", "urgent"),
        ("scan", str(ATTACK_DIR), "--since", "2026-11-10", "--until", "2026-11-09"),
        ("scan", str(tmp_path / "missing")),
        ("scan", str(ATTACK_DIR), "--rules", str(tmp_path / "missing")),
        ("rules", "list", "--rules", str(tmp_path / "missing")),
    ):
        code, _, err = run_cli(capsys, *args)
        assert code == 2, args
        assert err.startswith("argus: error:"), args
