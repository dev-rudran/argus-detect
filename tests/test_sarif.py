"""SARIF 2.1.0 report tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from conftest import ATTACK_DIR, BENIGN_DIR, RULES_DIR, UTC, make_event

from argus.cli import main
from argus.engine import EngineStats, ScanResult
from argus.ingest.base import ParserStats
from argus.models import Alert, Severity
from argus.report.common import ScanContext
from argus.report.sarif import SARIF_SCHEMA, fingerprint, render_sarif, sarif_level
from argus.rules.loader import compile_rule


def build_context(
    severity: Severity = Severity.HIGH,
    *,
    timestamp: datetime | None = None,
    line_no: int = 1,
    source: str = "test.log",
    message: str = "test event",
) -> ScanContext:
    rule = compile_rule(
        {
            "id": "ARGUS-9001",
            "title": "Test rule",
            "description": "A synthetic rule used to exercise the SARIF writer.",
            "severity": severity.value,
            "logsource": {"product": "linux", "service": "sshd"},
            "detection": {"selection": {"action": "test"}, "condition": "selection"},
            "tags": ["attack.credential_access", "attack.t1110", "attack.t1110.001"],
            "falsepositives": ["Synthetic test traffic."],
        },
        path="rules/9001.yml",
    )
    stamp = timestamp or datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    event = make_event(
        {
            "action": "test",
            "host": "web01",
            "user": "deploy",
            "src_ip": "10.0.0.5",
            "message": message,
        },
        timestamp=stamp,
        source=source,
        line_no=line_no,
        raw=message,
    )
    alert = Alert(
        rule_id=rule.id,
        title=rule.title,
        description=rule.description,
        severity=severity,
        group_key="src_ip=10.0.0.5",
        group_values={"src_ip": "10.0.0.5"},
        first_seen=stamp,
        last_seen=stamp,
        count=2,
        events=[event],
        techniques=["T1110", "T1110.001"],
        tags=rule.tags,
        falsepositives=rule.falsepositives,
        logsource=rule.logsource_label,
    )
    alert.observe(event)
    stats = EngineStats(events=1, first_event=stamp, last_event=stamp, alerts=1)
    result = ScanResult(alerts=[alert], stats=stats, rules=[rule])
    parser_stats = ParserStats(files=1, lines=1, events=1, by_type={"sshd": 1})
    return ScanContext(
        result=result,
        parser_stats=parser_stats,
        rules_path="rules",
        started=stamp,
        finished=stamp,
        inputs=["test.log"],
    )


def parse(document: str) -> dict:
    return json.loads(document)


def test_sarif_document_has_expected_shape():
    doc = parse(render_sarif(build_context()))
    assert doc["$schema"] == SARIF_SCHEMA
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1

    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "argus"
    assert driver["version"] == "0.1.0"
    assert driver["informationUri"] == "https://github.com/dev-rudran/argus-detect"
    assert len(driver["rules"]) == 1

    rule = driver["rules"][0]
    assert rule["id"] == "ARGUS-9001"
    assert rule["name"] == "ARGUS-9001"
    assert rule["shortDescription"]["text"] == "Test rule"
    assert rule["fullDescription"]["text"].startswith("A synthetic rule")
    assert rule["defaultConfiguration"]["level"] == "error"
    assert "attack.t1110" in rule["properties"]["tags"]
    assert rule["properties"]["security-severity"] == "8.0"

    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "ARGUS-9001"
    assert result["ruleIndex"] == 0
    assert result["level"] == "error"
    assert "Test rule" in result["message"]["text"]
    assert "src_ip=10.0.0.5" in result["message"]["text"]
    assert result["properties"]["count"] == 2
    assert result["properties"]["attack"] == ["T1110", "T1110.001"]


@pytest.mark.parametrize(
    ("severity", "level", "score"),
    [
        (Severity.CRITICAL, "error", "9.5"),
        (Severity.HIGH, "error", "8.0"),
        (Severity.MEDIUM, "warning", "5.5"),
        (Severity.LOW, "note", "3.0"),
        (Severity.INFORMATIONAL, "note", "0.0"),
    ],
)
def test_severity_maps_to_sarif_level_and_security_severity(severity, level, score):
    assert sarif_level(severity) == level
    doc = parse(render_sarif(build_context(severity)))
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"] == level
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == score
    assert run["results"][0]["level"] == level


def test_rules_are_deduplicated_by_id():
    ctx = build_context()
    ctx.result.rules.append(ctx.result.rules[0])
    doc = parse(render_sarif(ctx))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["ARGUS-9001"]
    assert doc["runs"][0]["results"][0]["ruleIndex"] == 0


def test_fingerprints_are_stable_across_runs():
    first_stamp = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    second_stamp = first_stamp + timedelta(hours=6)
    first = parse(render_sarif(build_context(timestamp=first_stamp)))
    second = parse(render_sarif(build_context(timestamp=second_stamp)))
    first_result = first["runs"][0]["results"][0]
    second_result = second["runs"][0]["results"][0]
    assert first_result["partialFingerprints"] == second_result["partialFingerprints"]
    assert first_result["partialFingerprints"]["argusRuleGroup/v1"] == fingerprint(
        "ARGUS-9001", "src_ip=10.0.0.5"
    )
    assert len(first_result["partialFingerprints"]["argusRuleGroup/v1"]) == 32
    assert first_result["properties"]["first_seen"] != second_result["properties"]["first_seen"]


def test_locations_are_present_for_file_backed_events_and_snippets_are_bounded():
    doc = parse(render_sarif(build_context(line_no=42, message="A" * 500)))
    location = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "test.log"
    assert location["region"]["startLine"] == 42
    snippet = location["region"]["snippet"]["text"]
    assert len(snippet) == 190
    assert snippet.endswith("...")


def test_events_without_a_source_have_no_locations():
    doc = parse(render_sarif(build_context(source="")))
    assert "locations" not in doc["runs"][0]["results"][0]


def test_sarif_output_is_valid_json_with_a_trailing_newline():
    rendered = render_sarif(build_context())
    assert rendered.endswith("\n")
    assert parse(rendered)["version"] == "2.1.0"


def test_cli_attack_corpus_emits_sarif(capsys):
    code = main(
        [
            "scan",
            str(ATTACK_DIR),
            "--rules",
            str(RULES_DIR),
            "--format",
            "sarif",
            "--year",
            "2026",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    doc = parse(captured.out)
    run = doc["runs"][0]
    assert len(run["results"]) == 43
    assert len(run["tool"]["driver"]["rules"]) == 36
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert {result["ruleId"] for result in run["results"]} == {
        f"ARGUS-{index:04d}" for index in range(1, 37)
    }
    assert all(result["ruleId"] in rule_ids for result in run["results"])
    assert all(result["locations"] for result in run["results"])


def test_cli_sarif_writes_to_output_file(capsys, tmp_path):
    target = tmp_path / "argus.sarif"
    code = main(
        [
            "scan",
            str(ATTACK_DIR),
            "--rules",
            str(RULES_DIR),
            "--format",
            "sarif",
            "--year",
            "2026",
            "-o",
            str(target),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""
    doc = parse(target.read_text(encoding="utf-8"))
    assert len(doc["runs"][0]["results"]) == 43


def test_cli_benign_scan_has_empty_results(capsys):
    code = main(
        [
            "scan",
            str(BENIGN_DIR),
            "--rules",
            str(RULES_DIR),
            "--format",
            "sarif",
            "--year",
            "2026",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    doc = parse(captured.out)
    run = doc["runs"][0]
    assert run["results"] == []
    assert len(run["tool"]["driver"]["rules"]) == 36
