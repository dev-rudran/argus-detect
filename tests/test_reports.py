"""Console, JSONL, Markdown and HTML report tests."""

from __future__ import annotations

import json
from datetime import datetime

from conftest import RULES_DIR, UTC, make_event

from argus.engine import EngineStats, ScanResult
from argus.ingest.base import ParserStats
from argus.models import Alert, Severity
from argus.report import render_console, render_html, render_jsonl, render_markdown
from argus.report.common import ScanContext
from argus.report.html import render_attack_matrix_html
from argus.rules.loader import compile_rule, load_rules


def build_context(min_severity: Severity = Severity.INFORMATIONAL) -> ScanContext:
    rule = compile_rule(
        {
            "id": "ARGUS-9001",
            "title": 'Test <script>alert("x")</script> | rule',
            "description": "Description with <img src=x onerror=alert(1)> and a | pipe.",
            "severity": "high",
            "logsource": {"product": "linux", "service": "sshd"},
            "detection": {"selection": {"action": "test"}, "condition": "selection"},
            "tags": ["attack.credential_access", "attack.t1110", "attack.t1110.001"],
            "falsepositives": ["Legitimate | test traffic."],
        },
        path="rules/9001.yml",
    )
    timestamp = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    event = make_event(
        {
            "action": "test",
            "host": "web01",
            "user": "deploy",
            "src_ip": "10.0.0.5",
            "message": 'raw <script>alert("x")</script>\nsecond line',
        },
        timestamp=timestamp,
        raw='raw <script>alert("x")</script>\nsecond line',
    )
    alert = Alert(
        rule_id=rule.id,
        title=rule.title,
        description=rule.description,
        severity=Severity.HIGH,
        group_key="src_ip=10.0.0.5",
        group_values={"src_ip": "10.0.0.5"},
        first_seen=timestamp,
        last_seen=timestamp,
        count=2,
        events=[event],
        techniques=["T1110", "T1110.001"],
        tags=rule.tags,
        falsepositives=rule.falsepositives,
        logsource=rule.logsource_label,
    )
    alert.observe(event)
    stats = EngineStats(events=1, first_event=timestamp, last_event=timestamp, alerts=1)
    result = ScanResult(alerts=[alert], stats=stats, rules=[rule])
    parser_stats = ParserStats(files=1, lines=1, events=1, by_type={"sshd": 1})
    return ScanContext(
        result=result,
        parser_stats=parser_stats,
        rules_path="rules",
        started=timestamp,
        finished=timestamp,
        min_severity=min_severity,
        inputs=["test.log"],
    )


def test_console_report_includes_alert_metadata_and_stats():
    output = render_console(build_context(), color=False, stats=True)
    assert "argus 0.1.0" in output
    assert "ARGUS-9001" in output
    assert "HIGH" in output
    assert "src_ip=10.0.0.5" in output
    assert "ATT&CK: T1110 Brute Force" in output
    assert "Summary" in output
    assert "Ingest" in output
    assert "log types: sshd 1" in output
    assert "\x1b[" not in output


def test_console_color_and_empty_severity_filter():
    colored = render_console(build_context(), color=True)
    assert "\x1b[" in colored
    empty = render_console(build_context(min_severity=Severity.CRITICAL), color=False)
    assert "No alerts at or above critical." in empty


def test_console_alert_ordering_is_severity_first():
    context = build_context()
    output = render_console(context, color=False)
    assert output.index("HIGH") < output.index("Summary")


def test_jsonl_report_is_one_valid_object_per_line():
    output = render_jsonl(build_context())
    lines = output.strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["rule_id"] == "ARGUS-9001"
    assert record["severity"] == "high"
    assert record["group_values"] == {"src_ip": "10.0.0.5"}
    assert record["ruleset"] == "rules"
    assert [item["id"] for item in record["attack_techniques"]] == ["T1110", "T1110.001"]
    assert record["events"][0]["raw"].count("\n") == 1


def test_jsonl_report_can_be_empty_and_filter_alerts():
    empty = build_context(min_severity=Severity.CRITICAL)
    assert render_jsonl(empty) == ""
    assert render_jsonl(build_context(), alerts=[]).strip() == ""


def test_markdown_report_contains_tables_and_evidence_fence():
    output = render_markdown(build_context())
    assert output.startswith("# argus incident report")
    assert "## Severity summary" in output
    assert "| High | 1 |" in output
    assert "## Rules triggered" in output
    assert "Test &lt;" not in output
    assert "\\|" in output
    assert "## Incident timeline" in output
    assert "## ATT&CK coverage" in output
    assert "```text" in output
    assert "raw <script>" in output


def test_markdown_report_selected_severity_hides_alerts():
    output = render_markdown(build_context(min_severity=Severity.CRITICAL))
    assert "No alerts at or above the configured severity threshold." in output
    assert "## Rules triggered" not in output


def test_html_report_is_self_contained_and_escapes_log_content():
    output = render_html(build_context())
    assert output.startswith("<!doctype html>")
    assert "Content-Security-Policy" in output
    assert "default-src 'none'" in output
    assert "Test &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in output
    assert "<img src=x onerror=alert(1)>" not in output
    assert "&lt;img src=x onerror=alert(1)&gt;" in output
    assert output.count("<script>") == 1
    assert 'src="http' not in output
    assert 'href="http' not in output
    assert "ATT&amp;CK coverage" in output
    assert "Incident timeline" in output
    assert "Search rule, group, host, user, IP" in output


def test_html_report_empty_state():
    output = render_html(build_context(min_severity=Severity.CRITICAL))
    assert "No alerts at or above the configured severity threshold." in output
    assert "No matched events to display." in output


def test_attack_matrix_html_and_cli_text():
    rules = load_rules(RULES_DIR)
    html = render_attack_matrix_html(rules)
    assert "ATT&amp;CK coverage" in html
    assert "48 of 48 catalogued techniques" in html
    assert "Credential Access" in html
    assert "T1110" in html
    assert "<script" not in html
