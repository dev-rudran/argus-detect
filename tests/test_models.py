"""Core model behaviour tests."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from conftest import UTC, make_event

from argus.match import FieldMatcher
from argus.models import Alert, Event, Rule, Selection, Severity, Threshold
from argus.rules.condition import parse_condition


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("info", Severity.INFORMATIONAL),
        ("informational", Severity.INFORMATIONAL),
        ("LOW", Severity.LOW),
        ("medium", Severity.MEDIUM),
        ("med", Severity.MEDIUM),
        ("high", Severity.HIGH),
        ("crit", Severity.CRITICAL),
        ("critical", Severity.CRITICAL),
    ],
)
def test_severity_parse_aliases(text, expected):
    assert Severity.parse(text) is expected


def test_severity_ordering_and_invalid_value():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.HIGH >= Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("bogus")


def test_event_get_properties_and_serialization():
    event = make_event(
        {
            "action": ["ssh_auth_failed"],
            "user": ["deploy"],
            "src_ip": "10.0.0.5",
            "message": "failed",
        },
        line_no=7,
        raw="raw line",
    )
    assert event.get("action") == ["ssh_auth_failed"]
    assert event.get("timestamp") == event.timestamp.isoformat()
    assert event.get("source") == "test.log"
    assert event.get("log_type") == "test"
    assert event.get("line_no") == 7
    assert event.get("missing", "fallback") == "fallback"
    assert event.action == "ssh_auth_failed"
    assert event.user == "deploy"
    assert event.host == ""
    assert event.src_ip == "10.0.0.5"
    assert event.message == "failed"
    assert event.keys == "test.log:7"
    data = event.to_dict()
    assert data["timestamp"].endswith("+00:00")
    assert data["fields"]["src_ip"] == "10.0.0.5"
    assert data["raw"] == "raw line"


def test_event_summary_truncates_and_includes_host():
    event = make_event({"host": "web01", "message": "a" * 100})
    summary = event.summary(width=30)
    assert "2026-11-10 12:00:00" in summary
    assert "web01" in summary
    assert len(summary) < 100


def test_selection_requires_every_field_group():
    selection = Selection(
        name="selection",
        fields={
            "action": [FieldMatcher.build("action", "ssh_auth_failed")],
            "user": [FieldMatcher.build("user", "root"), FieldMatcher.build("user", "admin")],
        },
    )
    assert selection.matches(make_event({"action": "ssh_auth_failed", "user": "admin"}))
    assert not selection.matches(make_event({"action": "ssh_auth_failed", "user": "deploy"}))
    assert not selection.matches(make_event({"action": "ssh_auth_failed"}))
    assert "action=ssh_auth_failed" in selection.describe()


def _rule(**overrides) -> Rule:
    condition = "selection"
    selection = Selection(
        name="selection",
        fields={"action": [FieldMatcher.build("action", "ssh_auth_failed")]},
    )
    base = {
        "id": "ARGUS-9001",
        "title": "Test rule",
        "description": "A synthetic test rule used for model tests.",
        "severity": Severity.HIGH,
        "logsource": {"product": "linux", "service": "sshd"},
        "selections": {"selection": selection},
        "condition": condition,
        "condition_ast": parse_condition(condition).ast,
        "tags": ["attack.credential_access", "attack.t1110", "attack.t1110.001"],
        "falsepositives": ["Test traffic."],
    }
    base.update(overrides)
    return Rule(**base)


def test_rule_metadata_helpers():
    rule = _rule(group_by=("user", "src_ip"))
    assert rule.correlated is False
    assert rule.logsource_label == "linux/sshd"
    assert rule.attack_tags == ["attack.credential_access", "attack.t1110", "attack.t1110.001"]
    assert rule.technique_tags == ["T1110", "T1110.001"]
    event = make_event({"user": "root"})
    assert rule.group_key(event) == "user=root,src_ip=?"
    assert rule.group_values(event) == {"user": "root", "src_ip": "?"}
    assert rule.matches(make_event({"action": "ssh_auth_failed"}))


def test_rule_to_dict_serializes_compiled_metadata():
    rule = _rule(
        timeframe=timedelta(minutes=5),
        group_by=("user",),
        threshold=Threshold(count=3, distinct=("src_ip",)),
    )
    data = rule.to_dict()
    assert data["timeframe"] == 300
    assert data["threshold"] == {"count": 3, "op": "gte", "distinct": ["src_ip"]}
    assert data["detection"]["condition"] == "selection"


def test_alert_observation_and_entity_sets():
    alert = Alert(
        rule_id="ARGUS-9001",
        title="Test",
        description="Test alert.",
        severity=Severity.HIGH,
        group_key="user=root",
        group_values={"user": "root"},
        first_seen=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        last_seen=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        max_samples=2,
    )
    first = make_event({"user": "root", "host": "web01", "src_ip": "10.0.0.5"}, line_no=1)
    second = make_event({"user": "deploy", "host": "db01", "src_ip": "10.0.0.6"}, line_no=2)
    third = make_event({"user": "admin", "host": "app01", "src_ip": "10.0.0.7"}, line_no=3)
    alert.add_event(first)
    alert.add_event(first)
    alert.add_event(second)
    alert.add_event(third)
    assert len(alert.events) == 2
    assert alert.hosts == {"web01", "db01"}
    assert alert.users == {"root", "deploy"}
    alert.refresh(second, 2)
    assert alert.count == 2
    data = alert.to_dict()
    assert data["attack"] == []
    assert data["hosts"] == ["db01", "web01"]


def test_alert_first_and_last_seen_expand():
    start = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    alert = Alert(
        rule_id="ARGUS-9001",
        title="Test",
        description="Test alert.",
        severity=Severity.LOW,
        group_key="global",
        group_values={},
        first_seen=start,
        last_seen=start,
    )
    earlier = make_event(timestamp=start - timedelta(minutes=5), line_no=1)
    later = make_event(timestamp=start + timedelta(minutes=2), line_no=2)
    alert.add_event(later)
    alert.add_event(earlier)
    assert alert.first_seen == start - timedelta(minutes=5)
    assert alert.last_seen == start + timedelta(minutes=2)
    assert alert.duration_seconds == 420


def test_event_field_list_first_string_helper():
    event = Event(
        timestamp=datetime(2026, 11, 10, tzinfo=UTC),
        fields={"user": [], "host": [None, "web01"], "src_ip": ["10.0.0.1", "10.0.0.2"]},
        raw="x",
        source="s",
        line_no=1,
        log_type="test",
    )
    assert event.user == ""
    assert event.host == "web01"
    assert event.src_ip == "10.0.0.1"
