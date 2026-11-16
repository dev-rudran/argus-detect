"""Incident timeline tests."""

from __future__ import annotations

from datetime import datetime

from conftest import UTC, make_event

from argus.models import Alert, Event, Severity
from argus.timeline import build_timeline, event_to_timeline_entry


def _alert(rule_id: str, severity: Severity, event: Event) -> Alert:
    alert = Alert(
        rule_id=rule_id,
        title=f"{rule_id} title",
        description="Timeline test alert.",
        severity=severity,
        group_key="global",
        group_values={},
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        events=[event],
    )
    alert.observe(event)
    return alert


def test_timeline_merges_events_from_multiple_rules():
    event = make_event(
        {"host": "web01", "user": "deploy", "src_ip": "10.0.0.5", "message": "matched"},
        timestamp=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        line_no=5,
    )
    timeline = build_timeline(
        [_alert("ARGUS-0001", Severity.HIGH, event), _alert("ARGUS-0002", Severity.MEDIUM, event)]
    )
    assert len(timeline.entries) == 1
    entry = timeline.entries[0]
    assert entry.host == "web01"
    assert entry.severity is Severity.HIGH
    assert [item[0] for item in entry.rules] == ["ARGUS-0001", "ARGUS-0002"]
    assert timeline.truncated == 0
    assert timeline.duration_seconds == 0


def test_timeline_orders_entries_and_truncates():
    alerts = []
    for index in range(5):
        event = make_event(
            {"message": f"event {index}"},
            timestamp=datetime(2026, 11, 10, 12, index, tzinfo=UTC),
            line_no=index,
            source=f"file{index}.log",
        )
        alerts.append(_alert(f"ARGUS-{index:04d}", Severity.LOW, event))
    timeline = build_timeline(alerts, limit=3)
    assert len(timeline.entries) == 3
    assert timeline.truncated == 2
    assert timeline.start is not None and timeline.end is not None
    assert timeline.start.minute == 0
    assert timeline.end.minute == 2


def test_event_to_timeline_entry():
    event = make_event({"message": "x"}, line_no=9)
    alert = _alert("ARGUS-0001", Severity.CRITICAL, event)
    entry = event_to_timeline_entry(event, alert)
    assert entry.line_no == 9
    assert entry.rules == [("ARGUS-0001", "ARGUS-0001 title", Severity.CRITICAL)]
    data = entry.to_dict()
    assert data["severity"] == "critical"
    assert data["rules"][0]["id"] == "ARGUS-0001"
