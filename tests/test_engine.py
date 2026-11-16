"""Detection engine correlation, deduplication and suppression tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from conftest import UTC, make_event

from argus.engine import Engine, SuppressionError, SuppressionSet, sort_alerts
from argus.models import Severity
from argus.rules.loader import compile_rule


def rule_definition(
    *,
    rule_id: str = "ARGUS-9001",
    selections: dict | None = None,
    condition: str = "selection",
    timeframe: str | None = None,
    threshold: dict | None = None,
    sequence: dict | None = None,
    group_by: list[str] | None = None,
) -> dict:
    data = {
        "id": rule_id,
        "title": "Engine test rule",
        "description": "A synthetic rule used to exercise the detection engine.",
        "severity": "high",
        "logsource": {"product": "linux", "service": "sshd"},
        "detection": {
            "selection": {"action": "ssh_auth_failed"},
            "condition": condition,
        },
        "tags": ["attack.t1110"],
        "falsepositives": ["Test traffic."],
    }
    if selections is not None:
        data["detection"] = {**selections, "condition": condition}
    if timeframe:
        data["timeframe"] = timeframe
    if threshold:
        data["threshold"] = threshold
    if sequence:
        data["sequence"] = sequence
    if group_by:
        data["group_by"] = group_by
    return data


def built_rule(**kwargs):
    return compile_rule(rule_definition(**kwargs))


def at(minute: int, second: int = 0) -> datetime:
    return datetime(2026, 11, 10, 12, 0, tzinfo=UTC) + timedelta(minutes=minute, seconds=second)


def failed(
    minute: int, *, src: str = "1.2.3.4", user: str = "root", line: int = 1, second: int = 0
):
    return make_event(
        {"action": "ssh_auth_failed", "src_ip": src, "user": user},
        timestamp=at(minute, second),
        line_no=line,
    )


def success(
    minute: int, *, src: str = "1.2.3.4", user: str = "root", line: int = 10, second: int = 0
):
    return make_event(
        {"action": "ssh_auth_success", "src_ip": src, "user": user},
        timestamp=at(minute, second),
        line_no=line,
    )


def test_single_rule_emits_and_deduplicates_within_window():
    engine = Engine([built_rule(group_by=["src_ip"])])
    engine.process(failed(0, line=1))
    engine.process(failed(1, line=2))
    assert len(engine.alerts) == 1
    alert = engine.alerts[0]
    assert alert.count == 2
    assert len(alert.events) == 2
    assert alert.group_key == "src_ip=1.2.3.4"
    engine.process(failed(10, line=3))
    assert len(engine.alerts) == 2


def test_single_rule_respects_rule_timeframe_for_dedup():
    engine = Engine([built_rule(timeframe="1m", group_by=["src_ip"])])
    engine.process(failed(0, line=1))
    engine.process(failed(0, second=30, line=2))
    engine.process(failed(2, line=3))
    assert len(engine.alerts) == 2
    assert engine.alerts[0].count == 2


def test_threshold_fires_then_refreshes_and_refires_after_window_empties():
    engine = Engine(
        [
            built_rule(
                timeframe="2m",
                threshold={"count": 2, "op": "gte"},
                group_by=["src_ip"],
            )
        ]
    )
    engine.process(failed(0, line=1))
    assert engine.alerts == []
    engine.process(failed(1, line=2))
    assert len(engine.alerts) == 1
    assert engine.alerts[0].count == 2
    engine.process(failed(1, second=30, line=3))
    assert len(engine.alerts) == 1
    assert engine.alerts[0].count == 3
    engine.process(failed(10, line=4))
    assert len(engine.alerts) == 1
    engine.process(failed(11, line=5))
    assert len(engine.alerts) == 2


def test_threshold_groups_by_field():
    engine = Engine([built_rule(timeframe="2m", threshold={"count": 1}, group_by=["src_ip"])])
    engine.process(failed(0, src="1.1.1.1", line=1))
    engine.process(failed(0, src="2.2.2.2", line=2))
    assert len(engine.alerts) == 2
    assert {alert.group_key for alert in engine.alerts} == {"src_ip=1.1.1.1", "src_ip=2.2.2.2"}


def test_threshold_distinct_counts_unique_values():
    engine = Engine(
        [
            built_rule(
                timeframe="5m",
                threshold={"count": 2, "distinct": ["user"]},
                group_by=["src_ip"],
            )
        ]
    )
    engine.process(failed(0, user="alice", line=1))
    engine.process(failed(1, user="alice", line=2))
    assert engine.alerts == []
    engine.process(failed(2, user="bob", line=3))
    assert len(engine.alerts) == 1
    assert engine.alerts[0].count == 3


def test_threshold_out_of_order_events_are_stale():
    engine = Engine([built_rule(timeframe="2m", threshold={"count": 2}, group_by=["src_ip"])])
    engine.process(failed(10, line=1))
    engine.process(failed(0, line=2))
    assert engine.stats.stale == 1
    assert engine.alerts == []


def test_sequence_requires_enough_first_stage_events():
    engine = Engine(
        [
            built_rule(
                rule_id="ARGUS-9004",
                selections={
                    "failures": {"action": "ssh_auth_failed"},
                    "success": {"action": "ssh_auth_success"},
                },
                condition="failures or success",
                sequence={
                    "first": "failures",
                    "then": "success",
                    "min_first": 3,
                    "within": "10m",
                    "group_by": ["src_ip"],
                },
            )
        ]
    )
    engine.process(failed(0, line=1))
    engine.process(failed(1, line=2))
    engine.process(success(2, line=3))
    assert engine.alerts == []
    engine.process(failed(3, line=4))
    engine.process(failed(4, line=5))
    engine.process(success(5, line=6))
    assert len(engine.alerts) == 1
    assert engine.alerts[0].count == 5
    assert engine.alerts[0].first_seen == at(0)
    assert engine.alerts[0].last_seen == at(5)


def test_sequence_respects_window_and_resets_after_firing():
    engine = Engine(
        [
            built_rule(
                rule_id="ARGUS-9004",
                selections={
                    "failures": {"action": "ssh_auth_failed"},
                    "success": {"action": "ssh_auth_success"},
                },
                condition="failures or success",
                sequence={
                    "first": "failures",
                    "then": "success",
                    "min_first": 2,
                    "within": "5m",
                    "group_by": ["src_ip"],
                },
            )
        ]
    )
    engine.process(failed(0, line=1))
    engine.process(failed(1, line=2))
    engine.process(success(10, line=3))
    assert engine.alerts == []
    engine.process(failed(11, line=4))
    engine.process(failed(12, line=5))
    engine.process(success(13, line=6))
    assert len(engine.alerts) == 1
    engine.process(success(14, line=7))
    assert len(engine.alerts) == 1


def test_sequence_groups_by_source():
    engine = Engine(
        [
            built_rule(
                rule_id="ARGUS-9004",
                selections={
                    "failures": {"action": "ssh_auth_failed"},
                    "success": {"action": "ssh_auth_success"},
                },
                condition="failures or success",
                sequence={
                    "first": "failures",
                    "then": "success",
                    "min_first": 1,
                    "within": "5m",
                    "group_by": ["src_ip"],
                },
            )
        ]
    )
    engine.process(failed(0, src="1.1.1.1", line=1))
    engine.process(success(1, src="2.2.2.2", line=2))
    assert engine.alerts == []
    engine.process(success(2, src="1.1.1.1", line=3))
    assert len(engine.alerts) == 1


def test_suppression_starts_window_and_reopens_after_duration():
    suppression = SuppressionSet.from_specs(["ARGUS-9001:*:1h"])
    engine = Engine([built_rule(group_by=["src_ip"])], suppression=suppression)
    engine.process(failed(0, line=1))
    assert engine.alerts == []
    assert engine.stats.suppressed == 1
    engine.process(failed(1, line=2))
    assert engine.stats.suppressed == 1
    assert engine.alerts == []
    engine.process(failed(61, line=3))
    assert len(engine.alerts) == 1


def test_suppression_wildcards_and_rule_specificity():
    suppression = SuppressionSet.from_specs(["ARGUS-*:src_ip=1.2.*:1h"])
    assert suppression.is_suppressed("ARGUS-0001", "src_ip=1.2.3.4", at(0))
    assert not suppression.is_suppressed("OTHER-0001", "src_ip=1.2.3.4", at(0))
    assert not suppression.is_suppressed("ARGUS-0001", "src_ip=9.9.9.9", at(0))


def test_suppression_file_loading(tmp_path: Path):
    path = tmp_path / "suppress.yml"
    path.write_text(
        "suppressions:\n  - rule: ARGUS-0001\n    group: '*'\n    duration: 30m\n",
        encoding="utf-8",
    )
    suppression = SuppressionSet.from_file(path)
    assert suppression.is_suppressed("ARGUS-0001", "global", at(0))
    empty = tmp_path / "empty.yml"
    empty.write_text("", encoding="utf-8")
    assert not SuppressionSet.from_file(empty)


def test_suppression_rejects_invalid_specs_and_files(tmp_path: Path):
    for spec in ("ARGUS-0001:1h", "ARGUS-0001:*:0s", "ARGUS-0001:*:forever"):
        with pytest.raises(SuppressionError):
            SuppressionSet.from_specs([spec])
    with pytest.raises(SuppressionError):
        SuppressionSet.from_file(tmp_path / "missing.yml")
    bad = tmp_path / "bad.yml"
    bad.write_text("- rule: ARGUS-0001\n", encoding="utf-8")
    with pytest.raises(SuppressionError, match="duration"):
        SuppressionSet.from_file(bad)
    wrong_type = tmp_path / "wrong.yml"
    wrong_type.write_text("rule: nope\n", encoding="utf-8")
    with pytest.raises(SuppressionError, match="list"):
        SuppressionSet.from_file(wrong_type)


def test_sample_event_limit_and_alert_count():
    engine = Engine([built_rule(group_by=["src_ip"])], sample_events=2)
    for index in range(5):
        engine.process(failed(0, line=index))
    assert len(engine.alerts) == 1
    assert engine.alerts[0].count == 5
    assert len(engine.alerts[0].events) == 2


def test_scan_result_helpers_and_sorting():
    engine = Engine(
        [
            built_rule(rule_id="ARGUS-9001", group_by=["src_ip"]),
            built_rule(
                rule_id="ARGUS-9002",
                selections={"selection": {"action": "ssh_auth_success"}},
                condition="selection",
                group_by=["src_ip"],
            ),
        ]
    )
    engine.process(failed(0, line=1))
    engine.process(success(0, line=2))
    result = engine.run([failed(20, line=3)])
    assert result.stats.events == 3
    assert result.by_severity["high"] == 3
    assert result.by_rule["ARGUS-9001"] == 2
    assert result.by_host == {"(unknown)": 3}
    assert [alert.rule_id for alert in sort_alerts(result.alerts)] == [
        "ARGUS-9001",
        "ARGUS-9002",
        "ARGUS-9001",
    ]
    assert len(result.alerts_at_or_above(Severity.HIGH)) == 3
    assert result.alerts_at_or_above(Severity.CRITICAL) == []
