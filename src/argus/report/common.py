"""Shared report context and metadata."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from argus.attack import Coverage, coverage, technique
from argus.engine import ScanResult
from argus.ingest.base import ParserStats
from argus.models import Alert, Severity
from argus.timeline import Timeline, build_timeline


@dataclass
class ScanContext:
    """Everything a reporter needs about one scan."""

    result: ScanResult
    parser_stats: ParserStats
    rules_path: str
    started: datetime
    finished: datetime
    min_severity: Severity = Severity.INFORMATIONAL
    version: str = "0.1.0"
    inputs: list[str] | None = None
    year: int | None = None
    forced_type: str = "auto"
    timeline: Timeline | None = None
    coverage_report: Coverage | None = None

    def __post_init__(self) -> None:
        if self.timeline is None:
            self.timeline = build_timeline(self.visible_alerts)
        if self.coverage_report is None:
            self.coverage_report = coverage(self.result.rules)

    @property
    def visible_alerts(self) -> list[Alert]:
        return sorted(
            [alert for alert in self.result.alerts if alert.severity >= self.min_severity],
            key=lambda alert: (alert.first_seen, -alert.severity.rank, alert.rule_id),
        )

    @property
    def all_alerts(self) -> list[Alert]:
        return sorted(
            self.result.alerts,
            key=lambda alert: (alert.first_seen, -alert.severity.rank, alert.rule_id),
        )

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, (self.finished - self.started).total_seconds())

    @property
    def events_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.parser_stats.events / self.elapsed_seconds

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for alert in self.visible_alerts:
            counts[alert.severity.value] += 1
        return counts

    @property
    def all_severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for alert in self.all_alerts:
            counts[alert.severity.value] += 1
        return counts

    @property
    def rule_counts(self) -> list[tuple[str, str, int]]:
        titles = {alert.rule_id: alert.title for alert in self.all_alerts}
        counter = Counter(alert.rule_id for alert in self.visible_alerts)
        return [
            (rule_id, titles.get(rule_id, ""), count) for rule_id, count in counter.most_common()
        ]

    @property
    def technique_alert_counts(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for alert in self.visible_alerts:
            for technique_id in alert.techniques:
                counts[technique_id] += 1
        return dict(counts)

    @property
    def time_range(self) -> str:
        first = self.result.stats.first_event
        last = self.result.stats.last_event
        if first is None or last is None:
            return "no events"
        return f"{first.isoformat()} to {last.isoformat()}"

    def metadata(self) -> dict[str, object]:
        return {
            "tool": "argus",
            "version": self.version,
            "generated_at": self.finished.isoformat(),
            "ruleset": self.rules_path,
            "rules": len(self.result.rules),
            "inputs": list(self.inputs or []),
            "files": self.parser_stats.files,
            "events": self.parser_stats.events,
            "malformed": self.parser_stats.malformed,
            "filtered": self.parser_stats.filtered,
            "skipped_files": self.parser_stats.skipped_files,
            "first_event": self.result.stats.first_event.isoformat()
            if self.result.stats.first_event
            else None,
            "last_event": self.result.stats.last_event.isoformat()
            if self.result.stats.last_event
            else None,
            "alerts": len(self.visible_alerts),
            "alerts_all": len(self.all_alerts),
            "suppressed": self.result.stats.suppressed,
            "duration_seconds": round(self.elapsed_seconds, 3),
            "events_per_second": round(self.events_per_second, 1),
            "min_severity": self.min_severity.value,
            "year": self.year,
            "type": self.forced_type,
        }

    def attack_details(self, alert: Alert) -> list[dict[str, object]]:
        details: list[dict[str, object]] = []
        for technique_id in alert.techniques:
            item = technique(technique_id)
            if item is None:
                details.append({"id": technique_id, "name": "", "tactics": [], "url": ""})
            else:
                details.append(
                    {
                        "id": item.id,
                        "name": item.name,
                        "tactics": [tactic.replace("-", " ").title() for tactic in item.tactics],
                        "url": item.url,
                    }
                )
        return details
