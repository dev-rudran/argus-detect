"""Merged chronological incident timeline built from alert evidence."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime

from argus.models import Alert, Event, Severity


@dataclass
class TimelineEntry:
    timestamp: datetime
    message: str
    source: str
    line_no: int
    host: str = ""
    user: str = ""
    src_ip: str = ""
    action: str = ""
    rules: list[tuple[str, str, Severity]] = dc_field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return max((item[2] for item in self.rules), default=Severity.INFORMATIONAL)

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "source": self.source,
            "line": self.line_no,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "action": self.action,
            "severity": self.severity.value,
            "rules": [
                {"id": rule_id, "title": title, "severity": severity.value}
                for rule_id, title, severity in self.rules
            ],
        }


@dataclass
class Timeline:
    entries: list[TimelineEntry] = dc_field(default_factory=list)
    truncated: int = 0

    @property
    def start(self) -> datetime | None:
        return self.entries[0].timestamp if self.entries else None

    @property
    def end(self) -> datetime | None:
        return self.entries[-1].timestamp if self.entries else None

    @property
    def duration_seconds(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return max(0.0, (self.end - self.start).total_seconds())


MAX_TIMELINE_ENTRIES = 500


def build_timeline(alerts: Iterable[Alert], *, limit: int = MAX_TIMELINE_ENTRIES) -> Timeline:
    """Merge alert evidence into one ordered timeline.

    Multiple rules matching the same log line are combined into a single
    timeline entry with the highest severity.
    """
    merged: dict[tuple[str, int, str], TimelineEntry] = {}
    total = 0
    for alert in alerts:
        for event in alert.events:
            total += 1
            key = (event.source, event.line_no, event.timestamp.isoformat())
            entry = merged.get(key)
            if entry is None:
                entry = TimelineEntry(
                    timestamp=event.timestamp,
                    message=event.message,
                    source=event.source,
                    line_no=event.line_no,
                    host=event.host,
                    user=event.user,
                    src_ip=event.src_ip,
                    action=event.action,
                )
                merged[key] = entry
            rule_ref = (alert.rule_id, alert.title, alert.severity)
            if rule_ref not in entry.rules:
                entry.rules.append(rule_ref)
    entries = sorted(
        merged.values(), key=lambda entry: (entry.timestamp, -entry.severity.rank, entry.source)
    )
    truncated = max(0, len(entries) - limit)
    if truncated:
        entries = entries[:limit]
    for entry in entries:
        entry.rules.sort(key=lambda item: (-item[2].rank, item[0]))
    return Timeline(entries=entries, truncated=truncated)


def event_to_timeline_entry(event: Event, alert: Alert) -> TimelineEntry:
    """Convert one event/alert pair; useful for tests and custom reports."""
    return TimelineEntry(
        timestamp=event.timestamp,
        message=event.message,
        source=event.source,
        line_no=event.line_no,
        host=event.host,
        user=event.user,
        src_ip=event.src_ip,
        action=event.action,
        rules=[(alert.rule_id, alert.title, alert.severity)],
    )
