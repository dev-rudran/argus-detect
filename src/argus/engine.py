"""Detection engine: matching, sliding windows, dedup, suppression and alerts."""

from __future__ import annotations

import fnmatch
from bisect import insort
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from argus.attack import techniques_for_rule
from argus.models import (
    DEFAULT_SAMPLE_EVENTS,
    Alert,
    Event,
    Rule,
    Severity,
    Threshold,
)
from argus.util.timeparse import parse_duration

DEFAULT_DEDUP_WINDOW = timedelta(minutes=5)
MAX_WINDOW_EVENTS = 10_000
CLEANUP_INTERVAL = 2_000


class SuppressionError(ValueError):
    """Raised for invalid suppression specifications."""


@dataclass
class Suppression:
    rule: str
    group: str
    duration: timedelta
    started: datetime | None = None

    def matches(self, rule_id: str, group_key: str) -> bool:
        return _glob(self.rule, rule_id) and _glob(self.group, group_key)

    def active(self, timestamp: datetime) -> bool:
        if self.started is None:
            self.started = timestamp
            return True
        if timestamp - self.started >= self.duration:
            self.started = timestamp
            return False
        return True


def _glob(pattern: str, value: str) -> bool:
    pattern = (pattern or "*").strip()
    if pattern in {"", "*"}:
        return True
    return fnmatch.fnmatchcase(value, pattern)


@dataclass
class SuppressionSet:
    entries: list[Suppression] = dc_field(default_factory=list)

    def add(self, rule: str, group: str, duration: timedelta) -> None:
        if duration.total_seconds() <= 0:
            raise SuppressionError("suppression duration must be greater than zero")
        self.entries.append(Suppression(rule=rule or "*", group=group or "*", duration=duration))

    def is_suppressed(self, rule_id: str, group_key: str, timestamp: datetime) -> bool:
        return any(
            entry.matches(rule_id, group_key) and entry.active(timestamp) for entry in self.entries
        )

    def __bool__(self) -> bool:
        return bool(self.entries)

    @classmethod
    def from_specs(cls, specs: Iterable[str]) -> SuppressionSet:
        result = cls()
        for spec in specs:
            text = str(spec).strip()
            if not text:
                continue
            try:
                rule, group, duration = _split_suppression_spec(text)
                result.add(rule, group, parse_duration(duration))
            except ValueError as exc:
                raise SuppressionError(str(exc)) from exc
        return result

    @classmethod
    def from_file(cls, path: Path | str) -> SuppressionSet:
        file_path = Path(path)
        if not file_path.exists():
            raise SuppressionError(f"suppression file not found: {file_path}")
        try:
            data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise SuppressionError(f"cannot read suppression file: {exc}") from exc
        if data is None:
            return cls()
        if isinstance(data, dict):
            if "suppressions" not in data:
                raise SuppressionError(
                    "suppression file mapping must contain a 'suppressions' list"
                )
            data = data["suppressions"]
        if not isinstance(data, list):
            raise SuppressionError("suppression file must contain a list or a 'suppressions' list")
        result = cls()
        for index, item in enumerate(data, start=1):
            if not isinstance(item, dict):
                raise SuppressionError(f"suppression entry {index} must be a mapping")
            try:
                rule = str(item.get("rule", "*"))
                group = str(item.get("group", "*"))
                duration = item.get("duration")
                if duration is None:
                    raise SuppressionError(f"suppression entry {index} is missing duration")
                result.add(rule, group, parse_duration(duration))
            except (ValueError, TypeError) as exc:
                raise SuppressionError(f"suppression entry {index}: {exc}") from exc
        return result


def _split_suppression_spec(spec: str) -> tuple[str, str, str]:
    """Split ``rule:group:duration`` where group may contain colons (IPv6)."""
    if ":" not in spec:
        raise SuppressionError(
            f"invalid suppression {spec!r}; expected rule:group:duration, for example ARGUS-0001:*:1h"
        )
    head, duration = spec.rsplit(":", 1)
    if not duration.strip():
        raise SuppressionError(f"invalid suppression {spec!r}; duration is empty")
    if ":" not in head:
        raise SuppressionError(
            f"invalid suppression {spec!r}; expected rule:group:duration, for example ARGUS-0001:*:1h"
        )
    rule, group = head.split(":", 1)
    if not rule.strip():
        rule = "*"
    if not group.strip():
        group = "*"
    return rule.strip(), group.strip(), duration.strip()


@dataclass
class EngineStats:
    events: int = 0
    rule_matches: int = 0
    alerts: int = 0
    suppressed: int = 0
    stale: int = 0
    first_event: datetime | None = None
    last_event: datetime | None = None

    @property
    def active_alerts(self) -> int:
        return self.alerts


@dataclass
class WindowState:
    entries: list[tuple[datetime, Event]] = dc_field(default_factory=list)
    distinct: Counter[tuple[Any, ...]] = dc_field(default_factory=Counter)
    newest: datetime | None = None
    fired: bool = False
    alert: Alert | None = None


@dataclass
class SequenceState:
    entries: list[tuple[datetime, Event]] = dc_field(default_factory=list)
    newest: datetime | None = None


@dataclass
class ScanResult:
    alerts: list[Alert]
    stats: EngineStats
    rules: list[Rule]
    suppressed: int = 0

    def alerts_at_or_above(self, severity: Severity) -> list[Alert]:
        return [alert for alert in self.alerts if alert.severity >= severity]

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {severity.value: 0 for severity in Severity}
        for alert in self.alerts:
            counts[alert.severity.value] += 1
        return counts

    @property
    def by_rule(self) -> dict[str, int]:
        counts: Counter[str] = Counter(alert.rule_id for alert in self.alerts)
        return dict(counts.most_common())

    @property
    def by_host(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for alert in self.alerts:
            if alert.hosts:
                for host in alert.hosts:
                    counts[host] += 1
            else:
                counts["(unknown)"] += 1
        return dict(counts.most_common())


class Engine:
    """Evaluate events against a rule set with bounded correlation state."""

    def __init__(
        self,
        rules: Iterable[Rule],
        *,
        suppression: SuppressionSet | None = None,
        dedup_window: timedelta = DEFAULT_DEDUP_WINDOW,
        sample_events: int = DEFAULT_SAMPLE_EVENTS,
    ) -> None:
        self.rules = list(rules)
        self.suppression = suppression or SuppressionSet()
        self.dedup_window = dedup_window
        self.sample_events = sample_events
        self.stats = EngineStats()
        self.alerts: list[Alert] = []
        self._windows: dict[tuple[str, str], WindowState] = {}
        self._sequences: dict[tuple[str, str], SequenceState] = {}
        self._dedup: dict[tuple[str, str], tuple[datetime, Alert]] = {}
        self._processed = 0
        self._max_window = max(
            (rule.timeframe for rule in self.rules if rule.timeframe is not None),
            default=timedelta(hours=1),
        )

    def run(self, events: Iterable[Event]) -> ScanResult:
        for event in events:
            self.process(event)
        return ScanResult(
            alerts=self.alerts,
            stats=self.stats,
            rules=self.rules,
            suppressed=self.stats.suppressed,
        )

    def process(self, event: Event) -> None:
        self.stats.events += 1
        if self.stats.first_event is None or event.timestamp < self.stats.first_event:
            self.stats.first_event = event.timestamp
        if self.stats.last_event is None or event.timestamp > self.stats.last_event:
            self.stats.last_event = event.timestamp
        self._processed += 1
        for rule in self.rules:
            matches = rule.selection_matches(event)
            if rule.sequence is not None:
                self._process_sequence(rule, event, matches)
                continue
            if not rule.condition_ast.evaluate(matches):
                continue
            self.stats.rule_matches += 1
            if rule.threshold is not None:
                self._process_threshold(rule, event)
            else:
                self._process_single(rule, event)
        if self._processed % CLEANUP_INTERVAL == 0:
            self._cleanup(event.timestamp)

    def _process_single(self, rule: Rule, event: Event) -> None:
        group_key = rule.group_key(event)
        key = (rule.id, group_key)
        window = rule.timeframe or self.dedup_window
        existing = self._dedup.get(key)
        if existing is not None:
            last_ts, alert = existing
            if abs((event.timestamp - last_ts).total_seconds()) < window.total_seconds():
                alert.refresh(event, alert.count + 1)
                return
        alert = self._new_alert(rule, event, count=1, events=[event], group_key=group_key)
        self._dedup[key] = (event.timestamp, alert)
        self._emit(rule, alert, event.timestamp)

    def _process_threshold(self, rule: Rule, event: Event) -> None:
        if rule.threshold is None or rule.timeframe is None:
            raise RuntimeError(f"rule {rule.id} has no threshold or timeframe")
        group_key = rule.group_key(event)
        key = (rule.id, group_key)
        state = self._windows.setdefault(key, WindowState())
        window = rule.timeframe
        anchor = event.timestamp if state.newest is None else max(state.newest, event.timestamp)
        if event.timestamp < anchor - window:
            self.stats.stale += 1
            return
        state.newest = anchor
        self._evict(state, anchor - window, rule.threshold)
        if not state.entries:
            state.fired = False
            state.alert = None
        insort(state.entries, (event.timestamp, event), key=lambda item: item[0])
        if rule.threshold.distinct:
            state.distinct[self._distinct_key(event, rule.threshold)] += 1
        self._evict(state, anchor - window, rule.threshold)
        if len(state.entries) > MAX_WINDOW_EVENTS:
            removed = state.entries.pop(0)
            self._decrement(state, removed[1], rule.threshold)
        count = len(state.entries)
        distinct_count = len(state.distinct) if rule.threshold.distinct else None
        meets = rule.threshold.meets(count, distinct_count)
        if state.fired:
            if not state.entries:
                state.fired = False
                state.alert = None
                return
            if state.alert is not None:
                state.alert.refresh(event, count)
            return
        if not meets:
            return
        evidence = [entry[1] for entry in state.entries]
        alert = self._new_alert(rule, event, count=count, events=evidence, group_key=group_key)
        state.fired = True
        state.alert = alert
        self._emit(rule, alert, event.timestamp)

    def _process_sequence(self, rule: Rule, event: Event, matches: dict[str, bool]) -> None:
        if rule.sequence is None:
            raise RuntimeError(f"rule {rule.id} has no sequence")
        sequence = rule.sequence
        group_key = rule.group_key(event)
        key = (rule.id, group_key)
        state = self._sequences.setdefault(key, SequenceState())
        if matches.get(sequence.first):
            self.stats.rule_matches += 1
            anchor = event.timestamp if state.newest is None else max(state.newest, event.timestamp)
            if event.timestamp < anchor - sequence.within:
                self.stats.stale += 1
                return
            state.newest = anchor
            insort(state.entries, (event.timestamp, event), key=lambda item: item[0])
            self._evict_sequence(state, anchor - sequence.within)
        if not matches.get(sequence.then):
            return
        self.stats.rule_matches += 1
        cutoff = event.timestamp - sequence.within
        state.entries = [entry for entry in state.entries if entry[0] >= cutoff]
        if len(state.entries) < sequence.min_first:
            return
        evidence = [entry[1] for entry in state.entries] + [event]
        alert = self._new_alert(
            rule,
            event,
            count=len(state.entries) + 1,
            events=evidence,
            group_key=group_key,
        )
        state.entries.clear()
        state.newest = event.timestamp
        self._emit(rule, alert, event.timestamp)

    def _new_alert(
        self,
        rule: Rule,
        event: Event,
        *,
        count: int,
        events: list[Event],
        group_key: str,
    ) -> Alert:
        timestamps = [item.timestamp for item in events] or [event.timestamp]
        alert = Alert(
            rule_id=rule.id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            group_key=group_key,
            group_values=rule.group_values(event),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            count=count,
            techniques=[item.id for item in techniques_for_rule(rule)],
            tags=list(rule.tags),
            falsepositives=list(rule.falsepositives),
            logsource=rule.logsource_label,
            max_samples=self.sample_events,
        )
        for item in events:
            alert.observe(item)
        for item in events:
            alert.add_event(item)
        return alert

    def _emit(self, rule: Rule, alert: Alert, timestamp: datetime) -> None:
        if self.suppression.is_suppressed(rule.id, alert.group_key, timestamp):
            self.stats.suppressed += 1
            return
        self.alerts.append(alert)
        self.stats.alerts += 1

    def _evict(self, state: WindowState, cutoff: datetime, threshold: Threshold) -> None:
        while state.entries and state.entries[0][0] < cutoff:
            _, event = state.entries.pop(0)
            self._decrement(state, event, threshold)

    def _decrement(self, state: WindowState, event: Event, threshold: Threshold) -> None:
        if not threshold.distinct:
            return
        key = self._distinct_key(event, threshold)
        if state.distinct.get(key, 0) <= 1:
            state.distinct.pop(key, None)
        else:
            state.distinct[key] -= 1

    @staticmethod
    def _distinct_key(event: Event, threshold: Threshold) -> tuple[Any, ...]:
        return tuple(str(event.get(field, "?")) for field in threshold.distinct)

    @staticmethod
    def _evict_sequence(state: SequenceState, cutoff: datetime) -> None:
        while state.entries and state.entries[0][0] < cutoff:
            state.entries.pop(0)

    def _cleanup(self, now: datetime) -> None:
        horizon = now - max(self._max_window, self.dedup_window) * 2
        for key in [
            key for key, state in self._windows.items() if state.newest and state.newest < horizon
        ]:
            del self._windows[key]
        for key in [
            key for key, state in self._sequences.items() if state.newest and state.newest < horizon
        ]:
            del self._sequences[key]
        for key, (last_seen, _) in list(self._dedup.items()):
            if last_seen < horizon:
                del self._dedup[key]


def sort_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Return alerts in incident-chronological order (most severe first on ties)."""
    return sorted(alerts, key=lambda alert: (alert.first_seen, -alert.severity.rank, alert.rule_id))


def group_alerts_by_severity(alerts: Iterable[Alert]) -> dict[Severity, list[Alert]]:
    groups: dict[Severity, list[Alert]] = {severity: [] for severity in Severity}
    for alert in alerts:
        groups[alert.severity].append(alert)
    return groups
