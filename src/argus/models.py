"""Core data models for events, detections and alerts."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from argus.match import FieldMatcher
from argus.util.timeparse import ensure_utc

MAX_OBSERVED = 100
DEFAULT_SAMPLE_EVENTS = 12


class Severity(str, Enum):
    """Alert severity with a stable ordering."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def parse(cls, value: object) -> Severity:
        text = str(value or "").strip().lower()
        aliases = {
            "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
        }
        try:
            return aliases[text]
        except KeyError as exc:
            raise ValueError(
                f"invalid severity {value!r}; expected informational, low, medium, high or critical"
            ) from exc


@dataclass(slots=True)
class Event:
    """A normalized log event.

    ``fields`` contains normalized names used by rules (``action``, ``user``,
    ``src_ip``, ``command`` and so on). ``raw`` is retained for evidence.
    """

    timestamp: datetime
    fields: dict[str, Any]
    raw: str
    source: str
    line_no: int
    log_type: str

    def __post_init__(self) -> None:
        self.timestamp = ensure_utc(self.timestamp)

    def get(self, name: str, default: Any = None) -> Any:
        if name in self.fields:
            return self.fields[name]
        if name == "timestamp":
            return self.timestamp.isoformat()
        if name == "source":
            return self.source
        if name == "log_type":
            return self.log_type
        if name == "line_no":
            return self.line_no
        return default

    @property
    def action(self) -> str:
        value = self.get("action")
        if isinstance(value, (list, tuple, set)):
            return str(next(iter(value), ""))
        return str(value or "")

    @property
    def host(self) -> str:
        return _first_string(self.get("host"))

    @property
    def user(self) -> str:
        return _first_string(self.get("user"))

    @property
    def src_ip(self) -> str:
        return _first_string(self.get("src_ip"))

    @property
    def message(self) -> str:
        return _first_string(self.get("message")) or self.raw

    @property
    def keys(self) -> str:
        return f"{self.source}:{self.line_no}"

    def to_dict(self, *, include_raw: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "timestamp": self.timestamp.isoformat(),
            "log_type": self.log_type,
            "source": self.source,
            "line": self.line_no,
            "fields": {key: _jsonable(value) for key, value in self.fields.items()},
        }
        if include_raw:
            data["raw"] = self.raw
        return data

    def summary(self, width: int = 180) -> str:
        from argus.util.text import truncate

        prefix = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        host = f" {self.host}" if self.host else ""
        return f"{prefix}{host} {truncate(self.message, width)}"


def _first_string(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if item is not None:
                return str(item)
        return ""
    return "" if value is None else str(value)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    return value


@dataclass
class Selection:
    """Named group of field matchers."""

    name: str
    fields: dict[str, list[FieldMatcher]]

    def matches(self, event: Event) -> bool:
        for matchers in self.fields.values():
            if not any(matcher.matches_event(event) for matcher in matchers):
                return False
        return bool(self.fields)

    def describe(self) -> str:
        return ", ".join(
            " or ".join(matcher.describe() for matcher in matchers)
            for matchers in self.fields.values()
        )


@dataclass(frozen=True)
class Threshold:
    """Correlation threshold evaluated over a sliding window."""

    count: int
    op: str = "gte"
    distinct: tuple[str, ...] = ()

    def meets(self, count: int, distinct_count: int | None = None) -> bool:
        value = distinct_count if self.distinct else count
        if value is None:
            return False
        if self.op == "gte":
            return value >= self.count
        if self.op == "gt":
            return value > self.count
        if self.op == "eq":
            return value == self.count
        if self.op == "lt":
            return value < self.count
        if self.op == "lte":
            return value <= self.count
        return False

    @property
    def display(self) -> str:
        operator = {"gte": ">=", "gt": ">", "eq": "==", "lt": "<", "lte": "<="}.get(
            self.op, self.op
        )
        suffix = f" distinct {', '.join(self.distinct)}" if self.distinct else ""
        return f"count() {operator} {self.count}{suffix}"


@dataclass(frozen=True)
class Sequence:
    """Two-stage correlation: N first-stage events followed by an end event."""

    first: str
    then: str
    min_first: int
    within: timedelta
    group_by: tuple[str, ...]

    @property
    def display(self) -> str:
        return (
            f"{self.min_first} x {self.first} -> {self.then} within "
            f"{int(self.within.total_seconds())}s"
        )


@dataclass(frozen=True)
class TimeWindow:
    """A half-open sliding window anchored on the newest observed event."""

    duration: timedelta

    def cutoff(self, newest: datetime) -> datetime:
        return newest - self.duration

    def contains(self, timestamp: datetime, newest: datetime) -> bool:
        return timestamp >= self.cutoff(newest)


@dataclass
class Rule:
    """A compiled detection rule."""

    id: str
    title: str
    description: str
    severity: Severity
    logsource: dict[str, str]
    selections: dict[str, Selection]
    condition: str
    condition_ast: Any
    tags: list[str]
    falsepositives: list[str]
    path: str = ""
    level: str = ""
    timeframe: timedelta | None = None
    group_by: tuple[str, ...] = ()
    threshold: Threshold | None = None
    sequence: Sequence | None = None
    raw: dict[str, Any] = dc_field(default_factory=dict)

    @property
    def correlated(self) -> bool:
        return self.threshold is not None or self.sequence is not None

    @property
    def logsource_label(self) -> str:
        product = self.logsource.get("product", "")
        service = self.logsource.get("service", "")
        if product and service:
            return f"{product}/{service}"
        return product or service or "generic"

    @property
    def attack_tags(self) -> list[str]:
        return [tag for tag in self.tags if tag.lower().startswith("attack.")]

    @property
    def technique_tags(self) -> list[str]:
        return [
            tag.split(".", 1)[1].upper() for tag in self.attack_tags if _looks_like_technique(tag)
        ]

    def selection_matches(self, event: Event) -> dict[str, bool]:
        return {name: selection.matches(event) for name, selection in self.selections.items()}

    def matches(self, event: Event) -> bool:
        if self.sequence is not None:
            return any(self.selection_matches(event).values())
        return bool(self.condition_ast.evaluate(self.selection_matches(event)))

    def group_key(self, event: Event) -> str:
        fields = self.sequence.group_by if self.sequence is not None else self.group_by
        if not fields:
            return "global"
        parts = []
        for name in fields:
            value = event.get(name)
            if isinstance(value, (list, tuple, set)):
                value = _first_string(value)
            parts.append(f"{name}={value if value not in (None, '') else '?'}")
        return ",".join(parts)

    def group_values(self, event: Event) -> dict[str, str]:
        fields = self.sequence.group_by if self.sequence is not None else self.group_by
        return {name: _first_string(event.get(name)) or "?" for name in fields}

    def to_dict(self) -> dict[str, Any]:
        threshold = None
        if self.threshold is not None:
            threshold = {
                "count": self.threshold.count,
                "op": self.threshold.op,
                "distinct": list(self.threshold.distinct),
            }
        sequence = None
        if self.sequence is not None:
            sequence = {
                "first": self.sequence.first,
                "then": self.sequence.then,
                "min_first": self.sequence.min_first,
                "within": self.sequence.within.total_seconds(),
                "group_by": list(self.sequence.group_by),
            }
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "logsource": self.logsource,
            "detection": {
                "selections": {
                    name: [
                        matcher.describe()
                        for matchers in selection.fields.values()
                        for matcher in matchers
                    ]
                    for name, selection in self.selections.items()
                },
                "condition": self.condition,
            },
            "timeframe": self.timeframe.total_seconds() if self.timeframe else None,
            "group_by": list(self.group_by),
            "threshold": threshold,
            "sequence": sequence,
            "tags": self.tags,
            "falsepositives": self.falsepositives,
            "level": self.level,
            "path": self.path,
        }


def _looks_like_technique(tag: str) -> bool:
    import re

    return re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag.lower()) is not None


@dataclass
class Alert:
    """A detection alert, potentially aggregated over correlated events."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    group_key: str
    group_values: dict[str, str]
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    events: list[Event] = dc_field(default_factory=list)
    techniques: list[str] = dc_field(default_factory=list)
    tags: list[str] = dc_field(default_factory=list)
    falsepositives: list[str] = dc_field(default_factory=list)
    logsource: str = ""
    hosts: set[str] = dc_field(default_factory=set)
    users: set[str] = dc_field(default_factory=set)
    src_ips: set[str] = dc_field(default_factory=set)
    max_samples: int = DEFAULT_SAMPLE_EVENTS

    def __post_init__(self) -> None:
        self.first_seen = ensure_utc(self.first_seen)
        self.last_seen = ensure_utc(self.last_seen)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    def observe(self, event: Event) -> None:
        """Update counters and bounded entity sets for a matched event."""
        if event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if event.timestamp > self.last_seen:
            self.last_seen = event.timestamp
        for entity, limit in (
            (self.hosts, MAX_OBSERVED),
            (self.users, MAX_OBSERVED),
            (self.src_ips, MAX_OBSERVED),
        ):
            if len(entity) < limit:
                value = ""
                if entity is self.hosts:
                    value = event.host
                elif entity is self.users:
                    value = event.user
                else:
                    value = event.src_ip
                if value:
                    entity.add(value)

    def add_event(self, event: Event) -> None:
        if len(self.events) >= self.max_samples:
            return
        key = event.keys
        if any(existing.keys == key for existing in self.events):
            return
        self.events.append(event)
        self.observe(event)

    def refresh(self, event: Event, count: int) -> None:
        self.count = max(self.count, count)
        self.observe(event)
        self.add_event(event)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "group": self.group_key,
            "group_values": self.group_values,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "count": self.count,
            "attack": self.techniques,
            "tags": self.tags,
            "falsepositives": self.falsepositives,
            "logsource": self.logsource,
            "hosts": sorted(self.hosts),
            "users": sorted(self.users),
            "src_ips": sorted(self.src_ips),
            "events": [event.to_dict() for event in self.events],
        }
