"""Shared parser base classes and statistics."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime

from argus.models import Event
from argus.util.timeparse import UTC


@dataclass
class ParserStats:
    files: int = 0
    lines: int = 0
    events: int = 0
    blank: int = 0
    malformed: int = 0
    truncated: int = 0
    filtered: int = 0
    skipped_files: int = 0
    by_type: dict[str, int] = dc_field(default_factory=dict)

    def add_event(self, event: Event) -> None:
        self.lines += 1
        self.events += 1
        self.by_type[event.log_type] = self.by_type.get(event.log_type, 0) + 1

    def add_malformed(self) -> None:
        self.lines += 1
        self.malformed += 1


class BaseParser:
    """Line-oriented parser interface."""

    log_type = "unknown"

    def __init__(self, year: int | None = None, default_timestamp: datetime | None = None) -> None:
        self.year = year
        self.default_timestamp = default_timestamp or datetime.now(tz=UTC)

    def parse_line(self, line: str, line_no: int, source: str) -> Event | None:
        raise NotImplementedError

    def clean(self, line: str) -> str:
        return line.rstrip("\r\n")
