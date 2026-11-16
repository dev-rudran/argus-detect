"""Timestamp parsing, duration parsing and syslog year inference."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

UTC = timezone.utc

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

_DURATION_RE = re.compile(r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[smhdw])\s*$", re.I)
_EPOCH_RE = re.compile(r"^\d{10}(?:\.\d+)?$")
_RFC3164_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?P<frac>\.\d+)?$"
)


class TimeParseError(ValueError):
    """Raised when a timestamp or duration cannot be interpreted."""


def parse_duration(value: object) -> timedelta:
    """Parse ``30s``, ``5m``, ``2h``, ``1d`` or ``1w`` into a timedelta."""
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < 0:
            raise TimeParseError("duration must not be negative")
        return timedelta(seconds=float(value))
    text = str(value or "").strip()
    match = _DURATION_RE.match(text)
    if not match:
        raise TimeParseError(f"invalid duration {text!r}; expected values such as 30s, 5m, 2h, 1d")
    amount = float(match.group("value"))
    unit = match.group("unit").lower()
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    if amount <= 0:
        raise TimeParseError("duration must be greater than zero")
    return timedelta(seconds=amount * factor)


def parse_timestamp(value: object, *, year: int | None = None) -> datetime:
    """Parse ISO-8601, RFC 3164, syslog ISO or epoch timestamps.

    Naive values are interpreted as UTC. ``year`` only applies to RFC 3164
    values that omit a year.
    """
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=UTC)

    text = str(value or "").strip()
    if not text:
        raise TimeParseError("empty timestamp")

    if _EPOCH_RE.match(text):
        try:
            return datetime.fromtimestamp(float(text), tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise TimeParseError(f"invalid epoch timestamp {text!r}") from exc

    iso_text = text.replace("Z", "+00:00").replace("z", "+00:00")
    try:
        return ensure_utc(datetime.fromisoformat(iso_text))
    except ValueError:
        pass

    match = _RFC3164_RE.match(text)
    if match:
        month = _MONTHS.get(match.group("mon").lower())
        if month is None:
            raise TimeParseError(f"unknown month in timestamp {text!r}")
        today = datetime.now(tz=UTC)
        base_year = year if year is not None else today.year
        fraction = float(match.group("frac") or 0)
        try:
            parsed = datetime(
                base_year,
                month,
                int(match.group("day")),
                int(match.group("hour")),
                int(match.group("minute")),
                int(match.group("second")),
                int(fraction * 1_000_000),
                tzinfo=UTC,
            )
        except ValueError as exc:
            raise TimeParseError(f"invalid timestamp {text!r}: {exc}") from exc
        if year is None:
            parsed = _roll_forward_or_back(parsed, today)
        return parsed

    raise TimeParseError(f"unsupported timestamp format {text!r}")


def _roll_forward_or_back(parsed: datetime, now: datetime) -> datetime:
    """Infer a year for a yearless timestamp relative to ``now``."""
    candidate = parsed
    if candidate > now + timedelta(days=2):
        candidate = candidate.replace(year=candidate.year - 1)
    elif candidate < now - timedelta(days=365):
        candidate = candidate.replace(year=candidate.year + 1)
    return candidate


def ensure_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass
class YearResolver:
    """Resolve years for RFC 3164 timestamps across a file, including rollover.

    Syslog files usually omit the year. When ``--year`` is supplied it is used
    as the starting year. Without it the current year is used and future dates
    are assumed to belong to the previous year. A December to January jump
    advances the year even when a starting year was supplied.
    """

    year: int | None = None
    _last: datetime | None = None

    def resolve(self, month: int, day: int, hour: int, minute: int, second: int) -> datetime:
        now = datetime.now(tz=UTC)
        base_year = self.year if self.year is not None else now.year
        year = base_year
        if self._last is not None:
            year = self._last.year
            candidate = self._build(year, month, day, hour, minute, second)
            if candidate < self._last - timedelta(days=180):
                year += 1
            elif candidate > self._last + timedelta(days=180):
                year -= 1
        candidate = self._build(year, month, day, hour, minute, second)
        if self.year is None and self._last is None and candidate > now + timedelta(days=2):
            candidate = candidate.replace(year=candidate.year - 1)
        self._last = candidate
        return candidate

    @staticmethod
    def _build(year: int, month: int, day: int, hour: int, minute: int, second: int) -> datetime:
        try:
            return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
        except ValueError as exc:
            raise TimeParseError(f"invalid syslog date: {exc}") from exc


def parse_since_until(value: object, *, end: bool = False) -> datetime:
    """Parse a CLI date or datetime, defaulting to start/end of the UTC day."""
    text = str(value or "").strip()
    if not text:
        raise TimeParseError("empty date")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        day = date.fromisoformat(text)
        start = datetime(day.year, day.month, day.day, tzinfo=UTC)
        return start + timedelta(days=1) - timedelta(microseconds=1) if end else start
    return ensure_utc(parse_timestamp(text))


def format_duration(value: timedelta) -> str:
    """Compact human-readable duration."""
    seconds = int(value.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m" if sec == 0 else f"{minutes}m{sec}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h" if minutes == 0 else f"{hours}h{minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d" if hours == 0 else f"{days}d{hours}h"
