"""Timestamp, duration and year-inference tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from argus.util.timeparse import (
    UTC,
    TimeParseError,
    YearResolver,
    ensure_utc,
    format_duration,
    parse_duration,
    parse_since_until,
    parse_timestamp,
)


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400), ("1w", 604800), ("1.5h", 5400)],
)
def test_parse_duration_units(text, seconds):
    assert parse_duration(text) == timedelta(seconds=seconds)


def test_parse_duration_accepts_numbers_and_timedelta():
    assert parse_duration(90) == timedelta(seconds=90)
    assert parse_duration(2.5) == timedelta(seconds=2.5)
    existing = timedelta(minutes=3)
    assert parse_duration(existing) is existing


@pytest.mark.parametrize("text", ["", "five minutes", "10", "1 month", "-5m", "0s"])
def test_parse_duration_rejects_invalid_values(text):
    with pytest.raises(TimeParseError):
        parse_duration(text)


def test_parse_duration_rejects_negative_number():
    with pytest.raises(TimeParseError):
        parse_duration(-1)


def test_parse_timestamp_iso_and_epoch():
    assert parse_timestamp("2026-11-10T03:04:05Z") == datetime(2026, 11, 10, 3, 4, 5, tzinfo=UTC)
    assert parse_timestamp("2026-11-10T05:04:05+02:00") == datetime(
        2026, 11, 10, 3, 4, 5, tzinfo=UTC
    )
    assert parse_timestamp("2026-11-10 03:04:05") == datetime(2026, 11, 10, 3, 4, 5, tzinfo=UTC)
    assert parse_timestamp(1762743845) == datetime.fromtimestamp(1762743845, tz=UTC)
    assert parse_timestamp("1762743845.5").microsecond == 500000


def test_parse_timestamp_rfc3164_honors_year():
    parsed = parse_timestamp("Nov 10 03:04:05", year=2024)
    assert parsed == datetime(2024, 11, 10, 3, 4, 5, tzinfo=UTC)


def test_parse_timestamp_accepts_datetime_and_normalizes_utc():
    value = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=5)))
    parsed = parse_timestamp(value)
    assert parsed.tzinfo == timezone.utc
    assert parsed.hour == 22
    assert parsed.day == 1


@pytest.mark.parametrize("text", ["", "not a time", "2026-13-40T99:99:99Z", "Nov 99 03:04:05"])
def test_parse_timestamp_rejects_invalid_values(text):
    with pytest.raises(TimeParseError):
        parse_timestamp(text, year=2026)


def test_year_resolver_rolls_december_into_january():
    resolver = YearResolver(year=2026)
    december = resolver.resolve(12, 31, 23, 59, 0)
    january = resolver.resolve(1, 1, 0, 1, 0)
    assert december.year == 2026
    assert january.year == 2027


def test_year_resolver_steps_back_when_initial_date_is_in_the_future():
    resolver = YearResolver()
    tomorrow = datetime.now(tz=UTC) + timedelta(days=5)
    resolved = resolver.resolve(tomorrow.month, tomorrow.day, 12, 0, 0)
    assert resolved.year == tomorrow.year - 1


def test_year_resolver_rejects_invalid_dates():
    resolver = YearResolver(year=2026)
    with pytest.raises(TimeParseError):
        resolver.resolve(2, 30, 10, 0, 0)


def test_parse_since_until_dates_cover_the_whole_utc_day():
    start = parse_since_until("2026-11-10")
    end = parse_since_until("2026-11-10", end=True)
    assert start == datetime(2026, 11, 10, tzinfo=UTC)
    assert end == datetime(2026, 11, 10, 23, 59, 59, 999999, tzinfo=UTC)


def test_parse_since_until_accepts_datetimes():
    assert parse_since_until("2026-11-10T03:00:00Z") == datetime(2026, 11, 10, 3, tzinfo=UTC)


def test_ensure_utc_and_format_duration():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    assert ensure_utc(naive).tzinfo is UTC
    assert format_duration(timedelta(seconds=5)) == "5s"
    assert format_duration(timedelta(seconds=90)) == "1m30s"
    assert format_duration(timedelta(minutes=120)) == "2h"
    assert format_duration(timedelta(hours=25)) == "1d1h"
