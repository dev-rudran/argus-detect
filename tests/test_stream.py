"""File discovery, type detection and streaming ingest tests."""

from __future__ import annotations

from datetime import datetime

import pytest
from conftest import UTC

from argus.ingest import IngestError
from argus.ingest.base import ParserStats
from argus.ingest.stream import (
    MAX_LINE,
    detect_type,
    discover_files,
    iter_events,
    make_parser,
)


def test_discover_files_expands_directories_and_deduplicates(tmp_path):
    first = tmp_path / "a.log"
    first.write_text("a\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    second = nested / "b.log"
    second.write_text("b\n", encoding="utf-8")
    files = discover_files([tmp_path, str(first)])
    assert files == [first, second]


def test_discover_files_rejects_missing_and_empty_inputs(tmp_path):
    with pytest.raises(IngestError, match="does not exist"):
        discover_files([tmp_path / "missing"])
    with pytest.raises(IngestError, match="no input files"):
        discover_files([tmp_path])


@pytest.mark.parametrize(
    ("name", "lines", "expected"),
    [
        (
            "auth.log",
            ["Nov 10 03:04:05 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"],
            "sshd",
        ),
        (
            "secure",
            [
                "Nov 10 03:04:05 host sshd[1]: Accepted publickey for deploy from 1.2.3.4 port 22 ssh2"
            ],
            "sshd",
        ),
        ("app.jsonl", ['{"timestamp":"2026-11-10T03:04:05Z","user":"deploy"}'], "jsonl"),
        ("audit.log", ["type=SYSCALL msg=audit(1762743845.123:1): uid=0"], "auditd"),
        ("system.log", ["Nov 10 03:04:05 host systemd[1]: Started nginx.service."], "syslog"),
        ("unknown", [], "syslog"),
    ],
)
def test_detect_type_uses_content_and_filename_hints(tmp_path, name, lines, expected):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert detect_type(path) == expected


def test_detect_type_validates_forced_type(tmp_path):
    path = tmp_path / "log"
    path.write_text("x\n", encoding="utf-8")
    assert detect_type(path, "jsonl") == "jsonl"
    with pytest.raises(IngestError, match="unknown log type"):
        detect_type(path, "csv")


def test_make_parser_selects_concrete_parser():
    assert make_parser("sshd").log_type == "sshd"
    assert make_parser("syslog").log_type == "syslog"
    assert make_parser("jsonl").log_type == "jsonl"
    assert make_parser("auditd").log_type == "auditd"
    with pytest.raises(IngestError):
        make_parser("csv")


def test_iter_events_streams_and_counts(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "Nov 10 03:04:05 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "\n"
        "this line is malformed\n"
        "Nov 10 03:04:06 web01 sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )
    stats = ParserStats()
    events = list(iter_events([path], forced_type="sshd", year=2026, stats=stats))
    assert len(events) == 2
    assert stats.files == 1
    assert stats.events == 2
    assert stats.blank == 1
    assert stats.malformed == 1
    assert stats.by_type == {"sshd": 2}
    assert events[0].fields["user"] == "root"


def test_iter_events_filters_since_and_until(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "Nov 10 03:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "Nov 10 04:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )
    stats = ParserStats()
    since = datetime(2026, 11, 10, 3, 30, tzinfo=UTC)
    until = datetime(2026, 11, 10, 4, 30, tzinfo=UTC)
    events = list(
        iter_events([path], forced_type="sshd", year=2026, since=since, until=until, stats=stats)
    )
    assert [event.timestamp.hour for event in events] == [4]
    assert stats.filtered == 1


def test_iter_events_skips_binary_files(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abc\x00def")
    stats = ParserStats()
    assert list(iter_events([path], stats=stats)) == []
    assert stats.skipped_files == 1


def test_iter_events_truncates_excessively_long_lines(tmp_path):
    path = tmp_path / "auth.log"
    payload = "Nov 10 03:04:05 web01 sshd[1]: " + "x" * (MAX_LINE + 20) + "\n"
    path.write_text(payload, encoding="utf-8")
    stats = ParserStats()
    events = list(iter_events([path], forced_type="sshd", year=2026, stats=stats))
    assert len(events) == 1
    assert stats.truncated == 1
