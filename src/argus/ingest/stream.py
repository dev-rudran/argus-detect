"""File discovery, format detection and the streaming ingest loop."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

from argus.ingest.auditd import AuditdParser
from argus.ingest.base import BaseParser, ParserStats
from argus.ingest.jsonl import JsonlParser
from argus.ingest.sshd import SshdParser
from argus.ingest.syslog import SyslogParser
from argus.models import Event
from argus.util.timeparse import ensure_utc

MAX_LINE = 262_144
SAMPLE_LINES = 50
SAMPLE_BYTES = 8192
VALID_TYPES = {"auto", "sshd", "syslog", "jsonl", "auditd"}


class IngestError(RuntimeError):
    """Raised for unreadable inputs or invalid ingest options."""


def discover_files(paths: Iterable[str | Path]) -> list[Path]:
    """Expand files and directories into a sorted, de-duplicated file list."""
    resolved: dict[str, Path] = {}
    for raw in paths:
        path = Path(raw).expanduser()
        if not path.exists():
            raise IngestError(f"input path does not exist: {path}")
        if path.is_file():
            resolved[str(path.resolve())] = path
            continue
        if not path.is_dir():
            raise IngestError(f"input path is not a file or directory: {path}")
        for candidate in sorted(path.rglob("*")):
            if candidate.is_file():
                resolved.setdefault(str(candidate.resolve()), candidate)
    if not resolved:
        raise IngestError("no input files found")
    return [resolved[key] for key in sorted(resolved)]


def _looks_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:SAMPLE_BYTES]
    except OSError:
        return True
    return b"\x00" in sample


def _sample_lines(path: Path) -> list[str]:
    lines: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    lines.append(line.rstrip("\r\n")[:SAMPLE_BYTES])
                if len(lines) >= SAMPLE_LINES:
                    break
    except OSError as exc:
        raise IngestError(f"cannot read {path}: {exc}") from exc
    return lines


def detect_type(path: Path | str, forced: str = "auto") -> str:
    """Detect or validate the log type for a file."""
    forced = (forced or "auto").lower()
    if forced not in VALID_TYPES:
        raise IngestError(
            f"unknown log type {forced!r}; expected one of {', '.join(sorted(VALID_TYPES))}"
        )
    if forced != "auto":
        return forced
    path = Path(path)
    suffix = path.name.lower()
    sample = _sample_lines(path)
    if not sample:
        if suffix.endswith((".jsonl", ".ndjson")):
            return "jsonl"
        if "audit" in suffix:
            return "auditd"
        if "auth" in suffix:
            return "sshd"
        return "syslog"

    json_hits = 0
    audit_hits = 0
    ssh_hits = 0
    syslog_hits = 0
    for line in sample:
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                json.loads(stripped)
                json_hits += 1
                continue
            except json.JSONDecodeError:
                pass
        if "msg=audit(" in line or re.search(r"(?:^|\s)type=[A-Z0-9_]+\s", line):
            audit_hits += 1
        if "sshd[" in line or "Failed password for" in line or "Accepted publickey for" in line:
            ssh_hits += 1
        if re.match(
            r"^(?:<\d{1,3}>)?(?:\d{4}[- ]|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line
        ):
            syslog_hits += 1

    scores = {
        "jsonl": json_hits,
        "auditd": audit_hits,
        "sshd": ssh_hits,
        "syslog": syslog_hits,
    }
    if suffix.endswith((".jsonl", ".ndjson")) or suffix.endswith(".json"):
        scores["jsonl"] += 50
    if "audit" in suffix:
        scores["auditd"] += 50
    if "auth" in suffix or "secure" in suffix:
        scores["sshd"] += 50
    best = max(scores, key=lambda name: scores[name])
    if scores[best] == 0:
        return "syslog"
    return best


def make_parser(
    log_type: str, *, year: int | None = None, default_timestamp: datetime | None = None
) -> BaseParser:
    """Construct a parser for a concrete log type."""
    if log_type == "sshd":
        return SshdParser(year=year, default_timestamp=default_timestamp)
    if log_type == "jsonl":
        return JsonlParser(year=year, default_timestamp=default_timestamp)
    if log_type == "auditd":
        return AuditdParser(year=year, default_timestamp=default_timestamp)
    if log_type == "syslog":
        return SyslogParser(year=year, default_timestamp=default_timestamp)
    raise IngestError(f"cannot construct parser for type {log_type!r}")


def iter_events(
    paths: Iterable[str | Path],
    *,
    forced_type: str = "auto",
    year: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    stats: ParserStats | None = None,
) -> Iterator[Event]:
    """Yield normalized events from files, streaming line by line."""
    stats = stats or ParserStats()
    files = discover_files(paths)
    since = ensure_utc(since) if since is not None else None
    until = ensure_utc(until) if until is not None else None
    for path in files:
        if _looks_binary(path):
            stats.skipped_files += 1
            continue
        log_type = detect_type(path, forced_type)
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime).astimezone()
        except OSError:
            mtime = None
        parser = make_parser(log_type, year=year, default_timestamp=mtime)
        stats.files += 1
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_no, line in enumerate(handle, start=1):
                    if len(line) > MAX_LINE:
                        line = line[:MAX_LINE]
                        stats.truncated += 1
                    if not line.strip():
                        stats.blank += 1
                        continue
                    try:
                        event = parser.parse_line(line, line_no, str(path))
                    except (ValueError, UnicodeError):
                        event = None
                    if event is None:
                        stats.add_malformed()
                        continue
                    if since is not None and event.timestamp < since:
                        stats.filtered += 1
                        continue
                    if until is not None and event.timestamp > until:
                        stats.filtered += 1
                        continue
                    stats.add_event(event)
                    yield event
        except OSError as exc:
            raise IngestError(f"cannot read {path}: {exc}") from exc
