"""Streaming log parsers and auto-detection."""

from __future__ import annotations

from argus.ingest.auditd import AuditdParser
from argus.ingest.jsonl import JsonlParser
from argus.ingest.sshd import SshdParser
from argus.ingest.stream import (
    IngestError,
    ParserStats,
    detect_type,
    discover_files,
    iter_events,
    make_parser,
)
from argus.ingest.syslog import SyslogParser

__all__ = [
    "AuditdParser",
    "IngestError",
    "JsonlParser",
    "ParserStats",
    "SshdParser",
    "SyslogParser",
    "detect_type",
    "discover_files",
    "iter_events",
    "make_parser",
]
