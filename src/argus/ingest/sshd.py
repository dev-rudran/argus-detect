"""OpenSSH auth.log parser.

OpenSSH writes RFC 3164 syslog lines (with or without a year) or RFC 5424
lines. The parser also recognizes the sudo, su, cron, systemd, useradd and
kernel records that normally share auth.log or syslog.
"""

from __future__ import annotations

from datetime import datetime

from argus.ingest.base import BaseParser
from argus.ingest.syslog import SyslogParser
from argus.models import Event


class SshdParser(BaseParser):
    """Auth.log parser built on the shared syslog classifier."""

    log_type = "sshd"

    def __init__(self, year: int | None = None, default_timestamp: datetime | None = None) -> None:
        super().__init__(year=year, default_timestamp=default_timestamp)
        self._delegate = SyslogParser(
            year=year, default_timestamp=default_timestamp, log_type=self.log_type
        )

    def parse_line(self, line: str, line_no: int, source: str) -> Event | None:
        event = self._delegate.parse_line(line, line_no, source)
        if event is not None:
            event.log_type = self.log_type
        return event
