"""Shared fixtures for the argus test suite."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from argus.models import Event

UTC = timezone.utc
PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = PROJECT_ROOT / "src" / "argus" / "rules"
BENIGN_DIR = PROJECT_ROOT / "examples" / "logs" / "benign"
ATTACK_DIR = PROJECT_ROOT / "examples" / "logs" / "attack"


def make_event(
    fields: dict[str, Any] | None = None,
    *,
    timestamp: datetime | None = None,
    source: str = "test.log",
    line_no: int = 1,
    raw: str = "test event",
    log_type: str = "test",
) -> Event:
    """Create a normalized event with sensible defaults."""
    return Event(
        timestamp=timestamp or datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        fields=dict(fields or {}),
        raw=raw,
        source=source,
        line_no=line_no,
        log_type=log_type,
    )


@pytest.fixture
def event_factory():
    return make_event


@pytest.fixture
def base_rule() -> dict[str, Any]:
    """A minimal valid rule mapping that tests can copy and mutate."""
    return {
        "id": "ARGUS-9001",
        "title": "Test rule",
        "description": "A unit-test rule that describes a synthetic condition.",
        "severity": "high",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {
            "selection": {"action": "ssh_auth_failed"},
            "condition": "selection",
        },
        "tags": ["attack.credential_access", "attack.t1110"],
        "falsepositives": ["Synthetic test traffic."],
    }
