"""argus - streaming detection engineering engine for Linux logs."""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Rudra Tushir"
__license__ = "MIT"

from argus.models import Alert, Event, Rule, Severity

__all__ = ["Alert", "Event", "Rule", "Severity", "__version__"]
