"""Field matchers used by detection selections.

Values are case-insensitive by default. Supported modifiers are ``contains``,
``startswith``, ``endswith``, ``re``, ``cidr``, ``gt``, ``lt``, ``gte`` and
``lte``. A bare field uses exact equality unless the value contains ``*`` or
``?``, in which case it is evaluated as a full-string glob.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dc_field
from re import Pattern
from typing import Any

from argus.util.net import parse_ip, parse_network

MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "cidr",
    "gt",
    "lt",
    "gte",
    "lte",
    "exists",
    "in",
}

MAX_PATTERN_LENGTH = 1024


class MatchError(ValueError):
    """Raised for invalid field expressions or matcher values."""


def split_field_expression(expression: str) -> tuple[str, str | None]:
    """Split ``field|modifier`` into its two parts."""
    if not isinstance(expression, str) or not expression.strip():
        raise MatchError("field expression must be a non-empty string")
    parts = [part.strip() for part in expression.strip().split("|")]
    if len(parts) > 2:
        raise MatchError(f"field expression {expression!r} has more than one modifier")
    name = parts[0]
    modifier = parts[1].lower() if len(parts) == 2 else None
    if not name:
        raise MatchError(f"field expression {expression!r} has an empty field name")
    if modifier is not None and modifier not in MODIFIERS:
        raise MatchError(
            f"unknown modifier {modifier!r} in {expression!r}; "
            f"supported: {', '.join(sorted(MODIFIERS))}"
        )
    return name, modifier


def _strings(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(item) for item in value]
    return [str(value)]


def _scalar(value: Any) -> Any:
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            return item
        return None
    return value


def glob_to_regex(pattern: str, case_sensitive: bool = False) -> Pattern[str]:
    """Translate a ``*``/``?`` glob into a compiled regex."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise MatchError("glob pattern is too long")
    pieces: list[str] = []
    for char in pattern:
        if char == "*":
            pieces.append(".*")
        elif char == "?":
            pieces.append(".")
        else:
            pieces.append(re.escape(char))
    flags = re.DOTALL if case_sensitive else re.IGNORECASE | re.DOTALL
    try:
        return re.compile("^" + "".join(pieces) + "$", flags)
    except re.error as exc:  # pragma: no cover - defensive
        raise MatchError(f"invalid glob pattern {pattern!r}: {exc}") from exc


def _compile_regex(pattern: str, case_sensitive: bool) -> Pattern[str]:
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise MatchError("regular expression is too long")
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise MatchError(f"invalid regular expression {pattern!r}: {exc}") from exc


def _to_number(value: Any) -> float | None:
    scalar = _scalar(value)
    if isinstance(scalar, bool):
        return None
    if isinstance(scalar, (int, float)):
        return float(scalar)
    text = str(scalar).strip().replace(",", "")
    if not text:
        return None
    match = re.match(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", text)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


@dataclass
class CompiledPattern:
    """One value inside a selection, already compiled where possible."""

    value: Any
    case_sensitive: bool = False
    regex: Pattern[str] | None = dc_field(default=None, repr=False)
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = dc_field(
        default=None, repr=False
    )
    number: float | None = dc_field(default=None, repr=False)
    exact: str | None = dc_field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.exact is None:
            self.exact = _stringify(self.value)

    def match(self, raw: Any, modifier: str | None) -> bool:
        values = _strings(raw) if isinstance(raw, (list, tuple, set, frozenset)) else [raw]
        return any(self._match_one(value, modifier) for value in values)

    def _match_one(self, raw: Any, modifier: str | None) -> bool:
        if modifier == "exists":
            return raw is not None
        if modifier == "cidr":
            address = parse_ip(raw)
            if address is None or self.network is None:
                return False
            try:
                return address in self.network
            except TypeError:
                # IPv4 address in an IPv6 network and vice versa.
                return False
        if modifier in {"gt", "lt", "gte", "lte"}:
            left = _to_number(raw)
            if left is None or self.number is None:
                return False
            if modifier == "gt":
                return left > self.number
            if modifier == "lt":
                return left < self.number
            if modifier == "gte":
                return left >= self.number
            return left <= self.number
        if modifier == "re":
            return self.regex is not None and self.regex.search(_stringify(raw)) is not None
        text = _stringify(raw)
        if modifier == "contains":
            left = text if self.case_sensitive else text.lower()
            right = self.exact if self.case_sensitive else self.exact.lower()
            return right in left
        if modifier == "startswith":
            left = text if self.case_sensitive else text.lower()
            right = self.exact if self.case_sensitive else self.exact.lower()
            return left.startswith(right)
        if modifier == "endswith":
            left = text if self.case_sensitive else text.lower()
            right = self.exact if self.case_sensitive else self.exact.lower()
            return left.endswith(right)
        if modifier == "in":
            if self.case_sensitive:
                return text in [str(item) for item in _as_list(self.value)]
            return text.lower() in [str(item).lower() for item in _as_list(self.value)]
        if self.regex is not None:
            return self.regex.search(text) is not None
        if self.case_sensitive:
            return text == self.exact
        return text.lower() == self.exact.lower()


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def compile_pattern(value: Any, modifier: str | None, case_sensitive: bool) -> CompiledPattern:
    """Compile one selection value, validating regexes and networks eagerly."""
    if isinstance(value, dict):
        raise MatchError("selection values may not be mappings")
    if isinstance(value, (list, tuple, set, frozenset)):
        raise MatchError("selection values must be scalars; use a list at the field level for OR")
    pattern = CompiledPattern(value=value, case_sensitive=case_sensitive)
    if modifier == "re":
        pattern.regex = _compile_regex(str(value), case_sensitive)
    elif modifier == "cidr":
        pattern.network = parse_network(value)
        if pattern.network is None:
            raise MatchError(f"invalid CIDR value {value!r}")
    elif modifier in {"gt", "lt", "gte", "lte"}:
        pattern.number = _to_number(value)
        if pattern.number is None:
            raise MatchError(f"numeric modifier requires a number, got {value!r}")
    elif modifier is None and isinstance(value, str) and ("*" in value or "?" in value):
        pattern.regex = glob_to_regex(value, case_sensitive)
    return pattern


@dataclass
class FieldMatcher:
    """Compiled matcher for one field in one selection."""

    field: str
    modifier: str | None
    values: list[CompiledPattern]
    case_sensitive: bool = False

    @classmethod
    def build(cls, expression: str, value: Any, *, case_sensitive: bool = False) -> FieldMatcher:
        name, modifier = split_field_expression(expression)
        if value is None:
            raise MatchError(f"field {expression!r} has an empty value")
        raw_values = _as_list(value)
        if not raw_values:
            raise MatchError(f"field {expression!r} has an empty value list")
        compiled = [compile_pattern(item, modifier, case_sensitive) for item in raw_values]
        return cls(field=name, modifier=modifier, values=compiled, case_sensitive=case_sensitive)

    def matches_value(self, raw: Any) -> bool:
        if raw is None:
            return any(
                pattern.match(raw, self.modifier)
                for pattern in self.values
                if self.modifier == "exists"
            )
        return any(pattern.match(raw, self.modifier) for pattern in self.values)

    def matches_event(self, event: Any) -> bool:
        return self.matches_value(event.get(self.field))

    def describe(self) -> str:
        rendered = [str(pattern.value) for pattern in self.values]
        suffix = f"|{self.modifier}" if self.modifier else ""
        return f"{self.field}{suffix}={rendered[0] if len(rendered) == 1 else rendered}"


def matches_any(values: Iterable[Any], matchers: Iterable[FieldMatcher]) -> bool:
    return any(matcher.matches_value(value) for value in values for matcher in matchers)
