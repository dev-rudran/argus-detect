"""Small, dependency-free text helpers used across the project."""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"


def strip_ansi(value: str) -> str:
    """Remove ANSI escape sequences from *value*."""
    return ANSI_RE.sub("", value)


def escape_html(value: Any) -> str:
    """Escape arbitrary log content for safe HTML embedding.

    Quotes are always escaped so values can be placed in attributes as well as
    text nodes.
    """
    return html.escape(str(value), quote=True)


def escape_markdown_cell(value: Any) -> str:
    """Make a value safe inside a GitHub-flavoured Markdown table cell."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return text.replace("\r", " ").replace("\n", " ").strip()


def fence_for(text: str) -> str:
    """Return a backtick fence longer than any run inside *text*."""
    longest = 0
    for match in re.finditer(r"`+", text):
        longest = max(longest, len(match.group(0)))
    return "`" * max(3, longest + 1)


def truncate(value: Any, width: int = 160) -> str:
    """Collapse whitespace and truncate with an ASCII ellipsis."""
    text = re.sub(r"\s+", " ", str(value)).strip()
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def human_bytes(value: int | float) -> str:
    """Format a byte count in binary units."""
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"


def slug(value: str) -> str:
    """Create a conservative HTML id fragment."""
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", ascii_value).strip("-.")
    return cleaned or "item"


def colorize(value: str, code: str, enabled: bool = True) -> str:
    """Wrap *value* in an ANSI color if *enabled*."""
    if not enabled:
        return value
    return f"{code}{value}{RESET}"


def bold(value: str, enabled: bool = True) -> str:
    return f"{BOLD}{value}{RESET}" if enabled else value


def dim(value: str, enabled: bool = True) -> str:
    return f"{DIM}{value}{RESET}" if enabled else value
