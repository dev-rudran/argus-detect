"""Text helper tests."""

from __future__ import annotations

from argus.util.text import (
    bold,
    colorize,
    dim,
    escape_html,
    escape_markdown_cell,
    fence_for,
    human_bytes,
    slug,
    strip_ansi,
    truncate,
)


def test_escape_html_escapes_tags_and_quotes():
    escaped = escape_html('<script>alert("x") & more</script>')
    assert "<script" not in escaped
    assert escaped == "&lt;script&gt;alert(&quot;x&quot;) &amp; more&lt;/script&gt;"


def test_escape_markdown_cell_escapes_pipes_and_newlines():
    assert escape_markdown_cell("a|b\nc\r\nd") == "a\\|b c  d"
    assert escape_markdown_cell("back\\slash") == "back\\\\slash"


def test_fence_for_is_longer_than_embedded_backticks():
    assert fence_for("plain") == "```"
    assert fence_for("a ``` b") == "````"
    assert fence_for("``````") == "```````"


def test_truncate_collapses_whitespace_and_adds_ascii_ellipsis():
    assert truncate("a\n\t b   c", 40) == "a b c"
    assert truncate("abcdefghij", 7) == "abcd..."
    assert truncate("abcdefghij", 3) == "abc"


def test_ansi_and_style_helpers():
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"
    assert bold("x", True) == "\x1b[1mx\x1b[0m"
    assert bold("x", False) == "x"
    assert dim("x", True).startswith("\x1b[2m")
    assert colorize("x", "\x1b[31m", True) == "\x1b[31mx\x1b[0m"
    assert colorize("x", "\x1b[31m", False) == "x"


def test_human_bytes_uses_binary_units():
    assert human_bytes(0) == "0 B"
    assert human_bytes(1023) == "1023 B"
    assert human_bytes(1024) == "1.0 KiB"
    assert human_bytes(5 * 1024 * 1024) == "5.0 MiB"


def test_slug_is_filesystem_and_html_safe():
    assert slug("Hello, World!") == "Hello-World"
    assert slug("..") == "item"
    assert slug("Café rule") == "Cafe-rule"
