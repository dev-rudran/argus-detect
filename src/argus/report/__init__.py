"""Report renderers for console, JSONL, Markdown and HTML."""

from argus.report.console import render_console
from argus.report.html import render_html
from argus.report.jsonl import render_jsonl
from argus.report.markdown import render_markdown

__all__ = ["render_console", "render_html", "render_jsonl", "render_markdown"]
