"""Colored console incident report."""

from __future__ import annotations

from datetime import datetime

from argus.attack import technique
from argus.models import Alert, Severity
from argus.report.common import ScanContext
from argus.util.text import bold, dim, truncate

RESET = "\x1b[0m"
SEVERITY_COLOR = {
    Severity.INFORMATIONAL: "\x1b[2;37m",
    Severity.LOW: "\x1b[36m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.HIGH: "\x1b[31m",
    Severity.CRITICAL: "\x1b[1;97;41m",
}


def _paint(value: str, severity: Severity, color: bool) -> str:
    if not color:
        return value
    return f"{SEVERITY_COLOR[severity]}{value}{RESET}"


def _header(value: str, color: bool) -> str:
    return bold(value, color)


def _time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def render_console(ctx: ScanContext, *, color: bool = True, stats: bool = False) -> str:
    """Render a console report as a string."""
    lines: list[str] = []
    alerts = sorted(
        ctx.visible_alerts,
        key=lambda alert: (-alert.severity.rank, alert.first_seen, alert.rule_id),
    )
    lines.append(_header(f"argus {ctx.version}  detection report", color))
    lines.append(
        dim(
            f"rules {len(ctx.result.rules)}  |  events {ctx.parser_stats.events:,}  |  "
            f"files {ctx.parser_stats.files}  |  malformed {ctx.parser_stats.malformed}",
            color,
        )
    )
    if ctx.result.stats.first_event and ctx.result.stats.last_event:
        lines.append(
            dim(
                f"window {_time(ctx.result.stats.first_event)} .. {_time(ctx.result.stats.last_event)} UTC",
                color,
            )
        )
    lines.append("")

    if not alerts:
        lines.append(f"No alerts at or above {ctx.min_severity.value}.")
    for alert in alerts:
        lines.extend(_render_alert(alert, color))
        lines.append("")

    lines.extend(_render_summary(ctx, color, alerts))
    if stats:
        lines.extend(_render_stats(ctx, color))
    return "\n".join(lines).rstrip() + "\n"


def _render_alert(alert: Alert, color: bool) -> list[str]:
    label = alert.severity.value.upper()
    lines = [
        f"{_paint(label, alert.severity, color)}  {_header(alert.rule_id, color)}  {alert.title}"
    ]
    lines.append(f"  group: {alert.group_key}   logsource: {alert.logsource}")
    lines.append(
        f"  first seen: {_time(alert.first_seen)}   last seen: {_time(alert.last_seen)}   "
        f"count: {alert.count}"
    )
    attack = []
    for technique_id in alert.techniques:
        item = technique(technique_id)
        attack.append(f"{technique_id} {item.name}" if item else technique_id)
    if attack:
        lines.append("  ATT&CK: " + "; ".join(attack))
    if alert.events:
        label_text = f"  evidence ({min(len(alert.events), 5)} of {alert.count} matched events):"
        lines.append(label_text)
        for event in alert.events[:5]:
            stamp = _time(event.timestamp)
            where = f"{event.source}:{event.line_no}"
            lines.append(
                dim(
                    f"    {stamp}  {event.log_type:7} {truncate(event.message, 190)}  [{where}]",
                    color,
                )
            )
    return lines


def _render_summary(ctx: ScanContext, color: bool, alerts: list[Alert]) -> list[str]:
    lines = [_header("Summary", color)]
    counts = dict.fromkeys(Severity, 0)
    for alert in alerts:
        counts[alert.severity] += 1
    severity_line = "  ".join(
        _paint(f"{severity.value} {counts[severity]}", severity, color)
        for severity in reversed(list(Severity))
        if counts[severity]
    )
    lines.append("  " + (severity_line or "no alerts"))
    if ctx.result.stats.suppressed:
        lines.append(f"  suppressed: {ctx.result.stats.suppressed}")
    if alerts:
        lines.append("  top rules:")
        for rule_id, title, count in ctx.rule_counts[:10]:
            lines.append(f"    {rule_id}  {truncate(title, 70)}  x{count}")
        host_counts: dict[str, int] = {}
        for alert in alerts:
            for host in alert.hosts:
                host_counts[host] = host_counts.get(host, 0) + 1
        if host_counts:
            lines.append("  hosts:")
            for host, count in sorted(host_counts.items(), key=lambda item: (-item[1], item[0]))[
                :10
            ]:
                lines.append(f"    {host}  x{count}")
    return lines


def _render_stats(ctx: ScanContext, color: bool) -> list[str]:
    stats = ctx.parser_stats
    lines = [
        "",
        _header("Ingest", color),
        f"  files {stats.files}   lines {stats.lines:,}   events {stats.events:,}   malformed {stats.malformed}",
        f"  filtered {stats.filtered}   skipped files {stats.skipped_files}   truncated {stats.truncated}",
        f"  elapsed {ctx.elapsed_seconds:.3f}s   {ctx.events_per_second:,.0f} events/s",
    ]
    if stats.by_type:
        types = ", ".join(f"{name} {count:,}" for name, count in sorted(stats.by_type.items()))
        lines.append(f"  log types: {types}")
    if ctx.result.stats.stale:
        lines.append(f"  out-of-window events: {ctx.result.stats.stale}")
    return lines
