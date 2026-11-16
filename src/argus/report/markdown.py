"""Markdown incident report."""

from __future__ import annotations

from argus.attack import TACTICS, technique
from argus.models import Alert
from argus.report.common import ScanContext
from argus.util.text import escape_markdown_cell, fence_for, truncate


def render_markdown(ctx: ScanContext) -> str:
    """Render an incident-style Markdown report."""
    alerts = ctx.visible_alerts
    meta = ctx.metadata()
    counts = ctx.severity_counts
    lines: list[str] = []
    lines.append("# argus incident report")
    lines.append("")
    lines.append(f"**Generated:** {ctx.finished.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    lines.append(f"**Ruleset:** `{ctx.rules_path}` ({meta['rules']} rules)  ")
    lines.append(f"**Time range:** {ctx.time_range}  ")
    lines.append(
        f"**Events processed:** {meta['events']:,} from {meta['files']} files "
        f"(malformed {meta['malformed']}, filtered {meta['filtered']})  "
    )
    lines.append(
        f"**Alerts:** {len(alerts)} "
        f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, "
        f"low {counts['low']}, informational {counts['informational']})  "
    )
    if meta["suppressed"]:
        lines.append(f"**Suppressed by policy:** {meta['suppressed']}  ")
    lines.append("")
    lines.append(
        "> Heuristic detections. Tune rules against your own baseline before paging on them."
    )
    lines.append("")

    lines.append("## Severity summary")
    lines.append("")
    lines.append("| Severity | Alerts |")
    lines.append("|---|---:|")
    for severity in ("critical", "high", "medium", "low", "informational"):
        lines.append(f"| {severity.title()} | {counts[severity]} |")
    lines.append("")

    if not alerts:
        lines.append("No alerts at or above the configured severity threshold.")
        lines.append("")
    else:
        lines.append("## Rules triggered")
        lines.append("")
        lines.append("| Rule | Title | Severity | Alerts | ATT&CK |")
        lines.append("|---|---|---|---:|---|")
        by_rule: dict[str, list[Alert]] = {}
        for alert in alerts:
            by_rule.setdefault(alert.rule_id, []).append(alert)
        for rule_id, group in sorted(by_rule.items(), key=lambda item: item[0]):
            first = group[0]
            techniques = ", ".join(first.techniques)
            lines.append(
                f"| {rule_id} | {escape_markdown_cell(first.title)} | {first.severity.value} | "
                f"{len(group)} | {escape_markdown_cell(techniques)} |"
            )
        lines.append("")

        lines.append("## Incident timeline")
        lines.append("")
        lines.append("| UTC | Host | User | Source IP | Event | Rules |")
        lines.append("|---|---|---|---|---|---|")
        if ctx.timeline is None:
            raise RuntimeError("report context is missing timeline data")
        for entry in ctx.timeline.entries:
            rules = ", ".join(sorted({item[0] for item in entry.rules}))
            lines.append(
                f"| {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{escape_markdown_cell(entry.host)} | {escape_markdown_cell(entry.user)} | "
                f"{escape_markdown_cell(entry.src_ip)} | "
                f"{escape_markdown_cell(truncate(entry.message, 140))} | "
                f"{escape_markdown_cell(rules)} |"
            )
        if ctx.timeline.truncated:
            lines.append("")
            lines.append(f"Timeline truncated by {ctx.timeline.truncated} entries.")
        lines.append("")

        lines.append("## Alerts")
        lines.append("")
        for alert in alerts:
            lines.extend(_render_alert(alert))
            lines.append("")

    lines.append("## ATT&CK coverage")
    lines.append("")
    if ctx.coverage_report is None:
        raise RuntimeError("report context is missing coverage data")
    coverage_report = ctx.coverage_report
    lines.append(
        f"Rules cover {coverage_report.covered_count} of {coverage_report.catalog_count} "
        f"catalogued techniques ({coverage_report.percent:.1f}%)."
    )
    lines.append("")
    lines.append("| Tactic | Covered | Techniques with rules |")
    lines.append("|---|---:|---|")
    for tactic, label in TACTICS:
        covered = coverage_report.tactic_covered(tactic)
        total = coverage_report.tactic_ids(tactic)
        if not total:
            continue
        rendered = ", ".join(
            f"{identifier} {coverage_report.catalog[identifier].name}" for identifier in covered
        )
        lines.append(
            f"| {label} | {len(covered)}/{len(total)} | {escape_markdown_cell(rendered or 'none')} |"
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        "This report is generated from matched log evidence retained in memory. "
        "Alert counts aggregate correlated events; evidence samples are bounded."
    )
    lines.append("")
    return "\n".join(lines)


def _render_alert(alert: Alert) -> list[str]:
    lines = [
        f"### {alert.severity.value.upper()} {alert.rule_id} - {alert.title}",
        "",
        f"**Group:** `{alert.group_key}`  ",
        f"**Logsource:** {alert.logsource}  ",
        f"**First seen:** {alert.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Last seen:** {alert.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Count:** {alert.count} events",
        "",
        alert.description,
        "",
    ]
    attack: list[str] = []
    for technique_id in alert.techniques:
        item = technique(technique_id)
        if item:
            attack.append(f"[{item.id}]({item.url}) {item.name}")
        else:
            attack.append(technique_id)
    if attack:
        lines.append("**ATT&CK:** " + "; ".join(attack))
        lines.append("")
    if alert.hosts or alert.users or alert.src_ips:
        entities = []
        if alert.hosts:
            entities.append("hosts: " + ", ".join(sorted(alert.hosts)))
        if alert.users:
            entities.append("users: " + ", ".join(sorted(alert.users)))
        if alert.src_ips:
            entities.append("source IPs: " + ", ".join(sorted(alert.src_ips)))
        lines.append("**Entities:** " + "; ".join(entities))
        lines.append("")
    lines.append("**Evidence**")
    lines.append("")
    evidence_lines = [
        f"{event.timestamp.isoformat()} {event.host} {event.message}  [{event.source}:{event.line_no}]"
        for event in alert.events
    ]
    evidence = "\n".join(evidence_lines)
    fence = fence_for(evidence)
    lines.append(fence + "text")
    lines.append(evidence)
    lines.append(fence)
    lines.append("")
    if alert.falsepositives:
        lines.append("**False positives:** " + "; ".join(alert.falsepositives))
        lines.append("")
    return lines
