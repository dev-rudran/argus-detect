"""Self-contained HTML incident report with inline CSS and JavaScript."""

from __future__ import annotations

from argus.attack import TACTICS, coverage, technique
from argus.models import Alert, Rule, Severity
from argus.report.common import ScanContext
from argus.util.text import escape_html, truncate

SEVERITY_CLASS = {
    Severity.INFORMATIONAL: "info",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}


def render_html(ctx: ScanContext) -> str:
    """Render a standalone HTML report (no CDN, webfonts or external assets)."""
    alerts = ctx.visible_alerts
    meta = ctx.metadata()
    counts = ctx.severity_counts
    technique_counts = ctx.technique_alert_counts
    if ctx.timeline is None or ctx.coverage_report is None:
        raise RuntimeError("report context is missing timeline or coverage data")

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; img-src data:\">"
    )
    parts.append(
        f"<title>argus detection report - {escape_html(ctx.finished.strftime('%Y-%m-%d %H:%M'))}</title>"
    )
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append('<div class="page">')

    parts.append('<header class="hero">')
    parts.append(
        '<div class="brand"><span class="eye" aria-hidden="true"></span><span>argus</span></div>'
    )
    parts.append("<h1>Detection report</h1>")
    parts.append(
        f'<p class="subtitle">Generated {escape_html(ctx.finished.strftime("%Y-%m-%d %H:%M:%S UTC"))} '
        f"from {meta['events']:,} events across {meta['files']} files.</p>"
    )
    parts.append("</header>")

    parts.append('<section class="cards metadata" aria-label="Scan metadata">')
    for label, value in (
        ("Ruleset", f"{meta['rules']} rules"),
        ("Events", f"{meta['events']:,}"),
        ("Malformed", str(meta["malformed"])),
        ("Alerts", str(len(alerts))),
        ("Suppressed", str(meta["suppressed"])),
        ("Elapsed", f"{meta['duration_seconds']:.3f}s"),
    ):
        parts.append(
            '<div class="card meta-card"><span class="meta-label">'
            + escape_html(label)
            + '</span><span class="meta-value">'
            + escape_html(value)
            + "</span></div>"
        )
    parts.append("</section>")
    parts.append(
        '<div class="meta-line"><span><strong>Ruleset:</strong> '
        + escape_html(ctx.rules_path)
        + "</span><span><strong>Time range:</strong> "
        + escape_html(ctx.time_range)
        + "</span><span><strong>Minimum severity:</strong> "
        + escape_html(ctx.min_severity.value)
        + "</span></div>"
    )

    parts.append('<section aria-label="Severity summary">')
    parts.append('<div class="cards severity-cards">')
    for severity in reversed(list(Severity)):
        count = counts[severity.value]
        parts.append(
            f'<button type="button" class="card severity-card {SEVERITY_CLASS[severity]}" '
            f'data-min-rank="{severity.rank}" title="Filter to {severity.value} and above">'
            f'<span class="sev-label">{severity.value.title()}</span>'
            f'<span class="sev-value">{count}</span></button>'
        )
    parts.append("</div>")
    parts.append("</section>")

    parts.append('<section id="alerts" aria-label="Alerts">')
    parts.append('<div class="section-head"><h2>Alerts</h2>')
    parts.append('<div class="controls">')
    parts.append('<label class="sr-only" for="severity-filter">Minimum severity</label>')
    parts.append('<select id="severity-filter">')
    parts.append('<option value="-1">All severities</option>')
    for severity in reversed(list(Severity)):
        parts.append(f'<option value="{severity.rank}">{severity.value.title()} and above</option>')
    parts.append("</select>")
    parts.append('<label class="sr-only" for="search">Search alerts</label>')
    parts.append(
        '<input id="search" type="search" placeholder="Search rule, group, host, user, IP">'
    )
    parts.append('<span id="visible-count" class="muted"></span>')
    parts.append("</div></div>")

    if alerts:
        parts.append('<div class="table-wrap"><table class="alert-table">')
        parts.append(
            "<thead><tr><th>Severity</th><th>Rule</th><th>Group</th><th>ATT&amp;CK</th>"
            "<th>First seen</th><th>Count</th><th>Evidence</th></tr></thead>"
        )
        for index, alert in enumerate(alerts, start=1):
            parts.append(_render_alert_rows(ctx, alert, index))
        parts.append("</table></div>")
    else:
        parts.append(
            '<p class="empty">No alerts at or above the configured severity threshold.</p>'
        )
    parts.append("</section>")

    parts.append('<section id="timeline" aria-label="Incident timeline">')
    parts.append('<div class="section-head"><h2>Incident timeline</h2>')
    parts.append(f'<span class="muted">{len(ctx.timeline.entries)} entries</span></div>')
    if ctx.timeline.entries:
        parts.append('<div class="table-wrap"><table class="timeline-table">')
        parts.append(
            "<thead><tr><th>UTC</th><th>Severity</th><th>Host</th><th>User</th>"
            "<th>Source IP</th><th>Event</th><th>Rules</th></tr></thead><tbody>"
        )
        for entry in ctx.timeline.entries:
            rules = ", ".join(sorted({item[0] for item in entry.rules}))
            parts.append(
                "<tr>"
                f'<td class="nowrap">{escape_html(entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"))}</td>'
                f'<td><span class="badge {SEVERITY_CLASS[entry.severity]}">{escape_html(entry.severity.value)}</span></td>'
                f"<td>{escape_html(entry.host)}</td>"
                f"<td>{escape_html(entry.user)}</td>"
                f"<td>{escape_html(entry.src_ip)}</td>"
                f'<td class="event-cell">{escape_html(truncate(entry.message, 220))}</td>'
                f'<td class="nowrap">{escape_html(rules)}</td>'
                "</tr>"
            )
        parts.append("</tbody></table></div>")
        if ctx.timeline.truncated:
            parts.append(
                f'<p class="muted">Timeline truncated by {ctx.timeline.truncated} entries.</p>'
            )
    else:
        parts.append('<p class="empty">No matched events to display.</p>')
    parts.append("</section>")

    parts.append('<section id="attack" aria-label="ATT&amp;CK coverage">')
    parts.append('<div class="section-head"><h2>ATT&amp;CK coverage</h2>')
    parts.append(
        f'<span class="muted">{ctx.coverage_report.covered_count}/{ctx.coverage_report.catalog_count} '
        f"techniques covered by rules</span></div>"
    )
    parts.append('<div class="matrix">')
    for tactic, label in TACTICS:
        tactic_ids = ctx.coverage_report.tactic_ids(tactic)
        if not tactic_ids:
            continue
        covered = ctx.coverage_report.tactic_covered(tactic)
        percent = ctx.coverage_report.tactic_percent(tactic)
        parts.append('<article class="tactic">')
        parts.append(
            "<header><h3>"
            + escape_html(label)
            + f'</h3><span class="muted">{len(covered)}/{len(tactic_ids)}</span></header>'
        )
        parts.append(f'<div class="bar"><span style="width:{percent:.1f}%"></span></div>')
        parts.append('<div class="tech-grid">')
        for technique_id in tactic_ids:
            item = ctx.coverage_report.catalog[technique_id]
            alert_count = technique_counts.get(technique_id, 0)
            heat = _heat(alert_count)
            rule_count = len(ctx.coverage_report.rule_ids_by_technique.get(technique_id, []))
            title = (
                f"{item.id} {item.name} - {rule_count} rule(s), {alert_count} alert(s) in this scan"
            )
            parts.append(
                f'<div class="tech heat-{heat}" title="{escape_html(title)}">'
                f'<span class="tech-id">{escape_html(item.id)}</span>'
                f'<span class="tech-name">{escape_html(item.name)}</span>'
                f'<span class="tech-count">{alert_count} alert(s)</span>'
                "</div>"
            )
        parts.append("</div></article>")
    parts.append("</div>")
    parts.append(
        '<p class="muted small">Heat reflects alerts in this scan, not rule coverage. '
        "Violet tiles have no matching alerts; brighter tiles have more.</p>"
    )
    parts.append("</section>")

    parts.append("<footer>")
    parts.append(
        "<p>argus "
        + escape_html(ctx.version)
        + " - heuristic detection engineering for Linux logs. "
        "Validate and tune rules against your environment.</p>"
    )
    parts.append("</footer>")
    parts.append("</div>")
    parts.append(f"<script>{_JS}</script>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def _render_alert_rows(ctx: ScanContext, alert: Alert, index: int) -> str:
    attack = []
    for technique_id in alert.techniques:
        item = technique(technique_id)
        label = f"{item.id} {item.name}" if item else technique_id
        attack.append(f'<span class="chip">{escape_html(label)}</span>')
    search_blob = " ".join(
        [
            alert.rule_id,
            alert.title,
            alert.group_key,
            " ".join(sorted(alert.hosts)),
            " ".join(sorted(alert.users)),
            " ".join(sorted(alert.src_ips)),
        ]
    )
    evidence = "\n".join(
        f"{event.timestamp.isoformat()} {event.log_type} {event.source}:{event.line_no} "
        f"{event.host} {event.raw}"
        for event in alert.events
    )
    severity_class = SEVERITY_CLASS[alert.severity]
    rule_cell = (
        f'<span class="rule-id">{escape_html(alert.rule_id)}</span><br>'
        f'<span class="rule-title">{escape_html(alert.title)}</span>'
    )
    return (
        f'<tbody class="alert-group" data-rank="{alert.severity.rank}" '
        f'data-search="{escape_html(search_blob.lower())}">'
        "<tr>"
        f'<td><span class="badge {severity_class}">{escape_html(alert.severity.value)}</span></td>'
        f'<td class="rule-cell">{rule_cell}</td>'
        f'<td class="mono">{escape_html(alert.group_key)}</td>'
        f'<td class="attack-cell">{"".join(attack)}</td>'
        f'<td class="nowrap">{escape_html(alert.first_seen.strftime("%Y-%m-%d %H:%M:%S"))}</td>'
        f'<td class="num">{alert.count}</td>'
        f"<td><details><summary>Evidence ({len(alert.events)} of {alert.count})</summary>"
        f'<pre class="evidence">{escape_html(evidence)}</pre></details></td>'
        "</tr>"
        '<tr class="detail-row"><td colspan="7">'
        f"<strong>Description:</strong> {escape_html(alert.description)}<br>"
        f"<strong>Entities:</strong> hosts {escape_html(', '.join(sorted(alert.hosts)) or 'none')}; "
        f"users {escape_html(', '.join(sorted(alert.users)) or 'none')}; "
        f"source IPs {escape_html(', '.join(sorted(alert.src_ips)) or 'none')}<br>"
        f"<strong>False positives:</strong> {escape_html('; '.join(alert.falsepositives) or 'not documented')}"
        "</td></tr>"
        "</tbody>"
    )


def _heat(count: int) -> int:
    if count <= 0:
        return 0
    if count == 1:
        return 1
    if count <= 3:
        return 2
    if count <= 6:
        return 3
    return 4


def render_attack_matrix_html(rules: list[Rule]) -> str:
    """Render a standalone ATT&CK coverage page for the loaded rule set."""
    report = coverage(rules)
    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        "<title>argus ATT&amp;CK coverage</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        '<body><div class="page">',
        '<header class="hero"><div class="brand"><span class="eye" aria-hidden="true"></span>'
        "<span>argus</span></div><h1>ATT&amp;CK coverage</h1>",
        f'<p class="subtitle">{report.covered_count} of {report.catalog_count} catalogued '
        f"techniques covered by {len(rules)} rules ({report.percent:.1f}%).</p></header>",
        '<section aria-label="Coverage matrix"><div class="matrix">',
    ]
    for tactic, label in TACTICS:
        tactic_ids = report.tactic_ids(tactic)
        if not tactic_ids:
            continue
        covered = report.tactic_covered(tactic)
        parts.append('<article class="tactic">')
        parts.append(
            "<header><h3>"
            + escape_html(label)
            + f'</h3><span class="muted">{len(covered)}/{len(tactic_ids)}</span></header>'
        )
        parts.append(
            f'<div class="bar"><span style="width:{report.tactic_percent(tactic):.1f}%"></span></div>'
        )
        parts.append('<div class="tech-grid">')
        for technique_id in tactic_ids:
            item = report.catalog[technique_id]
            rule_count = len(report.rule_ids_by_technique.get(technique_id, []))
            parts.append(
                f'<div class="tech heat-{_heat(rule_count)}" title="'
                + escape_html(f"{item.id} {item.name} - {rule_count} rule(s)")
                + '"><span class="tech-id">'
                + escape_html(item.id)
                + '</span><span class="tech-name">'
                + escape_html(item.name)
                + '</span><span class="tech-count">'
                + escape_html(f"{rule_count} rule(s)")
                + "</span></div>"
            )
        parts.append("</div></article>")
    parts.append("</div></section>")
    parts.append(
        '<p class="muted small">Technique metadata follows MITRE ATT&amp;CK. '
        "Uncovered catalog techniques indicate gaps in the bundled rule pack.</p>"
    )
    parts.append("<footer><p>argus - detection engineering for Linux logs.</p></footer>")
    parts.append("</div></body></html>")
    return "\n".join(parts) + "\n"


_CSS = r"""
:root {
  --bg: #0b1020;
  --panel: #121a32;
  --panel-2: #18213e;
  --border: #263252;
  --text: #e6e9f2;
  --muted: #94a0bd;
  --violet: #a78bfa;
  --violet-2: #7c5cff;
  --critical: #ff5c7a;
  --high: #ff8a5c;
  --medium: #f5c451;
  --low: #5cc8ff;
  --info: #94a0bd;
  --ok: #6ee7b7;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--violet); }
.page { max-width: 1240px; margin: 0 auto; padding: 32px 24px 64px; }
.hero { padding: 28px 0 20px; border-bottom: 1px solid var(--border); }
.brand { display: flex; align-items: center; gap: 10px; color: var(--violet); font-weight: 700; letter-spacing: .08em; text-transform: uppercase; font-size: 13px; }
.eye { display: inline-block; width: 22px; height: 22px; border: 2px solid var(--violet); border-radius: 50% / 60%; position: relative; }
.eye::after { content: ""; position: absolute; inset: 6px; background: var(--violet); border-radius: 50%; }
.hero h1 { margin: 8px 0 4px; font-size: 34px; letter-spacing: -.02em; }
.subtitle { margin: 0; color: var(--muted); }
.cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
.metadata { margin: 22px 0 10px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
.meta-label { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
.meta-value { display: block; font-size: 20px; font-weight: 650; margin-top: 2px; }
.meta-line { display: flex; flex-wrap: wrap; gap: 8px 24px; color: var(--muted); font-size: 13px; margin: 8px 0 26px; }
.severity-cards { margin: 0 0 28px; }
.severity-card { text-align: left; cursor: pointer; color: var(--text); font: inherit; border-left-width: 4px; }
.severity-card:hover { background: var(--panel-2); }
.severity-card .sev-label { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
.severity-card .sev-value { display: block; font-size: 30px; font-weight: 700; line-height: 1.1; }
.severity-card.critical { border-left-color: var(--critical); }
.severity-card.high { border-left-color: var(--high); }
.severity-card.medium { border-left-color: var(--medium); }
.severity-card.low { border-left-color: var(--low); }
.severity-card.info { border-left-color: var(--info); }
.section-head { display: flex; align-items: end; justify-content: space-between; gap: 16px; margin: 34px 0 12px; flex-wrap: wrap; }
.section-head h2 { margin: 0; font-size: 22px; letter-spacing: -.01em; }
.controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
select, input[type="search"] {
  background: var(--panel); color: var(--text); border: 1px solid var(--border);
  border-radius: 8px; padding: 8px 10px; font: inherit; font-size: 13px;
}
input[type="search"] { min-width: 290px; }
.muted { color: var(--muted); }
.small { font-size: 12px; }
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; background: var(--panel); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .07em; background: #0f1630; position: sticky; top: 0; }
tbody:last-child tr:last-child td { border-bottom: 0; }
tr.detail-row td { background: #0e152c; color: var(--muted); font-size: 12px; }
.alert-group:hover td { background: rgba(167, 139, 250, .04); }
.badge { display: inline-block; border-radius: 999px; padding: 2px 9px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; white-space: nowrap; }
.badge.critical { background: rgba(255, 92, 122, .16); color: var(--critical); border: 1px solid rgba(255, 92, 122, .45); }
.badge.high { background: rgba(255, 138, 92, .14); color: var(--high); border: 1px solid rgba(255, 138, 92, .42); }
.badge.medium { background: rgba(245, 196, 81, .13); color: var(--medium); border: 1px solid rgba(245, 196, 81, .4); }
.badge.low { background: rgba(92, 200, 255, .12); color: var(--low); border: 1px solid rgba(92, 200, 255, .38); }
.badge.info { background: rgba(148, 160, 189, .12); color: var(--info); border: 1px solid rgba(148, 160, 189, .35); }
.rule-id { color: var(--violet); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.rule-title { font-weight: 600; }
.mono, .evidence { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
.mono { font-size: 12px; color: #c6d0e8; }
.nowrap { white-space: nowrap; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.attack-cell { min-width: 160px; }
.chip { display: inline-block; background: rgba(167, 139, 250, .1); border: 1px solid rgba(167, 139, 250, .25); color: #d8ccff; border-radius: 6px; padding: 1px 6px; margin: 1px 3px 1px 0; font-size: 11px; }
details summary { cursor: pointer; color: var(--violet); white-space: nowrap; }
pre.evidence { margin: 10px 0 2px; padding: 12px; background: #080d1b; border: 1px solid var(--border); border-radius: 8px; color: #cdd6ee; font-size: 12px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; max-height: 420px; overflow: auto; }
.empty { padding: 20px; background: var(--panel); border: 1px dashed var(--border); border-radius: 12px; color: var(--muted); }
.event-cell { min-width: 280px; }
.matrix { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); }
.tactic { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }
.tactic header { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; }
.tactic h3 { margin: 0; font-size: 15px; }
.bar { height: 3px; background: #1d2746; border-radius: 999px; margin: 8px 0 12px; overflow: hidden; }
.bar span { display: block; height: 100%; background: var(--violet); }
.tech-grid { display: grid; gap: 6px; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }
.tech { border: 1px solid var(--border); border-radius: 8px; padding: 7px 8px; display: flex; flex-direction: column; gap: 1px; background: #0e152c; }
.tech-id { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; color: var(--violet); }
.tech-name { font-size: 11px; color: var(--text); }
.tech-count { font-size: 10px; color: var(--muted); }
.tech.heat-1 { background: #241f45; border-color: #39306e; }
.tech.heat-2 { background: #362a6d; border-color: #5545a5; }
.tech.heat-3 { background: #4f3aa0; border-color: #8068e8; }
.tech.heat-4 { background: #7148c8; border-color: #a78bfa; }
.tech.heat-4 .tech-name, .tech.heat-4 .tech-count { color: #fff; }
.tech.heat-4 .tech-id { color: #efe8ff; }
footer { margin-top: 44px; border-top: 1px solid var(--border); padding-top: 16px; color: var(--muted); font-size: 12px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
.hidden { display: none !important; }
@media (max-width: 700px) {
  .page { padding: 20px 12px 40px; }
  .hero h1 { font-size: 27px; }
  input[type="search"] { min-width: 100%; }
}
@media print {
  body { background: #fff; color: #111; }
  .page { max-width: none; }
  .controls, .severity-cards { display: none; }
  .card, .table-wrap, .tactic, .tech { background: #fff; border-color: #ccc; }
  th { background: #eee; }
  pre.evidence { background: #f6f6f6; color: #111; }
}
"""


_JS = r"""
(function () {
  "use strict";
  var groups = Array.prototype.slice.call(document.querySelectorAll("tbody.alert-group"));
  var severity = document.getElementById("severity-filter");
  var search = document.getElementById("search");
  var count = document.getElementById("visible-count");
  if (!groups.length || !severity || !search || !count) { return; }
  function apply() {
    var minRank = parseInt(severity.value, 10);
    var needle = search.value.trim().toLowerCase();
    var shown = 0;
    groups.forEach(function (group) {
      var rank = parseInt(group.getAttribute("data-rank"), 10);
      var haystack = group.getAttribute("data-search") || "";
      var ok = (minRank < 0 || rank >= minRank) && (!needle || haystack.indexOf(needle) !== -1);
      group.classList.toggle("hidden", !ok);
      if (ok) { shown += 1; }
    });
    count.textContent = shown + " of " + groups.length + " alerts shown";
  }
  severity.addEventListener("change", apply);
  search.addEventListener("input", apply);
  Array.prototype.forEach.call(document.querySelectorAll(".severity-card"), function (card) {
    card.addEventListener("click", function () {
      severity.value = card.getAttribute("data-min-rank");
      apply();
      document.getElementById("alerts").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
  apply();
})();
"""
