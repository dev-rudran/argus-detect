"""Command line interface for argus."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

import yaml

from argus import __version__
from argus.attack import TACTICS, coverage, tactic_label, techniques_for_rule
from argus.engine import Engine, ScanResult, SuppressionError, SuppressionSet
from argus.ingest import IngestError, ParserStats, iter_events
from argus.ingest.stream import VALID_TYPES
from argus.models import Rule, Severity
from argus.report import render_console, render_html, render_jsonl, render_markdown, render_sarif
from argus.report.common import ScanContext
from argus.report.html import render_attack_matrix_html
from argus.rules.loader import (
    RuleError,
    bundled_rules_dir,
    lint_rules,
    load_rules,
    load_rules_lenient,
)
from argus.util.text import truncate
from argus.util.timeparse import UTC, TimeParseError, parse_since_until

PROGRAM = "argus"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Streaming detection engineering engine for Linux auth, syslog, JSON and auditd logs.",
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan log files or directories")
    scan.add_argument("paths", nargs="+", help="log files or directories (recursive)")
    scan.add_argument(
        "--rules", metavar="DIR", help="rule directory (defaults to the bundled pack)"
    )
    scan.add_argument(
        "--format",
        choices=("console", "jsonl", "md", "html", "sarif"),
        default="console",
        help="report format (default: console)",
    )
    scan.add_argument(
        "-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout"
    )
    scan.add_argument(
        "--min-severity",
        default="informational",
        help="only report alerts at or above this severity (default: informational)",
    )
    scan.add_argument("--since", help="only include events at or after this UTC date/time")
    scan.add_argument("--until", help="only include events at or before this UTC date/time")
    scan.add_argument(
        "--fail-on",
        help="exit 1 when an alert at or above this severity is detected (informational..critical)",
    )
    scan.add_argument(
        "--stats", action="store_true", help="print ingest and performance statistics"
    )
    scan.add_argument(
        "--suppress",
        action="append",
        default=[],
        metavar="RULE:GROUP:DURATION",
        help="suppress matching alerts for a duration (repeatable; * wildcards allowed)",
    )
    scan.add_argument("--suppress-file", metavar="FILE", help="YAML suppression configuration")
    scan.add_argument("--year", type=int, help="starting year for yearless syslog timestamps")
    scan.add_argument(
        "--no-color", action="store_true", help="disable ANSI color in console output"
    )
    scan.add_argument(
        "--type",
        choices=sorted(VALID_TYPES),
        default="auto",
        help="force a log parser instead of auto-detecting (default: auto)",
    )
    scan.add_argument(
        "--sample-events",
        type=int,
        default=12,
        metavar="N",
        help="maximum evidence events retained per alert (default: 12)",
    )

    rules = subparsers.add_parser("rules", help="inspect and validate detection rules")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    for name, help_text in (
        ("list", "list loaded rules"),
        ("show", "show one rule"),
        ("lint", "run schema and semantic lint checks"),
        ("validate", "validate the rule pack (errors only)"),
    ):
        command = rules_sub.add_parser(name, help=help_text)
        command.add_argument("--rules", metavar="DIR", help="rule directory")
        if name == "show":
            command.add_argument("id", help="rule id, for example ARGUS-0001")

    explain = subparsers.add_parser("explain", help="explain a rule and its correlation semantics")
    explain.add_argument("id", help="rule id, for example ARGUS-0001")
    explain.add_argument("--rules", metavar="DIR", help="rule directory")

    matrix = subparsers.add_parser("attack-matrix", help="show ATT&CK coverage for the rule pack")
    matrix.add_argument("--rules", metavar="DIR", help="rule directory")
    matrix.add_argument("--format", choices=("text", "html"), default="text")
    matrix.add_argument("-o", "--output", metavar="FILE", help="write output to FILE")

    subparsers.add_parser("version", help="print the version")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "rules":
            return _rules(args)
        if args.command == "explain":
            return _explain(args)
        if args.command == "attack-matrix":
            return _attack_matrix(args)
        if args.command == "version":
            print(f"{PROGRAM} {__version__}")
            return 0
    except (RuleError, IngestError, SuppressionError, TimeParseError, OSError, ValueError) as exc:
        if os.environ.get("ARGUS_DEBUG"):
            raise
        print(f"{PROGRAM}: error: {exc}", file=sys.stderr)
        return 2
    parser.print_help(sys.stderr)
    return 2


def _scan(args: argparse.Namespace) -> int:
    try:
        min_severity = Severity.parse(args.min_severity)
    except ValueError as exc:
        raise RuleError(str(exc)) from exc
    fail_severity: Severity | None = None
    if args.fail_on:
        try:
            fail_severity = Severity.parse(args.fail_on)
        except ValueError as exc:
            raise RuleError(str(exc)) from exc
    since = parse_since_until(args.since) if args.since else None
    until = parse_since_until(args.until, end=True) if args.until else None
    if since and until and since > until:
        raise ValueError("--since must be earlier than --until")
    if args.sample_events <= 0:
        raise ValueError("--sample-events must be greater than zero")
    if args.year is not None and not 1970 <= args.year <= 2100:
        raise ValueError("--year must be between 1970 and 2100")

    rules = _load_rules_or_fail(args.rules)
    suppression = SuppressionSet()
    if args.suppress_file:
        suppression = SuppressionSet.from_file(args.suppress_file)
    specs: list[str] = []
    for value in args.suppress:
        specs.extend(part for part in str(value).split(",") if part.strip())
    if specs:
        extra = SuppressionSet.from_specs(specs)
        suppression.entries.extend(extra.entries)

    started = datetime.now(tz=UTC)
    parser_stats = ParserStats()
    engine = Engine(
        rules,
        suppression=suppression,
        sample_events=args.sample_events,
    )
    events = iter_events(
        args.paths,
        forced_type=args.type,
        year=args.year,
        since=since,
        until=until,
        stats=parser_stats,
    )
    for event in events:
        engine.process(event)
    finished = datetime.now(tz=started.tzinfo)
    result = ScanResult(
        alerts=engine.alerts,
        stats=engine.stats,
        rules=rules,
        suppressed=engine.stats.suppressed,
    )
    context = ScanContext(
        result=result,
        parser_stats=parser_stats,
        rules_path=args.rules or str(bundled_rules_dir()),
        started=started,
        finished=finished,
        min_severity=min_severity,
        version=__version__,
        inputs=list(args.paths),
        year=args.year,
        forced_type=args.type,
    )

    write_to_stdout = not args.output or args.output == "-"
    color = bool(
        args.format == "console"
        and write_to_stdout
        and not args.no_color
        and not os.environ.get("NO_COLOR")
        and sys.stdout.isatty()
    )
    if args.format == "console":
        rendered = render_console(context, color=color, stats=args.stats)
    elif args.format == "jsonl":
        rendered = render_jsonl(context)
    elif args.format == "md":
        rendered = render_markdown(context)
    elif args.format == "sarif":
        rendered = render_sarif(context)
    else:
        rendered = render_html(context)

    _write_output(rendered, args.output)
    if args.stats and ((args.output and args.output != "-") or args.format != "console"):
        print(
            f"{PROGRAM}: {parser_stats.events:,} events from {parser_stats.files} files, "
            f"{parser_stats.malformed} malformed, {len(result.alerts)} alerts, "
            f"{result.stats.suppressed} suppressed, {context.elapsed_seconds:.3f}s",
            file=sys.stderr,
        )
    if fail_severity is not None and any(
        alert.severity >= fail_severity for alert in result.alerts
    ):
        return 1
    return 0


def _load_rules_or_fail(path: str | None) -> list[Rule]:
    rules = load_rules(path)
    issues = [issue for issue in lint_rules(rules) if issue.level == "error"]
    if issues:
        details = "\n".join(str(issue) for issue in issues)
        raise RuleError(f"rule lint failed:\n{details}")
    return rules


def _rules(args: argparse.Namespace) -> int:
    if args.rules_command == "list":
        rules = _load_rules_or_fail(args.rules)
        print(f"{'ID':12} {'SEVERITY':13} {'LOGSOURCE':20} TITLE")
        for rule in sorted(rules, key=lambda item: item.id):
            print(
                f"{rule.id:12} {rule.severity.value:13} {rule.logsource_label:20} "
                f"{truncate(rule.title, 72)}"
            )
        print(f"\n{len(rules)} rules from {args.rules or bundled_rules_dir()}")
        return 0
    if args.rules_command == "show":
        rules = _load_rules_or_fail(args.rules)
        rule = _find_rule(rules, args.id)
        print(f"# {rule.id} {rule.title}")
        print(f"# source: {rule.path}")
        print(yaml.safe_dump(rule.raw, sort_keys=False, allow_unicode=False).rstrip())
        print("# compiled condition:", rule.condition_ast.describe())
        if rule.threshold:
            print("# correlation:", rule.threshold.display)
        if rule.sequence:
            print("# sequence:", rule.sequence.display)
        return 0
    if args.rules_command == "lint":
        loaded = load_rules_lenient(args.rules)
        issues = lint_rules(loaded.rules)
        for error in loaded.errors:
            print(f"ERROR   {error}")
        for issue in issues:
            print(str(issue))
        errors = len(loaded.errors) + sum(1 for issue in issues if issue.level == "error")
        warnings = sum(1 for issue in issues if issue.level == "warning")
        print(f"\n{len(loaded.rules)} rules checked, {errors} error(s), {warnings} warning(s)")
        return 1 if errors else 0
    if args.rules_command == "validate":
        loaded = load_rules_lenient(args.rules)
        issues = lint_rules(loaded.rules)
        errors = list(loaded.errors) + [str(issue) for issue in issues if issue.level == "error"]
        for error in errors:
            print(f"ERROR   {error}")
        if errors:
            print(f"\n{len(loaded.rules)} rules checked, {len(errors)} error(s)")
            return 1
        print(f"{len(loaded.rules)} rules valid")
        return 0
    return 2


def _find_rule(rules: list[Rule], identifier: str) -> Rule:
    wanted = identifier.strip().upper()
    for rule in rules:
        if rule.id.upper() == wanted:
            return rule
    raise RuleError(f"rule not found: {identifier}")


def _explain(args: argparse.Namespace) -> int:
    rules = _load_rules_or_fail(args.rules)
    rule = _find_rule(rules, args.id)
    print(f"{rule.id}  {rule.title}")
    print(f"Severity:    {rule.severity.value}")
    print(f"Logsource:   {rule.logsource_label}")
    print(f"Source:      {rule.path}")
    print(f"Description: {rule.description}")
    print()
    print("Detection")
    for name, selection in rule.selections.items():
        print(f"  {name}: {selection.describe()}")
    print(f"  condition: {rule.condition}")
    print(f"  compiled:  {rule.condition_ast.describe()}")
    if rule.threshold:
        timeframe = int(rule.timeframe.total_seconds()) if rule.timeframe else 0
        print(
            f"  correlation: {rule.threshold.display} within {timeframe}s"
            + (f", group_by {', '.join(rule.group_by)}" if rule.group_by else "")
        )
    if rule.sequence:
        print(f"  sequence: {rule.sequence.display}, group_by {', '.join(rule.sequence.group_by)}")
    print()
    print("ATT&CK")
    techniques = techniques_for_rule(rule)
    if not techniques:
        print("  (none)")
    for item in techniques:
        tactics = ", ".join(tactic_label(tactic) for tactic in item.tactics)
        print(f"  {item.id}  {item.name}  [{tactics}]  {item.url}")
    print()
    print("False positives")
    for item in rule.falsepositives:
        print(f"  - {item}")
    if rule.level:
        print()
        print(f"Tuning note: {rule.level}")
    return 0


def _attack_matrix(args: argparse.Namespace) -> int:
    rules = _load_rules_or_fail(args.rules)
    report = coverage(rules)
    if args.format == "html":
        rendered = render_attack_matrix_html(rules)
    else:
        lines = [
            f"argus {__version__} ATT&CK coverage",
            f"{len(rules)} rules cover {report.covered_count}/{report.catalog_count} "
            f"catalogued techniques ({report.percent:.1f}%)",
            "",
        ]
        for tactic, label in TACTICS:
            tactic_ids = report.tactic_ids(tactic)
            if not tactic_ids:
                continue
            covered = report.tactic_covered(tactic)
            lines.append(f"{label} ({len(covered)}/{len(tactic_ids)})")
            for identifier in tactic_ids:
                item = report.catalog[identifier]
                rule_ids = report.rule_ids_by_technique.get(identifier, [])
                status = ", ".join(rule_ids) if rule_ids else "-"
                lines.append(f"  {identifier:10} {truncate(item.name, 46):48} {status}")
            lines.append("")
        rendered = "\n".join(lines).rstrip() + "\n"
    _write_output(rendered, args.output)
    return 0


def _write_output(rendered: str, output: str | None) -> None:
    if not output or output == "-":
        sys.stdout.write(rendered)
        return
    path = Path(output).expanduser()
    if path.parent and str(path.parent) not in {"", "."}:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
