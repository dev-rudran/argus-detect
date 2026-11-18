"""SARIF 2.1.0 report for GitHub code scanning and other SARIF viewers."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from argus.models import Alert, Event, Rule, Severity
from argus.report.common import ScanContext
from argus.util.text import truncate

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/dev-rudran/argus-detect"
TOOL_NAME = "argus"
MAX_LOCATIONS = 10
EVIDENCE_WIDTH = 190

LEVEL_BY_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}

SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFORMATIONAL: "0.0",
}


def sarif_level(severity: Severity) -> str:
    """Map an argus severity to a SARIF result level."""
    return LEVEL_BY_SEVERITY[severity]


def fingerprint(rule_id: str, group_key: str) -> str:
    """Return a stable alert fingerprint derived from the rule and group only."""
    digest = hashlib.sha256(f"{rule_id}\x00{group_key}".encode()).hexdigest()
    return digest[:32]


def render_sarif(ctx: ScanContext) -> str:
    """Render the visible alerts as a SARIF 2.1.0 document."""
    rules = _dedupe_rules(ctx.result.rules)
    rule_index = {rule.id: index for index, rule in enumerate(rules)}
    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": ctx.version,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule_descriptor(rule) for rule in rules],
                    }
                },
                "results": [
                    _result(ctx, alert, rule_index.get(alert.rule_id))
                    for alert in ctx.visible_alerts
                ],
                "properties": {
                    "generated_at": ctx.finished.isoformat(),
                    "ruleset": ctx.rules_path,
                    "events": ctx.parser_stats.events,
                    "alerts": len(ctx.visible_alerts),
                    "suppressed": ctx.result.stats.suppressed,
                },
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def _dedupe_rules(rules: list[Rule]) -> list[Rule]:
    unique: dict[str, Rule] = {}
    for rule in rules:
        unique.setdefault(rule.id, rule)
    return [unique[rule_id] for rule_id in sorted(unique)]


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "defaultConfiguration": {"level": sarif_level(rule.severity)},
        "properties": {
            "tags": list(rule.tags),
            "security-severity": SECURITY_SEVERITY[rule.severity],
        },
    }


def _result(ctx: ScanContext, alert: Alert, rule_index: int | None) -> dict[str, Any]:
    level = sarif_level(alert.severity)
    result: dict[str, Any] = {
        "ruleId": alert.rule_id,
        "level": level,
        "message": {
            "text": (
                f"{alert.title}. Group: {alert.group_key}. "
                f"{alert.count} event(s) from {alert.first_seen.isoformat()} "
                f"to {alert.last_seen.isoformat()}."
            )
        },
        "partialFingerprints": {
            "argusRuleGroup/v1": fingerprint(alert.rule_id, alert.group_key),
        },
        "properties": {
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
            "count": alert.count,
            "attack": list(alert.techniques),
            "logsource": alert.logsource,
            "tags": list(alert.tags),
            "hosts": sorted(alert.hosts),
            "users": sorted(alert.users),
            "src_ips": sorted(alert.src_ips),
        },
    }
    if rule_index is not None:
        result["ruleIndex"] = rule_index
    locations = [_location(event) for event in alert.events if _file_backed(event)]
    if locations:
        result["locations"] = locations[:MAX_LOCATIONS]
    return result


def _file_backed(event: Event) -> bool:
    return bool(event.source) and event.line_no > 0


def _location(event: Event) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": event.source.replace("\\", "/")},
            "region": {
                "startLine": event.line_no,
                "snippet": {"text": truncate(event.message, EVIDENCE_WIDTH)},
            },
        }
    }
