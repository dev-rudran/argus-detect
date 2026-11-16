"""JSON Lines report: one self-contained alert object per line."""

from __future__ import annotations

import json
from collections.abc import Iterable

from argus.attack import technique
from argus.models import Alert
from argus.report.common import ScanContext


def alert_record(ctx: ScanContext, alert: Alert) -> dict[str, object]:
    """Build the JSON-serializable alert record used by JSONL output."""
    record = alert.to_dict()
    record["attack_techniques"] = [
        {
            "id": item.id,
            "name": item.name,
            "tactics": list(item.tactics),
            "url": item.url,
        }
        for item in (technique(identifier) for identifier in alert.techniques)
        if item is not None
    ]
    record["ruleset"] = ctx.rules_path
    return record


def render_jsonl(ctx: ScanContext, alerts: Iterable[Alert] | None = None) -> str:
    """Render alerts as JSON Lines with no embedded newlines."""
    selected = list(ctx.visible_alerts if alerts is None else alerts)
    return "".join(
        json.dumps(alert_record(ctx, alert), ensure_ascii=False, separators=(",", ":")) + "\n"
        for alert in selected
    )
