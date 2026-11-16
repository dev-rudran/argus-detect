"""Detection rule discovery, schema validation and linting."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any

import yaml

from argus.attack import TACTIC_NAMES, technique
from argus.match import FieldMatcher, MatchError
from argus.models import Rule, Selection, Sequence, Severity, Threshold
from argus.rules.condition import ConditionError, ThresholdSpec, parse_condition
from argus.util.timeparse import TimeParseError, parse_duration

RULE_ID_RE = re.compile(r"^ARGUS-\d{4}$")
TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")
TACTIC_TAG_RE = re.compile(r"^attack\.[a-z][a-z0-9_]*$")
VALID_OPS = {"gte", "gt", "eq", "lt", "lte"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


class RuleError(ValueError):
    """Raised when a rule file is structurally invalid."""


@dataclass
class LintIssue:
    level: str
    rule_id: str
    message: str
    path: str = ""

    def __str__(self) -> str:
        location = f" [{self.path}]" if self.path else ""
        return f"{self.level.upper():7} {self.rule_id}{location}: {self.message}"


@dataclass
class LoadedRules:
    rules: list[Rule] = dc_field(default_factory=list)
    errors: list[str] = dc_field(default_factory=list)
    files: list[str] = dc_field(default_factory=list)


def bundled_rules_dir() -> Path:
    """Return the path to the rule pack shipped with the package."""
    return Path(__file__).resolve().parent


def discover_rule_files(path: Path | str | None = None) -> list[Path]:
    """Find YAML rule files under *path* (or the bundled pack)."""
    base = Path(path) if path is not None else bundled_rules_dir()
    if not base.exists():
        raise RuleError(f"rules path does not exist: {base}")
    if base.is_file():
        return [base]
    files = sorted(set(base.rglob("*.yml")) | set(base.rglob("*.yaml")))
    if not files:
        raise RuleError(f"no .yml or .yaml rule files found under {base}")
    return files


def load_rules(path: Path | str | None = None) -> list[Rule]:
    """Load every rule under *path*, raising RuleError on the first failure."""
    rules: list[Rule] = []
    for file_path in discover_rule_files(path):
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleError(f"cannot read {file_path}: {exc}") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise RuleError(f"invalid YAML in {file_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise RuleError(f"{file_path}: rule file must contain a YAML mapping")
        rules.append(compile_rule(data, path=str(file_path)))
    return rules


def load_rules_lenient(path: Path | str | None = None) -> LoadedRules:
    """Load rules while collecting per-file errors (used by ``rules lint``)."""
    result = LoadedRules()
    try:
        files = discover_rule_files(path)
    except RuleError as exc:
        result.errors.append(str(exc))
        return result
    for file_path in files:
        result.files.append(str(file_path))
        try:
            data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise RuleError("rule file must contain a YAML mapping")
            result.rules.append(compile_rule(data, path=str(file_path)))
        except (
            OSError,
            yaml.YAMLError,
            RuleError,
            MatchError,
            ConditionError,
            TimeParseError,
        ) as exc:
            result.errors.append(f"{file_path}: {exc}")
    return result


def compile_rule(data: dict[str, Any], *, path: str = "") -> Rule:
    """Validate one rule mapping and compile its matchers and condition."""
    _require_keys(data, ["id", "title", "description", "severity", "logsource", "detection"])
    rule_id = _string(data["id"], "id")
    if not RULE_ID_RE.match(rule_id):
        raise RuleError(f"rule id {rule_id!r} must match ARGUS-####")
    title = _string(data["title"], "title")
    description = _string(data["description"], "description")
    if len(description) < 20:
        raise RuleError(f"{rule_id}: description must be at least 20 characters")
    try:
        severity = Severity.parse(data["severity"])
    except ValueError as exc:
        raise RuleError(f"{rule_id}: {exc}") from exc

    logsource = data["logsource"]
    if not isinstance(logsource, dict) or not logsource:
        raise RuleError(f"{rule_id}: logsource must be a non-empty mapping")
    clean_logsource: dict[str, str] = {}
    for key, value in logsource.items():
        if key not in {"product", "service", "category"}:
            raise RuleError(f"{rule_id}: unsupported logsource key {key!r}")
        clean_logsource[str(key)] = _string(value, f"logsource.{key}")

    detection = data["detection"]
    if not isinstance(detection, dict) or not detection:
        raise RuleError(f"{rule_id}: detection must be a non-empty mapping")
    if "condition" not in detection:
        raise RuleError(f"{rule_id}: detection requires a condition")
    condition_text = _string(detection["condition"], "detection.condition")
    selection_data = {key: value for key, value in detection.items() if key != "condition"}
    if not selection_data:
        raise RuleError(f"{rule_id}: detection requires at least one selection")
    selections: dict[str, Selection] = {}
    for name, fields in selection_data.items():
        if not isinstance(fields, dict) or not fields:
            raise RuleError(f"{rule_id}: selection {name!r} must be a non-empty mapping")
        compiled_fields: dict[str, list[FieldMatcher]] = {}
        for expression, value in fields.items():
            if not isinstance(expression, str) or not expression.strip():
                raise RuleError(f"{rule_id}: selection {name!r} has an invalid field name")
            try:
                matcher = FieldMatcher.build(expression, value)
            except MatchError as exc:
                raise RuleError(f"{rule_id}: selection {name!r}: {exc}") from exc
            compiled_fields.setdefault(matcher.field, []).append(matcher)
        selections[str(name)] = Selection(name=str(name), fields=compiled_fields)

    try:
        parsed = parse_condition(condition_text)
    except ConditionError as exc:
        raise RuleError(f"{rule_id}: {exc}") from exc
    try:
        referenced = parsed.resolve(selections.keys())
    except ConditionError as exc:
        raise RuleError(f"{rule_id}: {exc}") from exc
    unknown = referenced - set(selections)
    if unknown:
        raise RuleError(
            f"{rule_id}: condition references unknown selections: {', '.join(sorted(unknown))}"
        )

    tags = _string_list(data.get("tags", []), "tags")
    falsepositives = _string_list(data.get("falsepositives", []), "falsepositives")
    timeframe = None
    if data.get("timeframe") not in (None, ""):
        timeframe = parse_duration(data["timeframe"])
    group_by = _group_fields(data.get("group_by", []), "group_by")

    threshold = _compile_threshold(data.get("threshold"), rule_id, parsed.threshold)
    if parsed.threshold is not None:
        threshold = Threshold(count=parsed.threshold.count, op=parsed.threshold.op)
    sequence = _compile_sequence(data.get("sequence"), rule_id, selections, group_by)

    if (threshold is not None or sequence is not None) and timeframe is None:
        if sequence is not None:
            timeframe = sequence.within
        else:
            raise RuleError(f"{rule_id}: threshold correlation requires a timeframe")
    if threshold is not None and not group_by:
        group_by = ()
    if sequence is not None and not sequence.group_by:
        raise RuleError(f"{rule_id}: sequence correlation requires group_by")
    if threshold is not None and parsed.threshold is not None and data.get("threshold") is not None:
        raise RuleError(
            f"{rule_id}: define the threshold either in the condition or in the threshold block, not both"
        )
    if threshold is not None and not group_by:
        # A global threshold is valid but uncommon; allow it for aggregate rules.
        group_by = ()

    level = str(data.get("level", "") or "")
    raw = dict(data)
    return Rule(
        id=rule_id,
        title=title,
        description=description,
        severity=severity,
        logsource=clean_logsource,
        selections=selections,
        condition=condition_text,
        condition_ast=parsed.ast,
        tags=tags,
        falsepositives=falsepositives,
        path=path,
        level=level,
        timeframe=timeframe,
        group_by=group_by,
        threshold=threshold,
        sequence=sequence,
        raw=raw,
    )


def _require_keys(data: dict[str, Any], keys: Iterable[str]) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        raise RuleError(f"missing required key(s): {', '.join(missing)}")


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleError(f"{name} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuleError(f"{name} must be a list of strings")
    return [item.strip() for item in value if item.strip()]


def _group_fields(value: Any, name: str) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise RuleError(f"{name} must be a list of field names")
    return tuple(item.strip() for item in value)


def _compile_threshold(
    value: Any, rule_id: str, condition_threshold: ThresholdSpec | None
) -> Threshold | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuleError(
            f"{rule_id}: threshold must be a mapping with count and optional op/distinct"
        )
    if "count" not in value:
        raise RuleError(f"{rule_id}: threshold requires a count")
    count = value["count"]
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise RuleError(f"{rule_id}: threshold.count must be a positive integer")
    op = str(value.get("op", "gte")).lower()
    if op not in VALID_OPS:
        raise RuleError(f"{rule_id}: threshold.op must be one of {', '.join(sorted(VALID_OPS))}")
    distinct = _group_fields(value.get("distinct", []), "threshold.distinct")
    return Threshold(count=count, op=op, distinct=distinct)


def _compile_sequence(
    value: Any,
    rule_id: str,
    selections: dict[str, Selection],
    rule_group_by: tuple[str, ...],
) -> Sequence | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuleError(f"{rule_id}: sequence must be a mapping")
    for key in ("first", "then", "min_first", "within"):
        if key not in value:
            raise RuleError(f"{rule_id}: sequence requires {key}")
    first = str(value["first"])
    then = str(value["then"])
    if first not in selections:
        raise RuleError(f"{rule_id}: sequence.first references unknown selection {first!r}")
    if then not in selections:
        raise RuleError(f"{rule_id}: sequence.then references unknown selection {then!r}")
    if first == then:
        raise RuleError(f"{rule_id}: sequence.first and sequence.then must differ")
    min_first = value["min_first"]
    if isinstance(min_first, bool) or not isinstance(min_first, int) or min_first <= 0:
        raise RuleError(f"{rule_id}: sequence.min_first must be a positive integer")
    within = parse_duration(value["within"])
    group_by = _group_fields(value.get("group_by", list(rule_group_by)), "sequence.group_by")
    return Sequence(first=first, then=then, min_first=min_first, within=within, group_by=group_by)


def lint_rules(rules: list[Rule]) -> list[LintIssue]:
    """Perform semantic checks that go beyond schema validation."""
    issues: list[LintIssue] = []
    seen: dict[str, Rule] = {}
    for rule in rules:
        if rule.id in seen:
            issues.append(
                LintIssue(
                    "error", rule.id, f"duplicate rule id (also in {seen[rule.id].path})", rule.path
                )
            )
        else:
            seen[rule.id] = rule

        if not rule.description.strip():
            issues.append(LintIssue("error", rule.id, "description is required", rule.path))
        if not rule.falsepositives:
            issues.append(
                LintIssue(
                    "error", rule.id, "falsepositives must document at least one case", rule.path
                )
            )
        if not rule.tags:
            issues.append(LintIssue("warning", rule.id, "no tags; add ATT&CK tags", rule.path))

        attack_tags = rule.attack_tags
        if not attack_tags:
            issues.append(LintIssue("warning", rule.id, "no ATT&CK tags", rule.path))
        for tag in rule.tags:
            lower = tag.lower()
            if not lower.startswith("attack."):
                continue
            if TECHNIQUE_TAG_RE.match(lower):
                if technique(lower.split(".", 1)[1]) is None:
                    issues.append(
                        LintIssue(
                            "warning", rule.id, f"unknown ATT&CK technique {tag!r}", rule.path
                        )
                    )
            elif TACTIC_TAG_RE.match(lower):
                tactic_name = lower.split(".", 1)[1].replace("_", "-")
                if tactic_name not in TACTIC_NAMES:
                    issues.append(
                        LintIssue("error", rule.id, f"unknown ATT&CK tactic {tag!r}", rule.path)
                    )
            else:
                issues.append(
                    LintIssue(
                        "error",
                        rule.id,
                        f"malformed ATT&CK tag {tag!r}; expected attack.t####[.###] or attack.<tactic>",
                        rule.path,
                    )
                )

        for name, selection in rule.selections.items():
            if not selection.fields:
                issues.append(
                    LintIssue("error", rule.id, f"selection {name!r} is empty", rule.path)
                )
            for matchers in selection.fields.values():
                for matcher in matchers:
                    if matcher.modifier == "re":
                        for pattern in matcher.values:
                            if pattern.regex is None:
                                issues.append(
                                    LintIssue(
                                        "error",
                                        rule.id,
                                        f"regex failed to compile: {pattern.value!r}",
                                        rule.path,
                                    )
                                )
            if not _selection_used(rule, name):
                issues.append(
                    LintIssue(
                        "warning", rule.id, f"selection {name!r} is not referenced", rule.path
                    )
                )

        if rule.threshold is not None:
            if rule.timeframe is None:
                issues.append(
                    LintIssue("error", rule.id, "threshold rule has no timeframe", rule.path)
                )
            if rule.threshold.op not in VALID_OPS:
                issues.append(
                    LintIssue(
                        "error", rule.id, f"invalid threshold op {rule.threshold.op!r}", rule.path
                    )
                )
            if not rule.group_by:
                issues.append(
                    LintIssue(
                        "warning",
                        rule.id,
                        "threshold has no group_by; all events share one correlation group",
                        rule.path,
                    )
                )
        if rule.sequence is not None:
            if rule.sequence.within.total_seconds() <= 0:
                issues.append(
                    LintIssue("error", rule.id, "sequence.within must be positive", rule.path)
                )
            if not rule.sequence.group_by:
                issues.append(LintIssue("error", rule.id, "sequence requires group_by", rule.path))
        if rule.timeframe is not None and rule.timeframe.total_seconds() <= 0:
            issues.append(LintIssue("error", rule.id, "timeframe must be positive", rule.path))
        for field in rule.group_by:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", field):
                issues.append(
                    LintIssue("error", rule.id, f"invalid group_by field {field!r}", rule.path)
                )
        if len(rule.title) > 120:
            issues.append(
                LintIssue("warning", rule.id, "title is longer than 120 characters", rule.path)
            )
    return issues


def _selection_used(rule: Rule, name: str) -> bool:
    if rule.sequence is not None and name in {rule.sequence.first, rule.sequence.then}:
        return True
    try:
        return name in rule.condition_ast.selections(rule.selections.keys())
    except ConditionError:
        return True
