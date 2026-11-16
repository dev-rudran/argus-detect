"""Rule discovery, compilation and lint tests."""

from __future__ import annotations

from copy import deepcopy

import pytest
from conftest import RULES_DIR, make_event

from argus.attack import coverage
from argus.rules.loader import (
    RuleError,
    compile_rule,
    discover_rule_files,
    lint_rules,
    load_rules,
    load_rules_lenient,
)


def test_bundled_pack_loads_and_lints_clean():
    rules = load_rules(RULES_DIR)
    assert len(rules) == 36
    assert [rule.id for rule in rules] == [f"ARGUS-{index:04d}" for index in range(1, 37)]
    assert lint_rules(rules) == []


def test_bundled_pack_covers_the_attack_catalog():
    report = coverage(load_rules(RULES_DIR))
    assert report.covered_count == report.catalog_count == 48
    assert report.percent == 100.0


def test_discover_rule_files_supports_single_files_and_directories(tmp_path):
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text("id: ARGUS-9001\n", encoding="utf-8")
    assert discover_rule_files(rule_file) == [rule_file]
    assert discover_rule_files(tmp_path) == [rule_file]


def test_discover_rule_files_reports_missing_and_empty_paths(tmp_path):
    with pytest.raises(RuleError):
        discover_rule_files(tmp_path / "missing")
    with pytest.raises(RuleError):
        discover_rule_files(tmp_path)


def test_compile_valid_rule(base_rule):
    rule = compile_rule(deepcopy(base_rule), path="memory.yml")
    assert rule.id == "ARGUS-9001"
    assert rule.condition_ast.describe() == "selection"
    assert rule.selections["selection"].describe() == "action=ssh_auth_failed"
    assert rule.technique_tags == ["T1110"]
    assert rule.path == "memory.yml"
    assert rule.raw["title"] == "Test rule"


def test_compile_threshold_rule(base_rule):
    data = deepcopy(base_rule)
    data["timeframe"] = "5m"
    data["group_by"] = ["src_ip"]
    data["threshold"] = {"count": 6, "op": "gte", "distinct": ["user"]}
    rule = compile_rule(data)
    assert rule.correlated is True
    assert rule.threshold is not None
    assert rule.threshold.count == 6
    assert rule.threshold.distinct == ("user",)
    assert rule.timeframe is not None
    assert int(rule.timeframe.total_seconds()) == 300


def test_compile_sequence_rule(base_rule):
    data = deepcopy(base_rule)
    data["detection"] = {
        "failures": {"action": "ssh_auth_failed"},
        "success": {"action": "ssh_auth_success"},
        "condition": "failures or success",
    }
    data["sequence"] = {
        "first": "failures",
        "then": "success",
        "min_first": 3,
        "within": "10m",
        "group_by": ["src_ip"],
    }
    rule = compile_rule(data)
    assert rule.correlated is True
    assert rule.sequence is not None
    assert rule.sequence.first == "failures"
    assert rule.sequence.min_first == 3
    assert rule.timeframe is not None
    assert int(rule.timeframe.total_seconds()) == 600
    assert rule.group_key(make_event({"src_ip": "1.2.3.4"})) == "src_ip=1.2.3.4"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.pop("title"), "missing required key"),
        (lambda data: data.update(id="BAD-1"), "must match ARGUS"),
        (lambda data: data.update(description="too short"), "at least 20"),
        (lambda data: data.update(severity="urgent"), "invalid severity"),
        (lambda data: data.update(logsource={}), "logsource"),
        (lambda data: data.update(logsource={"vendor": "acme"}), "unsupported logsource"),
        (lambda data: data.update(detection={}), "detection"),
        (lambda data: data.update(detection={"condition": "selection"}), "at least one selection"),
        (
            lambda data: data.update(detection={"selection": {}, "condition": "selection"}),
            "non-empty mapping",
        ),
        (
            lambda data: data.update(
                detection={"selection": {"x|nope": "y"}, "condition": "selection"}
            ),
            "unknown modifier",
        ),
        (
            lambda data: data.update(detection={"selection": {"x": "y"}, "condition": "other"}),
            "unknown selections",
        ),
    ],
)
def test_compile_rejects_invalid_rules(base_rule, mutation, message):
    data = deepcopy(base_rule)
    mutation(data)
    with pytest.raises((RuleError, ValueError), match=message):
        compile_rule(data)


def test_compile_rejects_threshold_without_timeframe(base_rule):
    data = deepcopy(base_rule)
    data["threshold"] = {"count": 2}
    with pytest.raises(RuleError, match="timeframe"):
        compile_rule(data)


def test_compile_rejects_threshold_defined_twice(base_rule):
    data = deepcopy(base_rule)
    data["timeframe"] = "5m"
    data["threshold"] = {"count": 2}
    data["detection"]["condition"] = "selection | count() >= 2"
    with pytest.raises(RuleError, match="either"):
        compile_rule(data)


def test_compile_rejects_sequence_errors(base_rule):
    data = deepcopy(base_rule)
    data["sequence"] = {"first": "missing", "then": "selection", "min_first": 1, "within": "5m"}
    with pytest.raises(RuleError, match="unknown selection"):
        compile_rule(data)
    data = deepcopy(base_rule)
    data["sequence"] = {"first": "selection", "then": "selection", "min_first": 1, "within": "5m"}
    with pytest.raises(RuleError, match="must differ"):
        compile_rule(data)
    data = deepcopy(base_rule)
    data["detection"] = {
        "failures": {"action": "ssh_auth_failed"},
        "success": {"action": "ssh_auth_success"},
        "condition": "failures or success",
    }
    data["sequence"] = {"first": "failures", "then": "success", "min_first": 0, "within": "5m"}
    with pytest.raises(RuleError, match="min_first"):
        compile_rule(data)


def test_compile_rejects_sequence_without_group_by(base_rule):
    data = deepcopy(base_rule)
    data["detection"] = {
        "failures": {"action": "ssh_auth_failed"},
        "success": {"action": "ssh_auth_success"},
        "condition": "failures or success",
    }
    data["sequence"] = {"first": "failures", "then": "success", "min_first": 1, "within": "5m"}
    with pytest.raises(RuleError, match="group_by"):
        compile_rule(data)


def test_lint_detects_duplicate_ids(base_rule):
    rule = compile_rule(deepcopy(base_rule), path="a.yml")
    duplicate = compile_rule(deepcopy(base_rule), path="b.yml")
    issues = lint_rules([rule, duplicate])
    assert any(issue.level == "error" and "duplicate" in issue.message for issue in issues)


def test_lint_warns_about_missing_tags_and_unknown_technique(base_rule):
    no_tags = deepcopy(base_rule)
    no_tags["tags"] = []
    rule = compile_rule(no_tags)
    issues = lint_rules([rule])
    assert any(issue.level == "warning" and "ATT&CK" in issue.message for issue in issues)

    unknown = deepcopy(base_rule)
    unknown["tags"] = ["attack.t9999"]
    rule = compile_rule(unknown)
    assert any("unknown ATT&CK technique" in issue.message for issue in lint_rules([rule]))


def test_lint_rejects_unknown_tactic_and_malformed_tag(base_rule):
    bad_tactic = deepcopy(base_rule)
    bad_tactic["tags"] = ["attack.not_a_tactic"]
    rule = compile_rule(bad_tactic)
    assert any("unknown ATT&CK tactic" in issue.message for issue in lint_rules([rule]))
    malformed = deepcopy(base_rule)
    malformed["tags"] = ["attack.credential-access"]
    rule = compile_rule(malformed)
    assert any("malformed ATT&CK tag" in issue.message for issue in lint_rules([rule]))


def test_load_rules_lenient_collects_file_errors(tmp_path):
    good = tmp_path / "good.yml"
    good.write_text(
        """
id: ARGUS-9001
title: Good
description: A valid rule loaded from a temporary directory.
severity: low
logsource: {product: linux}
detection:
  selection: {action: test}
  condition: selection
falsepositives: [test]
""",
        encoding="utf-8",
    )
    bad = tmp_path / "bad.yml"
    bad.write_text("id: broken\n", encoding="utf-8")
    loaded = load_rules_lenient(tmp_path)
    assert len(loaded.rules) == 1
    assert len(loaded.errors) == 1
    assert "missing required key" in loaded.errors[0]
