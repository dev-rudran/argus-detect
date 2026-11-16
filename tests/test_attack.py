"""ATT&CK catalogue and coverage tests."""

from __future__ import annotations

from conftest import RULES_DIR

from argus.attack import TECHNIQUES, coverage, tactic_label, technique, techniques_for_tags
from argus.rules.loader import load_rules


def test_technique_lookup_is_case_insensitive_and_url_is_correct():
    item = technique("t1110.001")
    assert item is not None
    assert item.id == "T1110.001"
    assert item.is_subtechnique is True
    assert item.url == "https://attack.mitre.org/techniques/T1110/001"
    assert technique("T9999") is None


def test_techniques_for_tags_preserves_order_and_ignores_tactics():
    items = techniques_for_tags(
        ["attack.credential_access", "attack.t1110.003", "attack.t1110.001", "attack.t1110.003"]
    )
    assert [item.id for item in items] == ["T1110.003", "T1110.001"]


def test_coverage_counts_rules_and_techniques():
    rules = load_rules(RULES_DIR)
    report = coverage(rules)
    assert report.catalog_count == len(TECHNIQUES) == 48
    assert report.covered_count == 48
    assert report.percent == 100.0
    assert "ARGUS-0001" in report.rule_ids_by_technique["T1110"]
    assert report.heat("T1110") >= 3
    assert report.heat("T9999") == 0


def test_tactic_helpers_and_rows():
    report = coverage(load_rules(RULES_DIR))
    credential = report.tactic_ids("credential-access")
    assert "T1110" in credential
    assert set(report.tactic_covered("credential-access")) <= set(credential)
    assert report.tactic_percent("credential-access") > 0
    assert any(row["tactic"] == "credential-access" for row in report.rows())
    assert tactic_label("command_and_control") == "Command and Control"
    assert tactic_label("unknown-tactic") == "Unknown Tactic"
