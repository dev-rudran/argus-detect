"""Rule condition parser and evaluator tests."""

from __future__ import annotations

import pytest

from argus.rules.condition import (
    ConditionError,
    evaluate_condition,
    parse_condition,
    tokenize,
)


def test_single_selection():
    assert evaluate_condition("selection", {"selection": True})
    assert not evaluate_condition("selection", {"selection": False})


def test_and_or_precedence_and_parentheses():
    matches = {"a": True, "b": False, "c": True}
    assert evaluate_condition("a or b and c", matches)
    assert not evaluate_condition("(a or b) and b", matches)
    assert evaluate_condition("(a or b) and c", matches)


def test_not_and_double_not():
    matches = {"a": True, "b": False}
    assert evaluate_condition("not b", matches)
    assert not evaluate_condition("not a", matches)
    assert evaluate_condition("not not a", matches)


def test_any_of_them_and_all_of_them():
    assert evaluate_condition("1 of them", {"a": False, "b": True})
    assert evaluate_condition("any of them", {"a": False, "b": True})
    assert not evaluate_condition("all of them", {"a": True, "b": False})
    assert evaluate_condition("all of them", {"a": True, "b": True})
    assert not evaluate_condition("all of them", {})


def test_prefixed_selectors():
    matches = {"selection_a": True, "selection_b": False, "filter": True}
    assert evaluate_condition("1 of selection_*", matches)
    assert not evaluate_condition("all of selection_*", matches)
    assert evaluate_condition("any of filter*", matches)


def test_single_named_selection_after_of():
    assert evaluate_condition("1 of selection_a", {"selection_a": True})
    assert not evaluate_condition("1 of selection_a", {"selection_a": False})


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "   ",
        "selection and",
        "and selection",
        "(selection",
        "selection)",
        "2 of them",
        "1 selection",
        "not",
        "selection | count()",
        "selection | count() >= 0",
        "selection | avg() > 1",
        "selection @ other",
    ],
)
def test_invalid_conditions_raise(expression):
    with pytest.raises(ConditionError):
        parse_condition(expression)


def test_selector_must_match_a_real_selection():
    with pytest.raises(ConditionError):
        parse_condition("1 of missing_*").resolve(["selection"])


def test_threshold_spec_is_parsed():
    parsed = parse_condition("selection | count() >= 5")
    assert parsed.ast.describe() == "selection"
    assert parsed.threshold is not None
    assert parsed.threshold.op == "gte"
    assert parsed.threshold.count == 5


@pytest.mark.parametrize(
    ("symbol", "op"),
    [(">=", "gte"), (">", "gt"), ("<=", "lte"), ("<", "lt"), ("==", "eq")],
)
def test_threshold_operators(symbol, op):
    parsed = parse_condition(f"selection | count() {symbol} 10")
    assert parsed.threshold is not None
    assert parsed.threshold.op == op
    assert parsed.threshold.count == 10


def test_tokenize_ignores_space_and_reports_positions():
    tokens = tokenize("a and (b or c)")
    assert [token.value for token in tokens] == ["a", "and", "(", "b", "or", "c", ")"]
    assert tokens[0].position == 0
    assert tokens[-1].position == 13


def test_describe_round_trips_structure():
    parsed = parse_condition("(a or b) and not c")
    description = parsed.ast.describe()
    assert "or" in description
    assert "not" in description
    assert parsed.resolve(["a", "b", "c"]) == {"a", "b", "c"}
