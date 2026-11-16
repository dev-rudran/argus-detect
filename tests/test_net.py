"""IP address and network classification tests."""

from __future__ import annotations

import ipaddress

from argus.util.net import (
    dest_scope,
    ip_in_cidr,
    is_private_ip,
    is_public_ip,
    parse_ip,
    parse_network,
)


def test_parse_ip_supports_ipv4_ipv6_and_brackets():
    assert parse_ip("10.1.2.3") == ipaddress.ip_address("10.1.2.3")
    assert parse_ip("2001:db8::1") == ipaddress.ip_address("2001:db8::1")
    assert parse_ip("[2001:db8::2]") == ipaddress.ip_address("2001:db8::2")
    assert parse_ip("fe80::1%eth0") == ipaddress.ip_address("fe80::1")


def test_parse_ip_rejects_non_addresses():
    assert parse_ip("not-an-ip") is None
    assert parse_ip("") is None
    assert parse_ip(None) is None


def test_parse_network_treats_a_bare_address_as_a_host_route():
    assert parse_network("192.0.2.10") == ipaddress.ip_network("192.0.2.10/32")
    assert parse_network("2001:db8::10") == ipaddress.ip_network("2001:db8::10/128")
    assert parse_network("nonsense") is None


def test_ip_in_cidr_matches_families_and_rejects_mixed_families():
    assert ip_in_cidr("10.0.0.5", "10.0.0.0/8")
    assert ip_in_cidr("2001:db8::5", "2001:db8::/32")
    assert not ip_in_cidr("10.0.0.5", "2001:db8::/32")
    assert not ip_in_cidr("nonsense", "10.0.0.0/8")
    assert not ip_in_cidr("10.0.0.5", "nonsense")


def test_private_and_public_classification():
    for value in (
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "192.0.2.10",
        "198.51.100.7",
        "2001:db8::1",
    ):
        assert is_private_ip(value), value
        assert not is_public_ip(value), value
    for value in ("8.8.8.8", "185.220.101.47", "2606:4700:4700::1111"):
        assert is_public_ip(value), value
        assert not is_private_ip(value), value


def test_dest_scope_labels_public_internal_and_unknown():
    assert dest_scope("185.220.101.47") == "public"
    assert dest_scope("10.0.0.5") == "internal"
    assert dest_scope("203.0.113.9") == "internal"
    assert dest_scope("not-an-ip") == "unknown"
