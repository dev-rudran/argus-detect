"""IP address helpers with no third-party dependencies."""

from __future__ import annotations

import ipaddress

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# RFC 5737, RFC 3849 and other documentation / private ranges are not routable.
_EXTRA_NON_PUBLIC = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def parse_ip(value: object) -> IPAddress | None:
    """Parse an IPv4 or IPv6 address, returning None for non-addresses."""
    if value is None:
        return None
    text = str(value).strip().strip("[]")
    if not text:
        return None
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def parse_network(value: object) -> IPNetwork | None:
    """Parse a CIDR network; a bare address is treated as a /32 or /128."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        address = parse_ip(text)
        if address is None:
            return None
        return ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False)


def ip_in_cidr(value: object, cidr: object) -> bool:
    """Return True when *value* is a valid address inside *cidr*."""
    address = parse_ip(value)
    network = parse_network(cidr)
    if address is None or network is None:
        return False
    try:
        return address in network
    except TypeError:
        # IPv4 address in an IPv6 network and vice versa.
        return False


def is_private_ip(value: object) -> bool:
    """Return True for private, loopback, link-local and documentation ranges."""
    address = parse_ip(value)
    if address is None:
        return False
    if address.is_private or address.is_loopback or address.is_link_local:
        return True
    return any(
        address in network for network in _EXTRA_NON_PUBLIC if address.version == network.version
    )


def is_public_ip(value: object) -> bool:
    """Return True only for globally routable addresses.

    Documentation ranges (TEST-NET) are treated as non-public so example
    traffic is not mistaken for internet egress.
    """
    address = parse_ip(value)
    if address is None:
        return False
    if is_private_ip(address):
        return False
    return address.is_global


def dest_scope(value: object) -> str:
    """Classify a destination address as ``public``, ``internal`` or ``unknown``."""
    address = parse_ip(value)
    if address is None:
        return "unknown"
    return "public" if is_public_ip(address) else "internal"
