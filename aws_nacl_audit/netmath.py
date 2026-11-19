"""CIDR and port-range math.

Network ACLs are evaluated in rule-number order, first match wins, and every
rule matches on three independent axes: protocol, CIDR and port range. Every
rule in this tool reduces to "does entry A match a superset of what entry B
matches", so the overlap arithmetic lives here and is unit-tested on its own.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence

Range = tuple[int, int]

ALL_PORTS: Range = (0, 65535)
PROTO_ALL = "-1"

PROTO_NAMES = {
    "-1": "all",
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "58": "icmpv6",
}

# Protocols that carry a port number at all. Anything else (icmp, esp, gre)
# matches on the whole 0-65535 space as far as an ACL entry is concerned.
PORTED_PROTOCOLS = {"6", "17"}


class NetmathError(ValueError):
    """Raised for input that cannot be parsed as a CIDR or a port range."""


def proto_name(protocol: str) -> str:
    """Human label for an ACL protocol number."""
    return PROTO_NAMES.get(str(protocol), f"proto {protocol}")


def parse_cidr(text: str):
    """Parse a v4 or v6 CIDR, rejecting host bits set."""
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as exc:  # pragma: no cover - message passthrough
        raise NetmathError(f"bad CIDR {text!r}: {exc}") from exc


def cidr_contains(outer: str | None, inner: str | None) -> bool:
    """True when every address matched by `inner` is also matched by `outer`.

    Mixed address families never contain one another: an IPv4 outbound rule is
    not a return path for IPv6 traffic, which is a real way to lose half a
    dual-stack subnet.
    """
    if not outer or not inner:
        return False
    a, b = parse_cidr(outer), parse_cidr(inner)
    if a.version != b.version:
        return False
    return b.subnet_of(a)


def is_any_cidr(text: str | None) -> bool:
    """True for 0.0.0.0/0 and ::/0."""
    if not text:
        return False
    net = parse_cidr(text)
    return net.prefixlen == 0


def parse_port_range(text: str) -> Range:
    """Parse `1024-65535` or a single `443`."""
    raw = str(text).strip()
    if not raw:
        raise NetmathError("empty port range")
    if "-" in raw:
        lo_s, _, hi_s = raw.partition("-")
    else:
        lo_s = hi_s = raw
    try:
        lo, hi = int(lo_s), int(hi_s)
    except ValueError as exc:
        raise NetmathError(f"bad port range {text!r}") from exc
    if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
        raise NetmathError(f"port range {text!r} outside 0-65535")
    if lo > hi:
        raise NetmathError(f"port range {text!r} is inverted")
    return (lo, hi)


def format_range(rng: Range) -> str:
    lo, hi = rng
    if (lo, hi) == ALL_PORTS:
        return "all"
    return str(lo) if lo == hi else f"{lo}-{hi}"


def format_ranges(ranges: Sequence[Range]) -> str:
    return ", ".join(format_range(r) for r in ranges) if ranges else "none"


def range_intersect(a: Range, b: Range) -> Range | None:
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    return (lo, hi) if lo <= hi else None


def ranges_overlap(a: Range, b: Range) -> bool:
    return range_intersect(a, b) is not None


def covers_range(outer: Range, inner: Range) -> bool:
    return outer[0] <= inner[0] and outer[1] >= inner[1]


def merge_ranges(ranges: Iterable[Range]) -> list[Range]:
    """Sort and coalesce ranges, joining adjacent ones (443,444 -> 443-444)."""
    out: list[Range] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def range_subtract(target: Range, covers: Sequence[Range]) -> list[Range]:
    """The parts of `target` left uncovered by `covers`."""
    remaining = [target]
    for cover in merge_ranges(covers):
        nxt: list[Range] = []
        for lo, hi in remaining:
            inter = range_intersect((lo, hi), cover)
            if inter is None:
                nxt.append((lo, hi))
                continue
            if lo < inter[0]:
                nxt.append((lo, inter[0] - 1))
            if hi > inter[1]:
                nxt.append((inter[1] + 1, hi))
        remaining = nxt
        if not remaining:
            break
    return remaining


def range_width(rng: Range) -> int:
    return rng[1] - rng[0] + 1


def proto_covers(outer: str, inner: str) -> bool:
    """True when an entry on protocol `outer` also matches protocol `inner`."""
    outer, inner = str(outer), str(inner)
    if outer == PROTO_ALL:
        return True
    return outer == inner
