"""Normalised view of the describe-* payload.

The collectors hand over plain dicts shaped exactly like the EC2 API replies,
so a recorded `--dump-json` payload replays through the same code path as a
live run. This module turns those dicts into small typed objects the rule
engine can read without reaching for AWS key names everywhere.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .netmath import ALL_PORTS, PORTED_PROTOCOLS, Range, proto_name

# AWS returns the implicit catch-all deny as a real entry at rule number 32767.
# It is not something a reviewer wrote, so most rules skip it while rule-order
# evaluation still honours it.
IMPLICIT_RULE_NUMBER = 32767


@dataclass
class Entry:
    """One ACL entry (one rule)."""

    rule_number: int
    protocol: str
    action: str  # "allow" | "deny"
    egress: bool
    cidr: str | None
    ports: Range
    explicit_ports: bool

    @property
    def is_implicit(self) -> bool:
        return self.rule_number >= IMPLICIT_RULE_NUMBER

    @property
    def direction(self) -> str:
        return "outbound" if self.egress else "inbound"

    @property
    def is_ported(self) -> bool:
        return self.protocol in PORTED_PROTOCOLS

    def label(self) -> str:
        from .netmath import format_range

        return (
            f"rule {self.rule_number} {self.direction} {self.action} "
            f"{proto_name(self.protocol)} {self.cidr or '-'} ports {format_range(self.ports)}"
        )


@dataclass
class Acl:
    acl_id: str
    vpc_id: str
    is_default: bool
    entries: list[Entry]
    subnet_ids: list[str]
    association_count: int
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name", "")

    def directional(self, egress: bool) -> list[Entry]:
        return sorted(
            (e for e in self.entries if e.egress == egress),
            key=lambda e: e.rule_number,
        )


@dataclass
class Subnet:
    subnet_id: str
    vpc_id: str
    cidr: str
    availability_zone: str
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name", "")


@dataclass
class Vpc:
    vpc_id: str
    cidr: str
    is_default: bool
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name", "")


@dataclass
class Region:
    region: str
    acls: list[Acl]
    subnets: dict[str, Subnet]
    vpcs: dict[str, Vpc]


class PayloadError(ValueError):
    """Raised when a replayed payload is not shaped like a recorded run."""


def _tags(raw: dict) -> dict[str, str]:
    return {t.get("Key", ""): t.get("Value", "") for t in raw.get("Tags") or []}


def parse_entry(raw: dict) -> Entry:
    protocol = str(raw.get("Protocol", "-1"))
    port_range = raw.get("PortRange")
    if port_range:
        ports: Range = (
            int(port_range.get("From", 0)),
            int(port_range.get("To", 65535)),
        )
        explicit = True
    else:
        ports = ALL_PORTS
        explicit = False
    cidr = raw.get("CidrBlock") or raw.get("Ipv6CidrBlock")
    return Entry(
        rule_number=int(raw.get("RuleNumber", IMPLICIT_RULE_NUMBER)),
        protocol=protocol,
        action=str(raw.get("RuleAction", "deny")).lower(),
        egress=bool(raw.get("Egress", False)),
        cidr=cidr,
        ports=ports,
        explicit_ports=explicit,
    )


def parse_acl(raw: dict) -> Acl:
    associations = raw.get("Associations") or []
    return Acl(
        acl_id=raw.get("NetworkAclId", "<unknown>"),
        vpc_id=raw.get("VpcId", "<unknown>"),
        is_default=bool(raw.get("IsDefault", False)),
        entries=[parse_entry(e) for e in raw.get("Entries") or []],
        subnet_ids=[a.get("SubnetId") for a in associations if a.get("SubnetId")],
        association_count=len(associations),
        tags=_tags(raw),
    )


def parse_region(region: str, raw: dict) -> Region:
    if not isinstance(raw, dict):
        raise PayloadError(f"region {region!r} is not an object")
    acls = [parse_acl(a) for a in raw.get("NetworkAcls") or []]
    subnets = {}
    for s in raw.get("Subnets") or []:
        sid = s.get("SubnetId")
        if sid:
            subnets[sid] = Subnet(
                subnet_id=sid,
                vpc_id=s.get("VpcId", ""),
                cidr=s.get("CidrBlock", ""),
                availability_zone=s.get("AvailabilityZone", ""),
                tags=_tags(s),
            )
    vpcs = {}
    for v in raw.get("Vpcs") or []:
        vid = v.get("VpcId")
        if vid:
            vpcs[vid] = Vpc(
                vpc_id=vid,
                cidr=v.get("CidrBlock", ""),
                is_default=bool(v.get("IsDefault", False)),
                tags=_tags(v),
            )
    return Region(region=region, acls=acls, subnets=subnets, vpcs=vpcs)


def parse_payload(payload: dict) -> list[Region]:
    """Turn a recorded or freshly collected payload into Region objects."""
    if not isinstance(payload, dict):
        raise PayloadError("payload root is not an object")
    regions = payload.get("regions")
    if not isinstance(regions, dict) or not regions:
        raise PayloadError("payload has no 'regions' object")
    return [parse_region(name, body) for name, body in sorted(regions.items())]
