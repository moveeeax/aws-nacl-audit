"""The rule engine.

Every rule takes the normalised topology and returns Findings. Nothing here
talks to AWS, so the whole engine runs against JSON fixtures.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import __version__
from .config import Config
from .model import Acl, Entry, Region, Subnet, Vpc
from .netmath import (
    ALL_PORTS,
    PROTO_ALL,
    Range,
    cidr_contains,
    covers_range,
    format_range,
    format_ranges,
    is_any_cidr,
    merge_ranges,
    proto_covers,
    proto_name,
    range_intersect,
    range_subtract,
    range_width,
    ranges_overlap,
)

OK = "ok"
WARN = "warn"
CRITICAL = "critical"
SEVERITY_ORDER = {OK: 0, WARN: 1, CRITICAL: 2}


def worst(severities: Sequence[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER[s], default=OK) if severities else OK


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    acl_id: str
    vpc_id: str
    region: str = ""
    subnet_id: str | None = None
    rule_number: int | None = None
    direction: str | None = None

    def as_dict(self) -> dict:
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "region": self.region,
            "vpc_id": self.vpc_id,
            "acl_id": self.acl_id,
        }
        if self.subnet_id:
            d["subnet_id"] = self.subnet_id
        if self.rule_number is not None:
            d["rule_number"] = self.rule_number
        if self.direction:
            d["direction"] = self.direction
        return d


@dataclass
class AclResult:
    region: str
    vpc_id: str
    acl_id: str
    is_default: bool
    name: str
    subnet_ids: list[str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return worst([f.severity for f in self.findings])

    def entry_severities(self) -> list[dict]:
        buckets: dict[tuple, list[str]] = {}
        for f in self.findings:
            if f.rule_number is None:
                continue
            buckets.setdefault((f.rule_number, f.direction or ""), []).append(f.severity)
        return [
            {"rule_number": num, "direction": direction, "severity": worst(sev)}
            for (num, direction), sev in sorted(buckets.items())
        ]

    def as_dict(self) -> dict:
        return {
            "region": self.region,
            "vpc_id": self.vpc_id,
            "acl_id": self.acl_id,
            "is_default": self.is_default,
            "name": self.name,
            "subnet_ids": self.subnet_ids,
            "severity": self.severity,
            "entries": self.entry_severities(),
            "findings": [f.as_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
# rule-order evaluation
# --------------------------------------------------------------------------
def effective_allowed_ports(
    entries: Sequence[Entry],
    target_cidr: str,
    protocol: str,
    window: Range,
) -> list[Range]:
    """Ports inside `window` that traffic to/from `target_cidr` may actually use.

    This walks entries in rule-number order and retires each port as soon as
    the first matching entry decides it, which is what "first match wins"
    means. A broad allow at rule 100 therefore makes a deny at rule 200
    irrelevant here, exactly as it is in the VPC.
    """
    undecided: list[Range] = [window]
    allowed: list[Range] = []
    for entry in sorted(entries, key=lambda e: e.rule_number):
        if not undecided:
            break
        if not proto_covers(entry.protocol, protocol):
            continue
        if not cidr_contains(entry.cidr, target_cidr):
            continue
        still: list[Range] = []
        for span in undecided:
            decided = range_intersect(span, entry.ports)
            if decided is None:
                still.append(span)
                continue
            if entry.action == "allow":
                allowed.append(decided)
            still.extend(range_subtract(span, [decided]))
        undecided = still
    return merge_ranges(allowed)


def shadowing_entry(entry: Entry, earlier: Sequence[Entry]) -> Entry | None:
    """The first lower-numbered entry that already matches everything `entry` does."""
    for other in earlier:
        if other.rule_number >= entry.rule_number:
            continue
        if (
            proto_covers(other.protocol, entry.protocol)
            and cidr_contains(other.cidr, entry.cidr)
            and covers_range(other.ports, entry.ports)
        ):
            return other
    return None


def has_factory_allow_all(acl: Acl) -> bool:
    """True when the ACL still carries the default allow-everything pair."""
    directions = set()
    for entry in acl.entries:
        if entry.is_implicit or entry.action != "allow":
            continue
        if entry.protocol == PROTO_ALL and is_any_cidr(entry.cidr) and entry.ports == ALL_PORTS:
            directions.add(entry.egress)
    return directions == {True, False}


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------
def rule_default_acl(acl: Acl, region: Region, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    if not acl.is_default:
        return out
    for sid in acl.subnet_ids:
        subnet: Subnet | None = region.subnets.get(sid)
        where = f"{sid} ({subnet.cidr})" if subnet and subnet.cidr else sid
        out.append(
            Finding(
                rule="default-acl-subnet",
                severity=WARN,
                message=(
                    f"subnet {where} in {acl.vpc_id} is associated with the VPC default "
                    f"ACL {acl.acl_id}; it filters nothing"
                ),
                acl_id=acl.acl_id,
                vpc_id=acl.vpc_id,
                subnet_id=sid,
            )
        )
    if acl.subnet_ids and has_factory_allow_all(acl):
        out.append(
            Finding(
                rule="default-acl-allow-all",
                severity=WARN,
                message=(
                    f"default ACL {acl.acl_id} still carries its factory allow-all entries "
                    f"while serving {len(acl.subnet_ids)} subnet(s): a control in name only"
                ),
                acl_id=acl.acl_id,
                vpc_id=acl.vpc_id,
            )
        )
    return out


def rule_return_path(acl: Acl, region: Region, cfg: Config) -> list[Finding]:
    """Stateless ACLs need the ephemeral range open in the opposite direction."""
    out: list[Finding] = []
    for egress in (False, True):
        forward = acl.directional(egress)
        reverse = acl.directional(not egress)
        for entry in forward:
            if entry.is_implicit or entry.action != "allow" or not entry.is_ported:
                continue
            if not entry.cidr:
                continue
            allowed = effective_allowed_ports(
                reverse, entry.cidr, entry.protocol, cfg.ephemeral_range
            )
            uncovered = range_subtract(cfg.ephemeral_range, allowed)
            if not uncovered:
                continue
            back = "outbound" if not egress else "inbound"
            out.append(
                Finding(
                    rule="missing-return-path",
                    severity=CRITICAL,
                    message=(
                        f"{acl.acl_id} rule {entry.rule_number} allows {entry.direction} "
                        f"{proto_name(entry.protocol)} {format_range(entry.ports)} from "
                        f"{entry.cidr}, but the {back} ephemeral range "
                        f"{format_range(cfg.ephemeral_range)} is not fully allowed back: "
                        f"{format_ranges(uncovered)} uncovered. Connections will hang."
                    ),
                    acl_id=acl.acl_id,
                    vpc_id=acl.vpc_id,
                    rule_number=entry.rule_number,
                    direction=entry.direction,
                )
            )
    return out


def rule_shadowed(acl: Acl, region: Region, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for egress in (False, True):
        entries = [e for e in acl.directional(egress) if not e.is_implicit]
        for idx, entry in enumerate(entries):
            shadow = shadowing_entry(entry, entries[:idx])
            if shadow is None:
                continue
            if entry.action == "deny" and shadow.action == "allow":
                out.append(
                    Finding(
                        rule="shadowed-deny",
                        severity=CRITICAL,
                        message=(
                            f"{acl.acl_id} {entry.direction} deny rule {entry.rule_number} "
                            f"({entry.cidr} {proto_name(entry.protocol)} "
                            f"{format_range(entry.ports)}) is unreachable: allow rule "
                            f"{shadow.rule_number} already matches a superset. It reads as "
                            f"enforcement and enforces nothing."
                        ),
                        acl_id=acl.acl_id,
                        vpc_id=acl.vpc_id,
                        rule_number=entry.rule_number,
                        direction=entry.direction,
                    )
                )
            else:
                out.append(
                    Finding(
                        rule="shadowed-entry",
                        severity=WARN,
                        message=(
                            f"{acl.acl_id} {entry.direction} rule {entry.rule_number} is dead "
                            f"text: rule {shadow.rule_number} ({shadow.action}) already matches "
                            f"a superset of its CIDR, protocol and ports"
                        ),
                        acl_id=acl.acl_id,
                        vpc_id=acl.vpc_id,
                        rule_number=entry.rule_number,
                        direction=entry.direction,
                    )
                )
    return out


def rule_exposure(acl: Acl, region: Region, cfg: Config) -> list[Finding]:
    """Inbound allows from anywhere.

    A default ACL is skipped: `rule_default_acl` already owns that case and says
    something more useful about it than "allows everything".

    An entry that covers the whole configured ephemeral range is treated as a
    return-path rule and exempted. On a stateless ACL that rule is mandatory,
    and because 1024-65535 happens to contain 3306, 3389, 5432 and 6379, a
    naive admin-port check flags every correctly configured ACL in the account.
    """
    out: list[Finding] = []
    if acl.is_default:
        return out
    for entry in sorted(acl.entries, key=lambda e: (e.egress, e.rule_number)):
        if entry.is_implicit or entry.action != "allow" or entry.egress:
            continue
        if not is_any_cidr(entry.cidr):
            continue
        if entry.is_ported and covers_range(entry.ports, cfg.ephemeral_range):
            continue
        if entry.protocol == PROTO_ALL:
            out.append(
                Finding(
                    rule="open-all-protocols",
                    severity=CRITICAL,
                    message=(
                        f"{acl.acl_id} rule {entry.rule_number} allows every protocol and port "
                        f"inbound from {entry.cidr}"
                    ),
                    acl_id=acl.acl_id,
                    vpc_id=acl.vpc_id,
                    rule_number=entry.rule_number,
                    direction=entry.direction,
                )
            )
            continue
        hits = sorted(p for p in cfg.admin_ports if ranges_overlap(entry.ports, (p, p)))
        if hits:
            out.append(
                Finding(
                    rule="open-admin-port",
                    severity=CRITICAL,
                    message=(
                        f"{acl.acl_id} rule {entry.rule_number} allows "
                        f"{proto_name(entry.protocol)} {format_range(entry.ports)} inbound from "
                        f"{entry.cidr}, which reaches administrative port(s) "
                        f"{', '.join(str(p) for p in hits)}"
                    ),
                    acl_id=acl.acl_id,
                    vpc_id=acl.vpc_id,
                    rule_number=entry.rule_number,
                    direction=entry.direction,
                )
            )
        width = range_width(entry.ports)
        if width > cfg.max_open_ports:
            out.append(
                Finding(
                    rule="wide-open-range",
                    severity=WARN,
                    message=(
                        f"{acl.acl_id} rule {entry.rule_number} allows {width} inbound ports "
                        f"({format_range(entry.ports)}) from {entry.cidr}, over the "
                        f"--max-open-ports limit of {cfg.max_open_ports}"
                    ),
                    acl_id=acl.acl_id,
                    vpc_id=acl.vpc_id,
                    rule_number=entry.rule_number,
                    direction=entry.direction,
                )
            )
    return out


def rule_hygiene(acl: Acl, region: Region, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    if not acl.is_default and acl.association_count == 0:
        written = len([e for e in acl.entries if not e.is_implicit])
        out.append(
            Finding(
                rule="unattached-acl",
                severity=WARN,
                message=(
                    f"{acl.acl_id} in {acl.vpc_id} is associated with no subnet: dead "
                    f"configuration carrying {written} "
                    f"{'entry' if written == 1 else 'entries'}"
                ),
                acl_id=acl.acl_id,
                vpc_id=acl.vpc_id,
            )
        )
    for egress in (False, True):
        entries = [e for e in acl.directional(egress) if not e.is_implicit]
        for prev, nxt in zip(entries, entries[1:], strict=False):
            gap = nxt.rule_number - prev.rule_number
            if gap < cfg.min_rule_gap:
                out.append(
                    Finding(
                        rule="no-insertion-gap",
                        severity=WARN,
                        message=(
                            f"{acl.acl_id} {prev.direction} rules {prev.rule_number} and "
                            f"{nxt.rule_number} are {gap} apart (under --min-rule-gap "
                            f"{cfg.min_rule_gap}); the next change has to renumber live rules"
                        ),
                        acl_id=acl.acl_id,
                        vpc_id=acl.vpc_id,
                        rule_number=nxt.rule_number,
                        direction=nxt.direction,
                    )
                )
        if len(entries) >= cfg.entry_quota:
            out.append(
                Finding(
                    rule="entry-quota-reached",
                    severity=WARN,
                    message=(
                        f"{acl.acl_id} has {len(entries)} {'outbound' if egress else 'inbound'} "
                        f"entries, at or over the per-ACL quota of {cfg.entry_quota}"
                    ),
                    acl_id=acl.acl_id,
                    vpc_id=acl.vpc_id,
                )
            )
    missing = [t for t in cfg.require_tags if t not in acl.tags]
    if missing:
        out.append(
            Finding(
                rule="missing-tags",
                severity=WARN,
                message=f"{acl.acl_id} is missing required tag(s): {', '.join(missing)}",
                acl_id=acl.acl_id,
                vpc_id=acl.vpc_id,
            )
        )
    return out


RULES = (
    rule_default_acl,
    rule_return_path,
    rule_shadowed,
    rule_exposure,
    rule_hygiene,
)


def audit_acl(acl: Acl, region: Region, cfg: Config) -> AclResult:
    result = AclResult(
        region=region.region,
        vpc_id=acl.vpc_id,
        acl_id=acl.acl_id,
        is_default=acl.is_default,
        name=acl.name,
        subnet_ids=list(acl.subnet_ids),
    )
    for rule in RULES:
        for finding in rule(acl, region, cfg):
            finding.region = region.region
            result.findings.append(finding)
    result.findings.sort(
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_number or 0, f.rule)
    )
    return result


def audit(regions: Sequence[Region], cfg: Config) -> dict:
    """Run every rule over every ACL and build the report document."""
    acls: list[AclResult] = []
    for region in regions:
        for acl in sorted(region.acls, key=lambda a: (a.vpc_id, a.acl_id)):
            acls.append(audit_acl(acl, region, cfg))

    findings = [f for a in acls for f in a.findings]
    counts = {
        CRITICAL: sum(1 for f in findings if f.severity == CRITICAL),
        WARN: sum(1 for f in findings if f.severity == WARN),
    }

    vpc_index: dict[tuple, dict] = {}
    for region in regions:
        for acl in region.acls:
            key = (region.region, acl.vpc_id)
            vpc: Vpc | None = region.vpcs.get(acl.vpc_id)
            vpc_index.setdefault(
                key,
                {
                    "region": region.region,
                    "vpc_id": acl.vpc_id,
                    "cidr": vpc.cidr if vpc else "",
                    "name": vpc.name if vpc else "",
                    "acl_ids": [],
                    "severity": OK,
                },
            )["acl_ids"].append(acl.acl_id)
    for a in acls:
        entry = vpc_index.get((a.region, a.vpc_id))
        if entry:
            entry["severity"] = worst([entry["severity"], a.severity])

    return {
        "tool": "aws-nacl-audit",
        "version": __version__,
        "generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": cfg.as_dict(),
        "regions": [r.region for r in regions],
        "severity": worst([a.severity for a in acls]),
        "counts": counts,
        "vpcs": sorted(vpc_index.values(), key=lambda v: (v["region"], v["vpc_id"])),
        "acls": [a.as_dict() for a in acls],
        "findings": [f.as_dict() for f in findings],
    }
