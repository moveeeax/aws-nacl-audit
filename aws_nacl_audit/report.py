"""Renderers: text for a terminal, markdown for a PR comment, JSON for jq."""
from __future__ import annotations

import json

from .rules import CRITICAL, OK, WARN

MARK = {CRITICAL: "CRIT", WARN: "WARN", OK: " OK "}
BADGE = {CRITICAL: "🔴 critical", WARN: "🟡 warn", OK: "🟢 ok"}


def _by_vpc(report: dict) -> dict[tuple, list[dict]]:
    grouped: dict[tuple, list[dict]] = {}
    for acl in report["acls"]:
        grouped.setdefault((acl["region"], acl["vpc_id"]), []).append(acl)
    return grouped


def render_text(report: dict) -> str:
    lines: list[str] = []
    counts = report["counts"]
    lines.append(
        f"aws-nacl-audit {report['version']} — regions: {', '.join(report['regions'])}"
    )
    lines.append(
        f"ephemeral return range: {report['config']['ephemeral_range']}   "
        f"critical: {counts[CRITICAL]}   warn: {counts[WARN]}"
    )
    vpc_sev = {(v["region"], v["vpc_id"]): v for v in report["vpcs"]}
    for key, acls in _by_vpc(report).items():
        region, vpc_id = key
        vpc = vpc_sev.get(key, {})
        cidr = f" {vpc.get('cidr')}" if vpc.get("cidr") else ""
        lines.append("")
        lines.append(f"{region}  {vpc_id}{cidr}  [{vpc.get('severity', OK)}]")
        for acl in acls:
            tag = " (default)" if acl["is_default"] else ""
            subnets = (
                f" {len(acl['subnet_ids'])} subnet(s)" if acl["subnet_ids"] else " unattached"
            )
            lines.append(f"  {acl['acl_id']}{tag}{subnets}  [{acl['severity']}]")
            if not acl["findings"]:
                lines.append("    clean")
            for f in acl["findings"]:
                lines.append(f"    [{MARK[f['severity']]}] {f['rule']}: {f['message']}")
    if not report["acls"]:
        lines.append("")
        lines.append("no network ACLs found")
    lines.append("")
    lines.append(f"overall: {report['severity']}")
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    counts = report["counts"]
    lines: list[str] = [
        "## aws-nacl-audit",
        "",
        f"Regions: `{'`, `'.join(report['regions'])}` · "
        f"expected return range `{report['config']['ephemeral_range']}` · "
        f"**{counts[CRITICAL]} critical**, {counts[WARN]} warn · "
        f"overall {BADGE[report['severity']]}",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings. Every ACL filters what it claims to filter.")
        return "\n".join(lines)

    lines += ["| Severity | VPC | ACL | Rule | Finding |", "| --- | --- | --- | --- | --- |"]
    for f in report["findings"]:
        num = f.get("rule_number")
        where = f"`{num}`" if num is not None else "—"
        message = f["message"].replace("|", "\\|")
        lines.append(
            f"| {BADGE[f['severity']]} | `{f['vpc_id']}` | `{f['acl_id']}` | "
            f"{f['rule']} {where} | {message} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False)


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}


def render(report: dict, fmt: str) -> str:
    return RENDERERS[fmt](report)
