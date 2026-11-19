"""Live collection from EC2.

boto3 is imported lazily so `--from-json` works on a machine with no AWS SDK
and no credentials, which is how the test suite and CI run.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from . import __version__


class CollectError(RuntimeError):
    """Raised when AWS cannot be reached or refuses a describe call."""


def _client(region: str, profile: str | None = None):
    try:
        import boto3
    except ModuleNotFoundError as exc:  # pragma: no cover - boto3 is a hard dep
        raise CollectError(
            "boto3 is required for a live run; use --from-json to replay a payload"
        ) from exc
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("ec2", region_name=region)


def _paginate(client, op: str, key: str) -> list[dict]:
    out: list[dict] = []
    paginator = client.get_paginator(op)
    for page in paginator.paginate():
        out.extend(page.get(key, []))
    return out


def collect_region(region: str, profile: str | None = None) -> dict[str, list[dict]]:
    """Three describe calls: the ACLs, the subnets they attach to, the VPCs."""
    try:
        client = _client(region, profile)
        return {
            "NetworkAcls": _paginate(client, "describe_network_acls", "NetworkAcls"),
            "Subnets": _paginate(client, "describe_subnets", "Subnets"),
            "Vpcs": client.describe_vpcs().get("Vpcs", []),
        }
    except CollectError:
        raise
    except Exception as exc:  # botocore raises a zoo of client errors
        raise CollectError(f"{region}: {exc}") from exc


def collect(regions: Sequence[str], profile: str | None = None) -> dict:
    """Build a payload identical in shape to what `--from-json` consumes."""
    return {
        "tool": "aws-nacl-audit",
        "version": __version__,
        "collected": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "regions": {region: collect_region(region, profile) for region in regions},
    }
