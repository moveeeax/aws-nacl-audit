import pytest

from aws_nacl_audit import collect as collect_mod
from aws_nacl_audit.collect import CollectError, collect
from aws_nacl_audit.model import parse_payload


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        return iter(self._pages)


class FakeEc2:
    """Enough of the ec2 client to prove the collector stitches pages together."""

    def __init__(self):
        self.calls = []

    def get_paginator(self, op):
        self.calls.append(op)
        if op == "describe_network_acls":
            return FakePaginator(
                [
                    {"NetworkAcls": [{"NetworkAclId": "acl-a", "VpcId": "vpc-1", "Entries": []}]},
                    {"NetworkAcls": [{"NetworkAclId": "acl-b", "VpcId": "vpc-1", "Entries": []}]},
                ]
            )
        if op == "describe_subnets":
            return FakePaginator(
                [{"Subnets": [{"SubnetId": "subnet-a", "VpcId": "vpc-1",
                               "CidrBlock": "10.0.0.0/24"}]}]
            )
        raise AssertionError(f"unexpected paginator {op}")

    def describe_vpcs(self):
        self.calls.append("describe_vpcs")
        return {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]}


def test_collect_builds_a_replayable_payload(monkeypatch):
    fake = FakeEc2()
    monkeypatch.setattr(collect_mod, "_client", lambda region, profile=None: fake)
    payload = collect(["eu-central-1"])
    assert sorted(fake.calls) == [
        "describe_network_acls",
        "describe_subnets",
        "describe_vpcs",
    ]
    region = payload["regions"]["eu-central-1"]
    assert [a["NetworkAclId"] for a in region["NetworkAcls"]] == ["acl-a", "acl-b"]
    # The payload shape is exactly what --from-json consumes.
    parsed = parse_payload(payload)
    assert len(parsed[0].acls) == 2
    assert parsed[0].subnets["subnet-a"].cidr == "10.0.0.0/24"


def test_collect_wraps_client_errors(monkeypatch):
    def boom(region, profile=None):
        raise RuntimeError("AuthFailure")

    monkeypatch.setattr(collect_mod, "_client", boom)
    with pytest.raises(CollectError) as exc:
        collect(["eu-central-1"])
    assert "eu-central-1" in str(exc.value)
    assert "AuthFailure" in str(exc.value)
