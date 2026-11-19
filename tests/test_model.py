import pytest

from aws_nacl_audit.model import PayloadError, parse_acl, parse_entry, parse_payload

from .conftest import load


def test_entry_without_a_port_range_matches_everything():
    e = parse_entry({"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False,
                     "CidrBlock": "0.0.0.0/0"})
    assert e.ports == (0, 65535)
    assert e.explicit_ports is False
    assert e.direction == "inbound"
    assert e.is_ported is False


def test_implicit_catch_all_is_flagged():
    e = parse_entry({"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny", "Egress": True,
                     "CidrBlock": "0.0.0.0/0"})
    assert e.is_implicit
    assert e.direction == "outbound"


def test_ipv6_entries_keep_their_cidr():
    e = parse_entry({"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow", "Egress": False,
                     "Ipv6CidrBlock": "::/0", "PortRange": {"From": 443, "To": 443}})
    assert e.cidr == "::/0"
    assert e.label().startswith("rule 100 inbound allow tcp ::/0 ports 443")


def test_parse_acl_reads_tags_and_associations():
    acl = parse_acl({
        "NetworkAclId": "acl-x",
        "VpcId": "vpc-x",
        "IsDefault": True,
        "Tags": [{"Key": "Name", "Value": "edge"}],
        "Associations": [{"SubnetId": "subnet-1"}, {"NetworkAclId": "acl-x"}],
        "Entries": [],
    })
    assert acl.name == "edge"
    assert acl.subnet_ids == ["subnet-1"]
    assert acl.association_count == 2


def test_directional_sorts_by_rule_number():
    regions = parse_payload(load("prod.json"))
    web = next(a for a in regions[0].acls if a.acl_id == "acl-0web")
    assert [e.rule_number for e in web.directional(False)] == [100, 110, 120, 32767]
    assert [e.rule_number for e in web.directional(True)] == [100, 110, 32767]


@pytest.mark.parametrize("payload", [[], {"regions": {}}, {"regions": []}, {}])
def test_payload_errors(payload):
    with pytest.raises(PayloadError):
        parse_payload(payload)


def test_region_body_must_be_an_object():
    with pytest.raises(PayloadError):
        parse_payload({"regions": {"eu-central-1": "oops"}})
