from aws_nacl_audit.config import Config
from aws_nacl_audit.model import Entry, parse_payload
from aws_nacl_audit.rules import (
    CRITICAL,
    OK,
    WARN,
    audit,
    effective_allowed_ports,
    has_factory_allow_all,
    shadowing_entry,
    worst,
)

from .conftest import findings_for, load


def entry(num, proto="6", action="allow", egress=False, cidr="0.0.0.0/0", ports=(0, 65535)):
    return Entry(
        rule_number=num,
        protocol=proto,
        action=action,
        egress=egress,
        cidr=cidr,
        ports=ports,
        explicit_ports=ports != (0, 65535),
    )


# --- rule-order evaluation ------------------------------------------------
def test_first_match_wins_so_a_broad_allow_defeats_a_later_deny():
    entries = [
        entry(100, action="allow", ports=(1024, 65535)),
        entry(200, action="deny", ports=(3306, 3306)),
    ]
    assert effective_allowed_ports(entries, "10.0.0.1/32", "6", (1024, 65535)) == [(1024, 65535)]


def test_an_earlier_deny_punches_a_hole_in_the_return_range():
    entries = [
        entry(100, action="deny", ports=(3306, 3306)),
        entry(200, action="allow", ports=(1024, 65535)),
    ]
    allowed = effective_allowed_ports(entries, "10.0.0.1/32", "6", (1024, 65535))
    assert allowed == [(1024, 3305), (3307, 65535)]


def test_a_rule_for_another_cidr_contributes_nothing():
    entries = [entry(100, cidr="192.168.0.0/16", ports=(1024, 65535))]
    assert effective_allowed_ports(entries, "10.0.0.1/32", "6", (1024, 65535)) == []


def test_protocol_minus_one_covers_tcp():
    entries = [entry(100, proto="-1")]
    assert effective_allowed_ports(entries, "10.0.0.1/32", "6", (1024, 65535)) == [(1024, 65535)]


def test_shadowing_entry_finds_the_first_superset():
    broad = entry(100, proto="-1", cidr="10.0.0.0/8")
    narrow = entry(200, proto="6", cidr="10.0.1.0/24", ports=(443, 443))
    assert shadowing_entry(narrow, [broad]) is broad
    assert shadowing_entry(broad, [narrow]) is None


def test_has_factory_allow_all_needs_both_directions():
    regions = parse_payload(load("default_acl.json"))
    assert has_factory_allow_all(regions[0].acls[0])
    clean = parse_payload(load("clean.json"))
    assert not has_factory_allow_all(clean[0].acls[0])


def test_worst_severity():
    assert worst([OK, WARN, CRITICAL]) == CRITICAL
    assert worst([OK, WARN]) == WARN
    assert worst([]) == OK


# --- acceptance criteria --------------------------------------------------
def test_missing_return_path_is_critical_and_names_rule_and_range(run_audit):
    report = run_audit("missing_return.json")
    found = findings_for(report, "missing-return-path")
    # The ACL allows 443 in both directions and the ephemeral range in neither,
    # so both sides are broken and both are reported.
    assert {f["direction"] for f in found} == {"inbound", "outbound"}
    f = next(f for f in found if f["direction"] == "inbound")
    assert f["severity"] == CRITICAL
    assert f["rule_number"] == 100
    assert "443" in f["message"]
    assert "1024-65535 uncovered" in f["message"]
    assert report["severity"] == CRITICAL


def test_partial_return_path_names_only_the_uncovered_part(run_audit):
    report = run_audit("partial_return.json")
    messages = [f["message"] for f in findings_for(report, "missing-return-path")]
    assert messages, "expected the half-open ephemeral range to be reported"
    assert all("32768-65535 uncovered" in m for m in messages)


def test_ephemeral_range_override_changes_the_verdict(run_audit):
    # The outbound side allows 1024-32767, so a Linux-only return range is fine.
    cfg = Config(ephemeral_range=(1024, 30000))
    report = run_audit("partial_return.json", cfg)
    assert findings_for(report, "missing-return-path") == []


def test_subnet_on_the_vpc_default_acl_is_warn_and_names_subnet_and_vpc(run_audit):
    report = run_audit("default_acl.json")
    found = findings_for(report, "default-acl-subnet")
    assert len(found) == 1
    assert found[0]["severity"] == WARN
    assert found[0]["subnet_id"] == "subnet-3a"
    assert "subnet-3a" in found[0]["message"]
    assert "10.3.1.0/24" in found[0]["message"]
    assert "vpc-3" in found[0]["message"]


def test_default_acl_with_factory_rules_and_subnets_is_warn(run_audit):
    report = run_audit("default_acl.json")
    found = findings_for(report, "default-acl-allow-all")
    assert len(found) == 1
    assert found[0]["severity"] == WARN
    assert report["severity"] == WARN


def test_shadowed_deny_is_critical_and_names_both_rule_numbers(run_audit):
    report = run_audit("shadowed.json")
    found = findings_for(report, "shadowed-deny")
    assert len(found) == 1
    assert found[0]["severity"] == CRITICAL
    assert found[0]["rule_number"] == 200
    assert "rule 100" in found[0]["message"]


def test_shadowed_allow_is_only_warn(run_audit):
    report = run_audit("shadowed.json")
    found = findings_for(report, "shadowed-entry")
    assert [f["rule_number"] for f in found] == [300]
    assert found[0]["severity"] == WARN


def test_open_admin_port_is_critical(run_audit):
    report = run_audit("exposure.json")
    found = findings_for(report, "open-admin-port")
    numbers = {f["rule_number"] for f in found}
    assert numbers == {100, 200}
    assert all(f["severity"] == CRITICAL for f in found)
    assert "22" in next(f["message"] for f in found if f["rule_number"] == 100)


def test_wide_open_range_is_warn(run_audit):
    report = run_audit("exposure.json")
    found = findings_for(report, "wide-open-range")
    assert [f["rule_number"] for f in found] == [200]
    assert found[0]["severity"] == WARN


def test_allow_all_protocols_from_anywhere_is_critical(run_audit):
    report = run_audit("exposure.json")
    found = findings_for(report, "open-all-protocols")
    assert [f["rule_number"] for f in found] == [400]
    assert found[0]["severity"] == CRITICAL


def test_the_mandatory_ephemeral_return_rule_is_not_reported_as_exposure(run_audit):
    # 1024-65535 contains 3306 and 3389, but a stateless ACL cannot work without it.
    report = run_audit("exposure.json")
    exposed = findings_for(report, "open-admin-port") + findings_for(report, "wide-open-range")
    assert 300 not in {f["rule_number"] for f in exposed}


def test_unattached_acl_is_warn(run_audit):
    report = run_audit("hygiene.json")
    found = findings_for(report, "unattached-acl")
    assert len(found) == 1
    assert found[0]["severity"] == WARN
    assert found[0]["acl_id"] == "acl-orphan"


def test_tight_rule_numbering_is_warn(run_audit):
    report = run_audit("hygiene.json")
    found = findings_for(report, "no-insertion-gap")
    assert [f["rule_number"] for f in found] == [101, 102]
    assert all(f["severity"] == WARN for f in found)


def test_min_rule_gap_zero_silences_the_numbering_rule(run_audit):
    report = run_audit("hygiene.json", Config(min_rule_gap=0))
    assert findings_for(report, "no-insertion-gap") == []


def test_entry_quota_warns_with_the_count(run_audit):
    report = run_audit("hygiene.json", Config(entry_quota=3))
    found = findings_for(report, "entry-quota-reached")
    assert len(found) == 1
    assert "3 inbound entries" in found[0]["message"]


def test_required_tags(run_audit):
    report = run_audit("clean.json", Config(require_tags=["Owner", "CostCentre"]))
    found = {f["acl_id"]: f for f in findings_for(report, "missing-tags")}
    assert set(found) == {"acl-clean", "acl-default6"}
    # acl-clean already carries Owner, so only the missing key is named.
    assert "CostCentre" in found["acl-clean"]["message"]
    assert "Owner" not in found["acl-clean"]["message"]
    assert "Owner, CostCentre" in found["acl-default6"]["message"]


def test_a_correct_acl_produces_nothing(run_audit):
    report = run_audit("clean.json")
    assert report["findings"] == []
    assert report["severity"] == OK
    assert report["counts"] == {CRITICAL: 0, WARN: 0}
    assert all(a["severity"] == OK for a in report["acls"])


def test_default_acl_with_no_subnets_is_left_alone(run_audit):
    report = run_audit("clean.json")
    default = next(a for a in report["acls"] if a["acl_id"] == "acl-default6")
    assert default["findings"] == []


# --- report shape ---------------------------------------------------------
def test_report_rolls_severity_up_per_acl_and_per_vpc(run_audit):
    report = run_audit("prod.json")
    acls = {a["acl_id"]: a for a in report["acls"]}
    assert acls["acl-0web"]["severity"] == OK
    assert acls["acl-0app"]["severity"] == CRITICAL
    assert acls["acl-0db"]["severity"] == CRITICAL
    assert acls["acl-0defsbx"]["severity"] == WARN
    vpcs = {v["vpc_id"]: v for v in report["vpcs"]}
    assert vpcs["vpc-0a1prod"]["severity"] == CRITICAL
    assert vpcs["vpc-0a1prod"]["cidr"] == "10.0.0.0/16"
    assert vpcs["vpc-0b2sbx"]["severity"] == CRITICAL


def test_per_entry_severity_is_reported(run_audit):
    report = run_audit("prod.json")
    app = next(a for a in report["acls"] if a["acl_id"] == "acl-0app")
    severities = {(e["rule_number"], e["direction"]): e["severity"] for e in app["entries"]}
    assert severities[(200, "inbound")] == CRITICAL
    assert severities[(100, "inbound")] == WARN


def test_multiple_regions_are_merged_into_one_report():
    payload = {"regions": {}}
    for name in ("clean.json", "partial_return.json"):
        payload["regions"].update(load(name)["regions"])
    report = audit(parse_payload(payload), Config())
    assert report["regions"] == ["eu-central-1", "eu-west-1"]
    assert {a["region"] for a in report["acls"]} == {"eu-central-1", "eu-west-1"}
    assert report["severity"] == CRITICAL
