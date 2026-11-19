import pytest

from aws_nacl_audit.netmath import (
    ALL_PORTS,
    NetmathError,
    cidr_contains,
    covers_range,
    format_range,
    format_ranges,
    is_any_cidr,
    merge_ranges,
    parse_port_range,
    proto_covers,
    proto_name,
    range_intersect,
    range_subtract,
    range_width,
    ranges_overlap,
)


def test_cidr_contains_supersets():
    assert cidr_contains("10.0.0.0/8", "10.0.1.0/24")
    assert cidr_contains("0.0.0.0/0", "203.0.113.7/32")
    assert not cidr_contains("10.0.1.0/24", "10.0.0.0/8")


def test_cidr_contains_never_crosses_address_family():
    # An IPv4 outbound rule is not a return path for IPv6 traffic.
    assert not cidr_contains("0.0.0.0/0", "::/0")
    assert not cidr_contains("::/0", "0.0.0.0/0")
    assert cidr_contains("::/0", "2001:db8::/32")


def test_cidr_contains_handles_missing_sides():
    assert not cidr_contains(None, "10.0.0.0/8")
    assert not cidr_contains("10.0.0.0/8", None)


def test_is_any_cidr():
    assert is_any_cidr("0.0.0.0/0")
    assert is_any_cidr("::/0")
    assert not is_any_cidr("10.0.0.0/8")
    assert not is_any_cidr(None)


@pytest.mark.parametrize(
    "text,expected",
    [("443", (443, 443)), ("1024-65535", (1024, 65535)), (" 80 - 81 ", (80, 81))],
)
def test_parse_port_range(text, expected):
    assert parse_port_range(text) == expected


@pytest.mark.parametrize("bad", ["", "70000", "100-20", "http-80", "-", "1-"])
def test_parse_port_range_rejects_junk(bad):
    with pytest.raises(NetmathError):
        parse_port_range(bad)


def test_range_subtract_leaves_the_uncovered_part():
    assert range_subtract((1024, 65535), [(1024, 32767)]) == [(32768, 65535)]
    assert range_subtract((1024, 65535), [(1024, 65535)]) == []
    assert range_subtract((1024, 65535), []) == [(1024, 65535)]


def test_range_subtract_splits_a_hole_in_the_middle():
    assert range_subtract((1000, 2000), [(1200, 1300)]) == [(1000, 1199), (1301, 2000)]


def test_merge_ranges_joins_adjacent():
    assert merge_ranges([(443, 443), (444, 450), (1024, 2000)]) == [(443, 450), (1024, 2000)]


def test_range_helpers():
    assert range_intersect((1, 10), (5, 20)) == (5, 10)
    assert range_intersect((1, 10), (11, 20)) is None
    assert ranges_overlap((3000, 4000), (3306, 3306))
    assert covers_range((1024, 65535), (3306, 3306))
    assert not covers_range((3306, 3306), (1024, 65535))
    assert range_width((1024, 65535)) == 64512


def test_proto_covers_and_names():
    assert proto_covers("-1", "6")
    assert proto_covers("6", "6")
    assert not proto_covers("6", "17")
    assert proto_name("6") == "tcp"
    assert proto_name("99") == "proto 99"


def test_format_helpers():
    assert format_range(ALL_PORTS) == "all"
    assert format_range((443, 443)) == "443"
    assert format_ranges([(1, 2), (5, 5)]) == "1-2, 5"
    assert format_ranges([]) == "none"
