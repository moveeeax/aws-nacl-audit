import json

import pytest

from aws_nacl_audit import cli

from .conftest import EXAMPLES, FIXTURES


def run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_from_json_reproduces_a_full_run_offline(capsys):
    code, out, _ = run(["--from-json", str(EXAMPLES / "prod.json")], capsys)
    assert code == cli.EXIT_FINDINGS
    assert "acl-0web" in out
    assert "missing-return-path" in out
    assert "overall: critical" in out


def test_fail_on_critical_exits_one_only_for_critical(capsys):
    crit = ["--from-json", str(FIXTURES / "missing_return.json"), "--fail-on", "critical"]
    assert run(crit, capsys)[0] == cli.EXIT_FINDINGS

    warn_only = ["--from-json", str(FIXTURES / "hygiene.json"), "--fail-on", "critical"]
    assert run(warn_only, capsys)[0] == cli.EXIT_OK

    assert run(warn_only[:2] + ["--fail-on", "warn"], capsys)[0] == cli.EXIT_FINDINGS


def test_fail_on_none_always_exits_zero(capsys):
    argv = ["--from-json", str(EXAMPLES / "prod.json"), "--fail-on", "none"]
    assert run(argv, capsys)[0] == cli.EXIT_OK


def test_clean_input_exits_zero(capsys):
    code, out, _ = run(["--from-json", str(FIXTURES / "clean.json")], capsys)
    assert code == cli.EXIT_OK
    assert "clean" in out
    assert "overall: ok" in out


def test_json_output_is_parseable_and_jq_friendly(capsys):
    argv = ["--from-json", str(EXAMPLES / "prod.json"), "--format", "json"]
    code, out, _ = run(argv, capsys)
    assert code == cli.EXIT_FINDINGS
    doc = json.loads(out)
    critical = [a for a in doc["acls"] if a["severity"] == "critical"]
    assert {a["acl_id"] for a in critical} == {"acl-0app", "acl-0db", "acl-0mgmt"}
    assert doc["config"]["ephemeral_range"] == "1024-65535"
    assert doc["counts"]["critical"] > 0


def test_markdown_output_has_a_table_row_per_finding(capsys):
    argv = ["--from-json", str(EXAMPLES / "prod.json"), "--format", "markdown"]
    _, out, _ = run(argv, capsys)
    assert out.startswith("## aws-nacl-audit")
    rows = [line for line in out.splitlines() if line.startswith("| 🔴") or line.startswith("| 🟡")]
    assert len(rows) == len(json.loads(run(argv[:2] + ["--format", "json"], capsys)[1])["findings"])


def test_markdown_says_so_when_there_is_nothing_to_report(capsys):
    argv = ["--from-json", str(FIXTURES / "clean.json"), "--format", "markdown"]
    _, out, _ = run(argv, capsys)
    assert "No findings" in out


def test_malformed_payload_exits_two_without_a_traceback(capsys):
    code, _, err = run(["--from-json", str(FIXTURES / "malformed.json")], capsys)
    assert code == cli.EXIT_USAGE
    assert "no 'regions' object" in err
    assert "Traceback" not in err


def test_unreadable_payload_exits_two(capsys, tmp_path):
    code, _, err = run(["--from-json", str(tmp_path / "nope.json")], capsys)
    assert code == cli.EXIT_USAGE
    assert "cannot read" in err


def test_invalid_json_exits_two(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    code, _, err = run(["--from-json", str(bad)], capsys)
    assert code == cli.EXIT_USAGE
    assert "not valid JSON" in err


def test_no_source_exits_two(capsys):
    code, _, err = run([], capsys)
    assert code == cli.EXIT_USAGE
    assert "--region" in err


def test_bad_ephemeral_range_exits_two(capsys):
    argv = ["--from-json", str(FIXTURES / "clean.json"), "--ephemeral-range", "99999"]
    code, _, err = run(argv, capsys)
    assert code == cli.EXIT_USAGE
    assert "outside 0-65535" in err


def test_rules_file_sets_the_baseline(capsys, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("min_rule_gap: 0\nentry_quota: 3\n", encoding="utf-8")
    argv = ["--from-json", str(FIXTURES / "hygiene.json"), "--rules", str(rules),
            "--format", "json"]
    _, out, _ = run(argv, capsys)
    doc = json.loads(out)
    rules_hit = {f["rule"] for f in doc["findings"]}
    assert "no-insertion-gap" not in rules_hit
    assert "entry-quota-reached" in rules_hit


def test_an_explicit_flag_overrides_the_rules_file(capsys, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("min_rule_gap: 0\n", encoding="utf-8")
    argv = ["--from-json", str(FIXTURES / "hygiene.json"), "--rules", str(rules),
            "--min-rule-gap", "5", "--format", "json"]
    _, out, _ = run(argv, capsys)
    doc = json.loads(out)
    assert "no-insertion-gap" in {f["rule"] for f in doc["findings"]}


def test_bad_rules_file_exits_two(capsys, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("min_rule_gap: [1, 2]\n", encoding="utf-8")
    argv = ["--from-json", str(FIXTURES / "clean.json"), "--rules", str(rules)]
    code, _, err = run(argv, capsys)
    assert code == cli.EXIT_USAGE
    assert "min_rule_gap must be an integer" in err


def test_unknown_rules_key_exits_two(capsys, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("ephemeral_rage: 1024-65535\n", encoding="utf-8")
    argv = ["--from-json", str(FIXTURES / "clean.json"), "--rules", str(rules)]
    code, _, err = run(argv, capsys)
    assert code == cli.EXIT_USAGE
    assert "unknown rules key" in err


def test_missing_rules_file_exits_two(capsys, tmp_path):
    argv = ["--from-json", str(FIXTURES / "clean.json"), "--rules", str(tmp_path / "nope.yml")]
    code, _, err = run(argv, capsys)
    assert code == cli.EXIT_USAGE
    assert "cannot read rules file" in err


def test_regions_flag_is_deduplicated():
    parser = cli.build_parser()
    args = parser.parse_args(["--regions", "eu-central-1, eu-west-1", "--region", "eu-west-1"])
    assert cli.resolve_regions(args) == ["eu-central-1", "eu-west-1"]


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "aws-nacl-audit" in capsys.readouterr().out
