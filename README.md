# aws-nacl-audit

[![ci](https://github.com/moveeeax/aws-nacl-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-nacl-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Network ACLs are stateless, and nobody remembers that until a connection hangs.
The security group is right, the route table is right, the subnet is in the
right VPC, and the traffic still dies because the inbound rule for 443 exists
and the outbound rule for the ephemeral return range does not.

`aws-nacl-audit` reads every ACL in a region with three `describe` calls and
reports which ones actually filter traffic and which ones just hang up your
connections. No agent, no write permissions, no CloudFormation.

## What it checks

| Rule | Severity | What it catches |
| --- | --- | --- |
| `missing-return-path` | critical | An allow on a TCP/UDP port with no matching allow for the ephemeral range in the opposite direction. Prints the uncovered part of the range. |
| `shadowed-deny` | critical | A deny that can never be reached because a lower-numbered allow already matches a superset. It reads as enforcement and enforces nothing. |
| `shadowed-entry` | warn | Any other entry made dead text by a lower-numbered rule. |
| `open-admin-port` | critical | An inbound allow from `0.0.0.0/0` or `::/0` that reaches 22, 3389, 3306, 5432, 6379 or 27017. |
| `open-all-protocols` | critical | An inbound `protocol -1` allow from anywhere. |
| `wide-open-range` | warn | An inbound allow from anywhere spanning more than `--max-open-ports`. |
| `default-acl-subnet` | warn | A subnet associated with the VPC default ACL, which allows everything both ways. |
| `default-acl-allow-all` | warn | A default ACL still carrying its factory allow-all entries while serving subnets. |
| `unattached-acl` | warn | An ACL associated with no subnet: dead configuration. |
| `no-insertion-gap` | warn | Consecutive rule numbers closer than `--min-rule-gap`, so the next change has to renumber live rules. |
| `entry-quota-reached` | warn | An ACL at or over the per-direction entry quota. |
| `missing-tags` | warn | An ACL missing a key from `--require-tags`. |

## Install

```bash
pip install git+https://github.com/moveeeax/aws-nacl-audit.git
```

Needs Python 3.11+ and `ec2:DescribeNetworkAcls`, `ec2:DescribeSubnets`,
`ec2:DescribeVpcs`. Nothing else, and nothing that writes.

## Usage

```bash
aws-nacl-audit --region eu-central-1
aws-nacl-audit --regions eu-central-1,eu-west-1 --fail-on critical
aws-nacl-audit --ephemeral-range 32768-60999 --format json | jq '.acls[] | select(.severity=="critical")'
aws-nacl-audit --from-json examples/prod.json --format markdown
```

Against the bundled example payload:

```console
$ aws-nacl-audit --from-json examples/prod.json
aws-nacl-audit 0.1.0 — regions: eu-central-1
ephemeral return range: 1024-65535   critical: 4   warn: 6

eu-central-1  vpc-0a1prod 10.0.0.0/16  [critical]
  acl-0app 1 subnet(s)  [critical]
    [CRIT] shadowed-deny: acl-0app inbound deny rule 200 (10.0.0.0/16 tcp 3306) is unreachable: allow rule 50 already matches a superset. It reads as enforcement and enforces nothing.
    [WARN] shadowed-entry: acl-0app inbound rule 100 is dead text: rule 50 (allow) already matches a superset of its CIDR, protocol and ports
  acl-0db unattached  [critical]
    [CRIT] missing-return-path: acl-0db rule 100 allows inbound tcp 5432 from 10.0.2.0/24, but the outbound ephemeral range 1024-65535 is not fully allowed back: 1024-65535 uncovered. Connections will hang.
    [WARN] unattached-acl: acl-0db in vpc-0a1prod is associated with no subnet: dead configuration carrying 1 entry
  acl-0defprod (default) unattached  [ok]
    clean
  acl-0web 1 subnet(s)  [ok]
    clean
...
overall: critical
$ echo $?
1
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--region`, `--regions` | — | One region, or a comma-separated list to fan out over |
| `--profile` | — | AWS named profile |
| `--from-json PATH` | — | Replay a recorded payload; makes no AWS calls |
| `--dump-json PATH` | — | Record the collected payload for later replay |
| `--ephemeral-range` | `1024-65535` | Return range the stateless rules must allow back |
| `--max-open-ports` | `10` | Widest inbound range from anywhere before warning |
| `--min-rule-gap` | `10` | Minimum gap between consecutive rule numbers |
| `--entry-quota` | `20` | Per-ACL per-direction entry quota to warn at |
| `--require-tags` | — | Comma-separated tag keys every ACL must carry |
| `--rules PATH` | — | YAML overriding the thresholds above (see `examples/rules.yml`) |
| `--format` | `text` | `text`, `json` or `markdown` |
| `--fail-on` | `critical` | `warn`, `critical` or `none` |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` bad input. A
traceback is never a valid exit.

## How it works

Three `describe` calls build the topology — ACLs with their entries and subnet
associations, subnets for CIDRs and AZs, VPCs for names — and the collectors
hand over plain dicts shaped exactly like the EC2 API replies. Everything after
that is pure functions over those dicts, which is why `--dump-json` and
`--from-json` replay a run byte for byte and why the whole rule engine is tested
against JSON fixtures with no credentials and no `moto`.

The return-path check is the interesting one. It evaluates the opposite
direction the way the VPC does: walk entries in rule-number order and retire
each port of the ephemeral range as soon as the first matching entry decides it.
A broad allow at rule 100 therefore makes a deny at rule 200 irrelevant, and an
earlier deny punches a real hole in the return range. What is left undecided at
the end hits the implicit `*` deny, and whatever is not allowed is printed as
the uncovered range.

### The ephemeral-range exemption

`1024-65535` contains 3306, 3389, 5432 and 6379. A stateless ACL cannot work
without an inbound allow covering that range, so a naive admin-port check flags
every correctly configured ACL in the account. An entry that covers the *whole*
configured ephemeral range is treated as a return-path rule and exempted from
the exposure checks; a narrower entry that merely happens to include 3306 is
not. Set `--ephemeral-range 32768-60999` and an inbound `1024-65535` allow stops
being exempt, because it is then wider than the return path needs.

## CI

```yaml
- run: pip install git+https://github.com/moveeeax/aws-nacl-audit.git
- run: aws-nacl-audit --regions eu-central-1,eu-west-1 --fail-on critical --format markdown >> "$GITHUB_STEP_SUMMARY"
```

## Development

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && pytest -q
```

## License

MIT
