"""Command line entry point.

Exit codes: 0 clean (or --fail-on none), 1 findings at or above --fail-on,
2 bad input. A traceback is never a valid exit.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .collect import CollectError, collect
from .config import Config, ConfigError, load_rules_file
from .model import PayloadError, parse_payload
from .netmath import NetmathError, parse_port_range
from .report import render
from .rules import CRITICAL, SEVERITY_ORDER, WARN, audit

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-nacl-audit",
        description=(
            "Audit AWS network ACLs for missing stateless return paths, subnets left on "
            "the VPC default allow-all ACL, shadowed rules, open exposure and rule "
            "numbering with no room to insert."
        ),
    )
    p.add_argument("--version", action="version", version=f"aws-nacl-audit {__version__}")
    src = p.add_argument_group("source")
    src.add_argument("--region", help="single region to audit")
    src.add_argument("--regions", help="comma-separated regions to fan out over")
    src.add_argument("--profile", help="AWS named profile")
    src.add_argument("--from-json", metavar="PATH", help="replay a recorded payload, no AWS calls")
    src.add_argument("--dump-json", metavar="PATH", help="write the collected payload here")

    tune = p.add_argument_group("thresholds")
    tune.add_argument(
        "--ephemeral-range",
        help="return range the stateless rules must allow back (default 1024-65535)",
    )
    tune.add_argument("--max-open-ports", type=int,
                      help="widest inbound range from 0.0.0.0/0 before warning (default 10)")
    tune.add_argument("--min-rule-gap", type=int,
                      help="minimum gap between consecutive rule numbers (default 10)")
    tune.add_argument("--entry-quota", type=int,
                      help="per-ACL per-direction entry quota to warn at (default 20)")
    tune.add_argument("--require-tags", help="comma-separated tag keys every ACL must carry")
    tune.add_argument("--rules", metavar="PATH", help="YAML file overriding the thresholds above")

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    out.add_argument("--fail-on", choices=("warn", "critical", "none"), default="critical")
    return p


def resolve_regions(args: argparse.Namespace) -> list[str]:
    names: list[str] = []
    if args.regions:
        names += [r.strip() for r in args.regions.split(",") if r.strip()]
    if args.region:
        names.append(args.region.strip())
    seen, uniq = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def build_config(args: argparse.Namespace) -> Config:
    """A --rules file sets the baseline; an explicitly passed flag overrides it."""
    cfg = load_rules_file(args.rules) if args.rules else Config()
    if args.ephemeral_range is not None:
        cfg.ephemeral_range = parse_port_range(args.ephemeral_range)
    if args.max_open_ports is not None:
        cfg.max_open_ports = args.max_open_ports
    if args.min_rule_gap is not None:
        cfg.min_rule_gap = args.min_rule_gap
    if args.entry_quota is not None:
        cfg.entry_quota = args.entry_quota
    if args.require_tags:
        cfg.require_tags = [t.strip() for t in args.require_tags.split(",") if t.strip()]
    for name, value in (
        ("--max-open-ports", cfg.max_open_ports),
        ("--min-rule-gap", cfg.min_rule_gap),
        ("--entry-quota", cfg.entry_quota),
    ):
        if value < 0:
            raise ConfigError(f"{name} cannot be negative")
    return cfg


def load_from_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        raise PayloadError(f"cannot read {path}: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise PayloadError(f"{path} is not valid JSON: {exc}") from exc


def exit_code(severity: str, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_OK
    threshold = CRITICAL if fail_on == "critical" else WARN
    return EXIT_FINDINGS if SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold] else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        cfg = build_config(args)
    except (ConfigError, NetmathError) as exc:
        print(f"aws-nacl-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.from_json:
            payload = load_from_json(args.from_json)
        else:
            regions = resolve_regions(args)
            if not regions:
                print(
                    "aws-nacl-audit: pass --region, --regions or --from-json",
                    file=sys.stderr,
                )
                return EXIT_USAGE
            payload = collect(regions, args.profile)
            if args.dump_json:
                with open(args.dump_json, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, default=str)
        regions_parsed = parse_payload(payload)
    except (PayloadError, NetmathError) as exc:
        print(f"aws-nacl-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except CollectError as exc:
        print(f"aws-nacl-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"aws-nacl-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = audit(regions_parsed, cfg)
    print(render(report, args.format))
    return exit_code(report["severity"], args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
