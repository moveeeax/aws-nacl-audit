"""Audit thresholds, overridable from the CLI or a YAML file."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .netmath import NetmathError, Range, parse_port_range

# The return range that actually matters depends on the client: Linux picks
# 32768-60999, an NLB and most AWS-managed callers use 1024-65535. The wider
# AWS range is the safe default because it is a superset of what a Linux box
# will use.
DEFAULT_EPHEMERAL = (1024, 65535)

DEFAULT_ADMIN_PORTS = [22, 3389, 3306, 5432, 6379, 27017]

# Per-ACL quota is 20 entries per direction by default, raisable to 40.
DEFAULT_ENTRY_QUOTA = 20


class ConfigError(ValueError):
    """Raised for an unusable --rules file or threshold."""


@dataclass
class Config:
    ephemeral_range: Range = DEFAULT_EPHEMERAL
    admin_ports: list[int] = field(default_factory=lambda: list(DEFAULT_ADMIN_PORTS))
    max_open_ports: int = 10
    min_rule_gap: int = 10
    entry_quota: int = DEFAULT_ENTRY_QUOTA
    require_tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ephemeral_range"] = f"{self.ephemeral_range[0]}-{self.ephemeral_range[1]}"
        return d


def _as_int(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from exc


def from_mapping(raw: dict[str, Any]) -> Config:
    """Build a Config from a parsed YAML/JSON mapping."""
    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        raise ConfigError("rules file must contain a mapping at the top level")
    unknown = set(raw) - {
        "ephemeral_range",
        "admin_ports",
        "max_open_ports",
        "min_rule_gap",
        "entry_quota",
        "require_tags",
    }
    if unknown:
        raise ConfigError("unknown rules key(s): " + ", ".join(sorted(unknown)))

    cfg = Config()
    if "ephemeral_range" in raw:
        try:
            cfg.ephemeral_range = parse_port_range(raw["ephemeral_range"])
        except NetmathError as exc:
            raise ConfigError(str(exc)) from exc
    if "admin_ports" in raw:
        ports = raw["admin_ports"]
        if not isinstance(ports, list):
            raise ConfigError("admin_ports must be a list of port numbers")
        cfg.admin_ports = [_as_int(p, "admin_ports entry") for p in ports]
    if "max_open_ports" in raw:
        cfg.max_open_ports = _as_int(raw["max_open_ports"], "max_open_ports")
    if "min_rule_gap" in raw:
        cfg.min_rule_gap = _as_int(raw["min_rule_gap"], "min_rule_gap")
    if "entry_quota" in raw:
        cfg.entry_quota = _as_int(raw["entry_quota"], "entry_quota")
    if "require_tags" in raw:
        tags = raw["require_tags"]
        if not isinstance(tags, list):
            raise ConfigError("require_tags must be a list of tag keys")
        cfg.require_tags = [str(t) for t in tags]
    return cfg


def load_rules_file(path: str) -> Config:
    """Read a YAML (or JSON, which is valid YAML) rules override."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as exc:
        raise ConfigError(f"cannot read rules file {path}: {exc.strerror}") from exc
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - PyYAML is a hard dep
        raise ConfigError("PyYAML is required to read a --rules file") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    return from_mapping(raw)
