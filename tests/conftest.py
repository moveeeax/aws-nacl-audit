import json
from pathlib import Path

import pytest

from aws_nacl_audit.config import Config
from aws_nacl_audit.model import parse_payload
from aws_nacl_audit.rules import audit

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = Path(__file__).parent.parent / "examples"


def load(name: str) -> dict:
    root = FIXTURES if (FIXTURES / name).exists() else EXAMPLES
    return json.loads((root / name).read_text(encoding="utf-8"))


@pytest.fixture
def run_audit():
    def _run(name: str, cfg: Config | None = None) -> dict:
        return audit(parse_payload(load(name)), cfg or Config())

    return _run


def findings_for(report: dict, rule: str):
    return [f for f in report["findings"] if f["rule"] == rule]
