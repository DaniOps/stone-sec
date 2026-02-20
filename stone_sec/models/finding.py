from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from stone_sec.engine.severity import Severity


@dataclass
class Finding:
    file: Path
    line: int
    rule_id: str
    severity: Severity
    title: str
    snippet: str

    explanation: Optional[str] = None
    exploit_scenario: Optional[str] = None
    remediation: Optional[str] = None