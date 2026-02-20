import ast
from pathlib import Path
from typing import List

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class SubprocessShellRule(ast.NodeVisitor):
    """
    Detects subprocess calls with shell=True.
    """

    RULE_ID = "PY-SUBPROCESS-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        # Look for subprocess.* calls
        if isinstance(node.func, ast.Attribute):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        self.findings.append(
                            Finding(
                                file=self.file_path,
                                line=node.lineno,
                                rule_id=self.RULE_ID,
                                severity=Severity.HIGH,
                                title="subprocess call with shell=True",
                                snippet="subprocess(..., shell=True)",
                            )
                        )
                        break

        self.generic_visit(node)