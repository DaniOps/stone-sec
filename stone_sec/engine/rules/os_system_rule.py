import ast
from pathlib import Path
from typing import List

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class OsSystemRule(ast.NodeVisitor):
    """
    Detects usage of os.system().
    """

    RULE_ID = "PY-OS-SYSTEM-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        # Detect os.system(...)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "system"
        ):
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of os.system()",
                    snippet="os.system(...)",
                )
            )

        self.generic_visit(node)