import ast
from pathlib import Path
from typing import List

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class ExecUsageRule(ast.NodeVisitor):
    """
    Detects usage of exec().
    """

    RULE_ID = "PY-EXEC-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "exec":
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of exec()",
                    snippet="exec(...)",
                )
            )

        self.generic_visit(node)
