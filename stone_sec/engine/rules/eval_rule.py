import ast
from pathlib import Path
from typing import List

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class EvalUsageRule(ast.NodeVisitor):
    """
    Detects usage of eval().
    """

    RULE_ID = "PY-EVAL-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        # Check if function name is `eval`
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            snippet = "eval(...)"

            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of eval()",
                    snippet=snippet,
                )
            )

        self.generic_visit(node)