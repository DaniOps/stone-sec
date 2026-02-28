import ast
from pathlib import Path
from typing import List

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class SQLStringInterpolationRule(ast.NodeVisitor):
    """
    Detects SQL execution calls using string interpolation patterns.
    """

    RULE_ID = "PY-SQL-001"
    SQL_SINKS = {"execute", "executemany"}

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def _is_interpolated_sql_expr(self, expr: ast.AST) -> bool:
        # f"..."
        if isinstance(expr, ast.JoinedStr):
            return True

        # "..." + var
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            return True

        # "...{}".format(...)
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "format"
        ):
            return True

        return False

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in self.SQL_SINKS:
            if node.args and self._is_interpolated_sql_expr(node.args[0]):
                self.findings.append(
                    Finding(
                        file=self.file_path,
                        line=node.lineno,
                        rule_id=self.RULE_ID,
                        severity=Severity.HIGH,
                        title="Possible SQL injection via interpolated query string",
                        snippet="cursor.execute(f'...') / '+', '%', or .format() query building",
                    )
                )

        self.generic_visit(node)
