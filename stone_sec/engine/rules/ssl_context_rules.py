import ast
from pathlib import Path
from typing import List, Set

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class SSLContextWeakConfigRule(ast.NodeVisitor):
    """
    Detects weak SSL context settings:
    - ctx.check_hostname = False
    - ctx.verify_mode = ssl.CERT_NONE
    """

    RULE_ID_CHECK_HOSTNAME = "PY-SSLCTX-001"
    RULE_ID_VERIFY_MODE = "PY-SSLCTX-002"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.ssl_aliases: Set[str] = set()
        self.cert_none_names: Set[str] = set()
        self.ssl_context_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "ssl":
                self.ssl_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "ssl":
            for alias in node.names:
                if alias.name == "CERT_NONE":
                    self.cert_none_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _is_ssl_context_ctor(self, call: ast.Call) -> bool:
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            if call.func.value.id in self.ssl_aliases and call.func.attr in {
                "SSLContext",
                "create_default_context",
            }:
                return True
        return False

    def _is_cert_none_expr(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name) and expr.id in self.cert_none_names:
            return True
        if (
            isinstance(expr, ast.Attribute)
            and isinstance(expr.value, ast.Name)
            and expr.value.id in self.ssl_aliases
            and expr.attr == "CERT_NONE"
        ):
            return True
        return False

    def visit_Assign_target(self, target: ast.Attribute, value: ast.AST, lineno: int):
        if not isinstance(target.value, ast.Name):
            return
        if target.value.id not in self.ssl_context_names:
            return

        if (
            target.attr == "check_hostname"
            and isinstance(value, ast.Constant)
            and value.value is False
        ):
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=lineno,
                    rule_id=self.RULE_ID_CHECK_HOSTNAME,
                    severity=Severity.HIGH,
                    title="SSL context has check_hostname disabled",
                    snippet="ctx.check_hostname = False",
                )
            )

        if target.attr == "verify_mode" and self._is_cert_none_expr(value):
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=lineno,
                    rule_id=self.RULE_ID_VERIFY_MODE,
                    severity=Severity.HIGH,
                    title="SSL context verify_mode set to CERT_NONE",
                    snippet="ctx.verify_mode = ssl.CERT_NONE",
                )
            )

    def visit_Assign(self, node: ast.Assign):  # type: ignore[override]
        # First pass: track context variables.
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and self._is_ssl_context_ctor(node.value)
        ):
            self.ssl_context_names.add(node.targets[0].id)

        # Second pass: detect weak config writes.
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                self.visit_Assign_target(target, node.value, node.lineno)

        self.generic_visit(node)
