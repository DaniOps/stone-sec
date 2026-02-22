import ast
from pathlib import Path
from typing import List, Set

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class InsecureTLSVerifyRule(ast.NodeVisitor):
    RULE_ID = "PY-TLS-VERIFY-001"
    CLIENT_METHODS = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
    }

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.requests_aliases: Set[str] = set()
        self.httpx_aliases: Set[str] = set()
        self.direct_client_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local_name = alias.asname or alias.name
            if alias.name == "requests":
                self.requests_aliases.add(local_name)
            elif alias.name == "httpx":
                self.httpx_aliases.add(local_name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module in {"requests", "httpx"}:
            for alias in node.names:
                if alias.name in self.CLIENT_METHODS:
                    self.direct_client_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _has_verify_false(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "verify":
                return isinstance(kw.value, ast.Constant) and kw.value.value is False
        return False

    def visit_Call(self, node: ast.Call):
        is_client_call = False

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if (
                node.func.value.id in self.requests_aliases
                and node.func.attr in self.CLIENT_METHODS
            ):
                is_client_call = True
            if (
                node.func.value.id in self.httpx_aliases
                and node.func.attr in self.CLIENT_METHODS
            ):
                is_client_call = True

        if isinstance(node.func, ast.Name) and node.func.id in self.direct_client_names:
            is_client_call = True

        if is_client_call and self._has_verify_false(node):
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="HTTP request with TLS verification disabled",
                    snippet="requests/httpx call with verify=False",
                )
            )

        self.generic_visit(node)


class SSLUnverifiedContextRule(ast.NodeVisitor):
    RULE_ID = "PY-SSL-UNVERIFIED-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.ssl_aliases: Set[str] = set()
        self.unverified_context_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "ssl":
                self.ssl_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "ssl":
            for alias in node.names:
                if alias.name == "_create_unverified_context":
                    self.unverified_context_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.ssl_aliases
            and node.func.attr == "_create_unverified_context"
        ) or (
            isinstance(node.func, ast.Name)
            and node.func.id in self.unverified_context_names
        )

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of ssl._create_unverified_context()",
                    snippet="ssl._create_unverified_context(...)",
                )
            )

        self.generic_visit(node)
