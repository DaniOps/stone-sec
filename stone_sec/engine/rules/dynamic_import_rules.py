import ast
from pathlib import Path
from typing import List, Set

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class BuiltinDynamicImportRule(ast.NodeVisitor):
    """
    Detects __import__(...) where module argument is non-literal.
    """

    RULE_ID = "PY-IMPORT-DYN-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            if node.args and not (
                isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                self.findings.append(
                    Finding(
                        file=self.file_path,
                        line=node.lineno,
                        rule_id=self.RULE_ID,
                        severity=Severity.MEDIUM,
                        title="Dynamic __import__ with non-literal module name",
                        snippet="__import__(dynamic_name)",
                    )
                )
        self.generic_visit(node)


class ImportlibDynamicImportRule(ast.NodeVisitor):
    """
    Detects importlib.import_module(...) where module argument is non-literal.
    """

    RULE_ID = "PY-IMPORT-DYN-002"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.importlib_aliases: Set[str] = set()
        self.import_module_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "importlib":
                self.importlib_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    self.import_module_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _is_non_literal_module_arg(self, node: ast.Call) -> bool:
        if not node.args:
            return False
        first = node.args[0]
        return not (isinstance(first, ast.Constant) and isinstance(first.value, str))

    def visit_Call(self, node: ast.Call):
        is_target = False

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.importlib_aliases
            and node.func.attr == "import_module"
        ):
            is_target = True

        if isinstance(node.func, ast.Name) and node.func.id in self.import_module_names:
            is_target = True

        if is_target and self._is_non_literal_module_arg(node):
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.MEDIUM,
                    title="Dynamic importlib.import_module with non-literal module name",
                    snippet="importlib.import_module(dynamic_name)",
                )
            )

        self.generic_visit(node)
