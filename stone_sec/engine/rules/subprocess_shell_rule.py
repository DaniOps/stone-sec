import ast
from pathlib import Path
from typing import List, Set

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


class YamlUnsafeLoadRule(ast.NodeVisitor):
    """
    Detects yaml.load(...) usage without a safe loader.
    Safe loaders accepted: yaml.SafeLoader, yaml.CSafeLoader.
    """

    RULE_ID = "PY-YAML-001"
    SAFE_LOADER_ATTRS = {"SafeLoader", "CSafeLoader"}

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.yaml_aliases: Set[str] = set()
        self.yaml_load_names: Set[str] = set()
        self.safe_loader_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "yaml":
                self.yaml_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "yaml":
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name == "load":
                    self.yaml_load_names.add(local_name)
                if alias.name in self.SAFE_LOADER_ATTRS:
                    self.safe_loader_names.add(local_name)
        self.generic_visit(node)

    def _is_safe_loader_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.safe_loader_names

        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in self.yaml_aliases
            and node.attr in self.SAFE_LOADER_ATTRS
        ):
            return True

        return False

    def visit_Assign(self, node: ast.Assign):
        # Track aliases like LOADER = yaml.SafeLoader or LOADER = SafeLoader
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if self._is_safe_loader_expr(node.value):
                self.safe_loader_names.add(node.targets[0].id)
        self.generic_visit(node)

    def _is_yaml_load_call(self, node: ast.Call) -> bool:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.yaml_aliases
            and node.func.attr == "load"
        ):
            return True
        if isinstance(node.func, ast.Name) and node.func.id in self.yaml_load_names:
            return True
        return False

    def _extract_loader_arg(self, node: ast.Call):
        for keyword in node.keywords:
            if keyword.arg == "Loader":
                return keyword.value
        if len(node.args) >= 2:
            return node.args[1]
        return None

    def visit_Call(self, node: ast.Call):
        if self._is_yaml_load_call(node):
            loader_arg = self._extract_loader_arg(node)
            unsafe = loader_arg is None or not self._is_safe_loader_expr(loader_arg)

            if unsafe:
                self.findings.append(
                    Finding(
                        file=self.file_path,
                        line=node.lineno,
                        rule_id=self.RULE_ID,
                        severity=Severity.HIGH,
                        title="Use of yaml.load() without safe loader",
                        snippet="yaml.load(...)",
                    )
                )

        self.generic_visit(node)
