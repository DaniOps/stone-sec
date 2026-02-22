import ast
from pathlib import Path
from typing import List, Set

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


class TempfileMktempRule(ast.NodeVisitor):
    """
    Detects usage of tempfile.mktemp().
    """

    RULE_ID = "PY-TEMPFILE-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tempfile_aliases: Set[str] = set()
        self.mktemp_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "tempfile":
                self.tempfile_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "tempfile":
            for alias in node.names:
                if alias.name == "mktemp":
                    self.mktemp_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_mktemp = False

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.tempfile_aliases
            and node.func.attr == "mktemp"
        ):
            is_mktemp = True

        if isinstance(node.func, ast.Name) and node.func.id in self.mktemp_names:
            is_mktemp = True

        if is_mktemp:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of insecure tempfile.mktemp()",
                    snippet="tempfile.mktemp(...)",
                )
            )

        self.generic_visit(node)
