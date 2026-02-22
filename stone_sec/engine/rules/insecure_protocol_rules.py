import ast
from pathlib import Path
from typing import List, Set

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class TelnetUsageRule(ast.NodeVisitor):
    RULE_ID = "PY-TELNET-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.telnetlib_aliases: Set[str] = set()
        self.telnet_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "telnetlib":
                self.telnetlib_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "telnetlib":
            for alias in node.names:
                if alias.name == "Telnet":
                    self.telnet_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.telnetlib_aliases
            and node.func.attr == "Telnet"
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.telnet_names)

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of insecure telnetlib.Telnet",
                    snippet="telnetlib.Telnet(...)",
                )
            )

        self.generic_visit(node)


class FTPUsageRule(ast.NodeVisitor):
    RULE_ID = "PY-FTP-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.ftplib_aliases: Set[str] = set()
        self.ftp_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "ftplib":
                self.ftplib_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "ftplib":
            for alias in node.names:
                if alias.name == "FTP":
                    self.ftp_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.ftplib_aliases
            and node.func.attr == "FTP"
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.ftp_names)

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.MEDIUM,
                    title="Use of cleartext ftplib.FTP",
                    snippet="ftplib.FTP(...)",
                )
            )

        self.generic_visit(node)
