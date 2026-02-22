import ast
from pathlib import Path
from typing import List, Optional, Set

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


class PickleLoadsRule(ast.NodeVisitor):
    """
    Detects usage of pickle.loads().
    """

    RULE_ID = "PY-PICKLE-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.pickle_aliases: Set[str] = set()
        self.loads_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "pickle":
                self.pickle_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "pickle":
            for alias in node.names:
                if alias.name == "loads":
                    self.loads_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_pickle_loads = False

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.pickle_aliases
            and node.func.attr == "loads"
        ):
            is_pickle_loads = True

        if isinstance(node.func, ast.Name) and node.func.id in self.loads_names:
            is_pickle_loads = True

        if is_pickle_loads:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of insecure pickle.loads()",
                    snippet="pickle.loads(...)",
                )
            )

        self.generic_visit(node)


class WeakHashRule(ast.NodeVisitor):
    """
    Detects weak crypto usage: hashlib.md5, hashlib.sha1, hashlib.new("md5"/"sha1").
    """

    RULE_ID = "PY-CRYPTO-001"
    WEAK_ALGOS = {"md5", "sha1"}

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.hashlib_aliases: Set[str] = set()
        self.md5_names: Set[str] = set()
        self.sha1_names: Set[str] = set()
        self.new_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "hashlib":
                self.hashlib_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "hashlib":
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name == "md5":
                    self.md5_names.add(local_name)
                elif alias.name == "sha1":
                    self.sha1_names.add(local_name)
                elif alias.name == "new":
                    self.new_names.add(local_name)
        self.generic_visit(node)

    def _get_new_algo_name(self, node: ast.Call) -> Optional[str]:
        if not node.args:
            return None
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.lower()
        return None

    def visit_Call(self, node: ast.Call):
        is_weak_hash = False

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.hashlib_aliases
        ):
            if node.func.attr in {"md5", "sha1"}:
                is_weak_hash = True
            elif node.func.attr == "new":
                algo = self._get_new_algo_name(node)
                if algo in self.WEAK_ALGOS:
                    is_weak_hash = True

        if isinstance(node.func, ast.Name):
            if node.func.id in self.md5_names or node.func.id in self.sha1_names:
                is_weak_hash = True
            elif node.func.id in self.new_names:
                algo = self._get_new_algo_name(node)
                if algo in self.WEAK_ALGOS:
                    is_weak_hash = True

        if is_weak_hash:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.MEDIUM,
                    title="Use of weak hash algorithm (MD5/SHA1)",
                    snippet="hashlib.md5(...) / hashlib.sha1(...) / hashlib.new('md5'|'sha1', ...)",
                )
            )

        self.generic_visit(node)
