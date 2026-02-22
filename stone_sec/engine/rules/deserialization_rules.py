import ast
from pathlib import Path
from typing import List, Set

from stone_sec.engine.severity import Severity
from stone_sec.models.finding import Finding


class MarshalLoadsRule(ast.NodeVisitor):
    RULE_ID = "PY-MARSHAL-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.marshal_aliases: Set[str] = set()
        self.loads_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "marshal":
                self.marshal_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "marshal":
            for alias in node.names:
                if alias.name == "loads":
                    self.loads_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.marshal_aliases
            and node.func.attr == "loads"
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.loads_names)

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of insecure marshal.loads()",
                    snippet="marshal.loads(...)",
                )
            )

        self.generic_visit(node)


class DillLoadRule(ast.NodeVisitor):
    RULE_ID = "PY-DILL-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.dill_aliases: Set[str] = set()
        self.loads_names: Set[str] = set()
        self.load_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "dill":
                self.dill_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "dill":
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name == "loads":
                    self.loads_names.add(local_name)
                elif alias.name == "load":
                    self.load_names.add(local_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = False

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.dill_aliases
            and node.func.attr in {"loads", "load"}
        ):
            is_match = True

        if isinstance(node.func, ast.Name) and (
            node.func.id in self.loads_names or node.func.id in self.load_names
        ):
            is_match = True

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of insecure dill deserialization",
                    snippet="dill.load(...) / dill.loads(...)",
                )
            )

        self.generic_visit(node)


class JsonpickleDecodeRule(ast.NodeVisitor):
    RULE_ID = "PY-JSONPICKLE-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.jsonpickle_aliases: Set[str] = set()
        self.decode_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "jsonpickle":
                self.jsonpickle_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "jsonpickle":
            for alias in node.names:
                if alias.name == "decode":
                    self.decode_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.jsonpickle_aliases
            and node.func.attr == "decode"
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.decode_names)

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of insecure jsonpickle.decode()",
                    snippet="jsonpickle.decode(...)",
                )
            )

        self.generic_visit(node)


class YamlUnsafeDirectLoadRule(ast.NodeVisitor):
    RULE_ID = "PY-YAML-002"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.yaml_aliases: Set[str] = set()
        self.bad_load_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "yaml":
                self.yaml_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "yaml":
            for alias in node.names:
                if alias.name in {"full_load", "unsafe_load"}:
                    self.bad_load_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.yaml_aliases
            and node.func.attr in {"full_load", "unsafe_load"}
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.bad_load_names)

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of unsafe YAML loader",
                    snippet="yaml.full_load(...) / yaml.unsafe_load(...)",
                )
            )

        self.generic_visit(node)


class NumpyAllowPickleRule(ast.NodeVisitor):
    RULE_ID = "PY-NUMPY-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.numpy_aliases: Set[str] = set()
        self.load_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "numpy":
                self.numpy_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "numpy":
            for alias in node.names:
                if alias.name == "load":
                    self.load_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _has_allow_pickle_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "allow_pickle":
                return isinstance(kw.value, ast.Constant) and kw.value.value is True
        return False

    def visit_Call(self, node: ast.Call):
        is_numpy_load = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.numpy_aliases
            and node.func.attr == "load"
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.load_names)

        if is_numpy_load and self._has_allow_pickle_true(node):
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of numpy.load(..., allow_pickle=True)",
                    snippet="numpy.load(..., allow_pickle=True)",
                )
            )

        self.generic_visit(node)


class PandasReadPickleRule(ast.NodeVisitor):
    RULE_ID = "PY-PANDAS-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.pandas_aliases: Set[str] = set()
        self.read_pickle_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "pandas":
                self.pandas_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "pandas":
            for alias in node.names:
                if alias.name == "read_pickle":
                    self.read_pickle_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.pandas_aliases
            and node.func.attr == "read_pickle"
        ) or (
            isinstance(node.func, ast.Name) and node.func.id in self.read_pickle_names
        )

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of insecure pandas.read_pickle()",
                    snippet="pandas.read_pickle(...)",
                )
            )

        self.generic_visit(node)


class TorchLoadRule(ast.NodeVisitor):
    RULE_ID = "PY-TORCH-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.torch_aliases: Set[str] = set()
        self.load_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "torch":
                self.torch_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "torch":
            for alias in node.names:
                if alias.name == "load":
                    self.load_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.torch_aliases
            and node.func.attr == "load"
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.load_names)

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of potentially unsafe torch.load()",
                    snippet="torch.load(...)",
                )
            )

        self.generic_visit(node)


class JoblibLoadRule(ast.NodeVisitor):
    RULE_ID = "PY-JOBLIB-001"

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.joblib_aliases: Set[str] = set()
        self.load_names: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "joblib":
                self.joblib_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "joblib":
            for alias in node.names:
                if alias.name == "load":
                    self.load_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        is_match = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.joblib_aliases
            and node.func.attr == "load"
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.load_names)

        if is_match:
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    rule_id=self.RULE_ID,
                    severity=Severity.HIGH,
                    title="Use of potentially unsafe joblib.load()",
                    snippet="joblib.load(...)",
                )
            )

        self.generic_visit(node)
