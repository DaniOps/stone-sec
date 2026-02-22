from pathlib import Path
from typing import List, Type
import ast

from stone_sec.models.finding import Finding
from stone_sec.engine.rules.eval_rule import EvalUsageRule, PickleLoadsRule, WeakHashRule
from stone_sec.engine.rules.os_system_rule import OsSystemRule, TempfileMktempRule
from stone_sec.engine.rules.subprocess_shell_rule import SubprocessShellRule, YamlUnsafeLoadRule
from stone_sec.engine.rules.exec_rule import ExecUsageRule
from stone_sec.engine.rules.deserialization_rules import (
    DillLoadRule,
    JoblibLoadRule,
    JsonpickleDecodeRule,
    MarshalLoadsRule,
    NumpyAllowPickleRule,
    PandasReadPickleRule,
    TorchLoadRule,
    YamlUnsafeDirectLoadRule,
)
from stone_sec.engine.rules.network_tls_rules import (
    InsecureTLSVerifyRule,
    SSLUnverifiedContextRule,
)
from stone_sec.engine.rules.insecure_protocol_rules import FTPUsageRule, TelnetUsageRule


RULES: List[Type[ast.NodeVisitor]] = [
    EvalUsageRule,
    ExecUsageRule,
    OsSystemRule,
    SubprocessShellRule,
    PickleLoadsRule,
    YamlUnsafeLoadRule,
    YamlUnsafeDirectLoadRule,
    TempfileMktempRule,
    WeakHashRule,
    MarshalLoadsRule,
    DillLoadRule,
    JsonpickleDecodeRule,
    NumpyAllowPickleRule,
    PandasReadPickleRule,
    TorchLoadRule,
    JoblibLoadRule,
    InsecureTLSVerifyRule,
    SSLUnverifiedContextRule,
    TelnetUsageRule,
    FTPUsageRule,
]


def run_rules(tree: ast.AST, file_path: Path) -> List[Finding]:
    findings: List[Finding] = []

    for rule_cls in RULES:
        rule = rule_cls(file_path)
        rule.visit(tree)
        findings.extend(rule.findings)

    return findings
