from pathlib import Path
from typing import List, Type
import ast

from stone_sec.models.finding import Finding
from stone_sec.engine.rules.eval_rule import EvalUsageRule, PickleLoadsRule, WeakHashRule
from stone_sec.engine.rules.os_system_rule import OsSystemRule, TempfileMktempRule
from stone_sec.engine.rules.subprocess_shell_rule import SubprocessShellRule, YamlUnsafeLoadRule


RULES: List[Type[ast.NodeVisitor]] = [
    EvalUsageRule,
    OsSystemRule,
    SubprocessShellRule,
    PickleLoadsRule,
    YamlUnsafeLoadRule,
    TempfileMktempRule,
    WeakHashRule,
]


def run_rules(tree: ast.AST, file_path: Path) -> List[Finding]:
    findings: List[Finding] = []

    for rule_cls in RULES:
        rule = rule_cls(file_path)
        rule.visit(tree)
        findings.extend(rule.findings)

    return findings
