import ast
import unittest
from pathlib import Path

from stone_sec.engine.rules.exec_rule import ExecUsageRule


class ExecUsageRuleTests(unittest.TestCase):
    def run_rule(self, source: str):
        tree = ast.parse(source, filename="sample.py")
        rule = ExecUsageRule(Path("sample.py"))
        rule.visit(tree)
        return rule.findings

    def test_exec_triggers(self):
        findings = self.run_rule("exec('print(1)')\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-EXEC-001")

    def test_non_exec_does_not_trigger(self):
        findings = self.run_rule("print('ok')\n")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
