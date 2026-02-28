import ast
import unittest
from pathlib import Path

from stone_sec.engine.rules.sql_injection_rules import SQLStringInterpolationRule


class SQLInjectionRuleTests(unittest.TestCase):
    def run_rule(self, source: str):
        tree = ast.parse(source, filename="sample.py")
        rule = SQLStringInterpolationRule(Path("sample.py"))
        rule.visit(tree)
        return rule.findings

    def test_fstring_execute_triggers(self):
        findings = self.run_rule("cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-SQL-001")

    def test_format_execute_triggers(self):
        findings = self.run_rule(
            "cursor.execute(\"SELECT * FROM users WHERE id = {}\".format(uid))\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-SQL-001")

    def test_parameterized_execute_does_not_trigger(self):
        findings = self.run_rule("cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n")
        self.assertEqual(len(findings), 0)

    def test_constant_query_does_not_trigger(self):
        findings = self.run_rule("cursor.execute(\"SELECT 1\")\n")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
