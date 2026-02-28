import ast
import unittest
from pathlib import Path

from stone_sec.engine.rules.dynamic_import_rules import (
    BuiltinDynamicImportRule,
    ImportlibDynamicImportRule,
)


class DynamicImportRuleTests(unittest.TestCase):
    def run_rule(self, rule_cls, source: str):
        tree = ast.parse(source, filename="sample.py")
        rule = rule_cls(Path("sample.py"))
        rule.visit(tree)
        return rule.findings

    def test_builtin_dynamic_import_triggers(self):
        findings = self.run_rule(BuiltinDynamicImportRule, "__import__(module_name)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-IMPORT-DYN-001")

    def test_builtin_literal_import_does_not_trigger(self):
        findings = self.run_rule(BuiltinDynamicImportRule, "__import__('os')\n")
        self.assertEqual(len(findings), 0)

    def test_importlib_dynamic_import_triggers(self):
        findings = self.run_rule(
            ImportlibDynamicImportRule,
            "import importlib\nimportlib.import_module(module_name)\n",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-IMPORT-DYN-002")

    def test_importlib_literal_import_does_not_trigger(self):
        findings = self.run_rule(
            ImportlibDynamicImportRule,
            "from importlib import import_module\nimport_module('json')\n",
        )
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
