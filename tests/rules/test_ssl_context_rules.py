import ast
import unittest
from pathlib import Path

from stone_sec.engine.rules.ssl_context_rules import SSLContextWeakConfigRule


class SSLContextRuleTests(unittest.TestCase):
    def run_rule(self, source: str):
        tree = ast.parse(source, filename="sample.py")
        rule = SSLContextWeakConfigRule(Path("sample.py"))
        rule.visit(tree)
        return rule.findings

    def test_check_hostname_false_triggers(self):
        findings = self.run_rule(
            "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-SSLCTX-001")

    def test_verify_mode_cert_none_triggers(self):
        findings = self.run_rule(
            "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nctx.verify_mode = ssl.CERT_NONE\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-SSLCTX-002")

    def test_verify_mode_cert_required_does_not_trigger(self):
        findings = self.run_rule(
            "import ssl\nctx = ssl.create_default_context()\nctx.verify_mode = ssl.CERT_REQUIRED\n"
        )
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
