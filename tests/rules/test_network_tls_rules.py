import ast
import unittest
from pathlib import Path

from stone_sec.engine.rules.network_tls_rules import (
    InsecureTLSVerifyRule,
    SSLUnverifiedContextRule,
)


class NetworkTLSRuleTests(unittest.TestCase):
    def run_rule(self, rule_cls, source: str):
        tree = ast.parse(source, filename="sample.py")
        rule = rule_cls(Path("sample.py"))
        rule.visit(tree)
        return rule.findings

    def test_requests_verify_false_triggers(self):
        findings = self.run_rule(
            InsecureTLSVerifyRule, "import requests\nrequests.get(url, verify=False)\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-TLS-VERIFY-001")

    def test_httpx_verify_false_triggers(self):
        findings = self.run_rule(
            InsecureTLSVerifyRule, "import httpx\nhttpx.post(url, verify=False)\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-TLS-VERIFY-001")

    def test_verify_true_does_not_trigger(self):
        findings = self.run_rule(
            InsecureTLSVerifyRule, "import requests\nrequests.get(url, verify=True)\n"
        )
        self.assertEqual(len(findings), 0)

    def test_ssl_unverified_context_triggers(self):
        findings = self.run_rule(
            SSLUnverifiedContextRule, "import ssl\nssl._create_unverified_context()\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-SSL-UNVERIFIED-001")


if __name__ == "__main__":
    unittest.main()
