import ast
import unittest
from pathlib import Path

from stone_sec.engine.rules.insecure_protocol_rules import FTPUsageRule, TelnetUsageRule


class InsecureProtocolRuleTests(unittest.TestCase):
    def run_rule(self, rule_cls, source: str):
        tree = ast.parse(source, filename="sample.py")
        rule = rule_cls(Path("sample.py"))
        rule.visit(tree)
        return rule.findings

    def test_telnet_triggers(self):
        findings = self.run_rule(TelnetUsageRule, "import telnetlib\ntelnetlib.Telnet(host)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-TELNET-001")

    def test_ftp_triggers(self):
        findings = self.run_rule(FTPUsageRule, "from ftplib import FTP\nFTP(host)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-FTP-001")

    def test_ftps_does_not_trigger(self):
        findings = self.run_rule(FTPUsageRule, "from ftplib import FTP_TLS\nFTP_TLS(host)\n")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
