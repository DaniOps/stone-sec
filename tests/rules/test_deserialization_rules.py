import ast
import unittest
from pathlib import Path

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


class DeserializationRuleTests(unittest.TestCase):
    def run_rule(self, rule_cls, source: str):
        tree = ast.parse(source, filename="sample.py")
        rule = rule_cls(Path("sample.py"))
        rule.visit(tree)
        return rule.findings

    def test_marshal_loads_triggers(self):
        findings = self.run_rule(MarshalLoadsRule, "import marshal\nmarshal.loads(data)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-MARSHAL-001")

    def test_dill_load_triggers(self):
        findings = self.run_rule(DillLoadRule, "from dill import load\nload(f)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-DILL-001")

    def test_jsonpickle_decode_triggers(self):
        findings = self.run_rule(
            JsonpickleDecodeRule, "import jsonpickle as jp\njp.decode(raw)\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-JSONPICKLE-001")

    def test_yaml_full_load_triggers(self):
        findings = self.run_rule(
            YamlUnsafeDirectLoadRule, "from yaml import full_load\nfull_load(doc)\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-YAML-002")

    def test_numpy_allow_pickle_true_triggers(self):
        findings = self.run_rule(
            NumpyAllowPickleRule, "import numpy as np\nnp.load(p, allow_pickle=True)\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-NUMPY-001")

    def test_numpy_default_does_not_trigger(self):
        findings = self.run_rule(NumpyAllowPickleRule, "import numpy as np\nnp.load(p)\n")
        self.assertEqual(len(findings), 0)

    def test_pandas_read_pickle_triggers(self):
        findings = self.run_rule(PandasReadPickleRule, "import pandas as pd\npd.read_pickle(p)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-PANDAS-001")

    def test_torch_load_triggers(self):
        findings = self.run_rule(TorchLoadRule, "import torch\ntorch.load(p)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-TORCH-001")

    def test_joblib_load_triggers(self):
        findings = self.run_rule(JoblibLoadRule, "import joblib\njoblib.load(p)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY-JOBLIB-001")


if __name__ == "__main__":
    unittest.main()
