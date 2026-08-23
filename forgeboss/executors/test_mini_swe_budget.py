from __future__ import annotations

import inspect
import os
import sys
import unittest
from unittest import mock

from forgeboss.executors import mini_swe_runner


class MiniSweBudgetTests(unittest.TestCase):
    def test_rejects_non_numeric_nonfinite_and_nonpositive(self):
        for raw in ("nope", "nan", "inf", "+inf", "-inf", "0", "-0", "-1", -2, 0):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    mini_swe_runner._validated_budget(raw)

    def test_accepts_finite_positive_budget_exactly(self):
        for raw, expected in (("0.01", 0.01), ("2.50", 2.5), (7, 7.0)):
            with self.subTest(raw=raw):
                self.assertEqual(mini_swe_runner._validated_budget(raw), expected)

    def test_main_invalid_budget_fails_before_packet_or_paid_agent(self):
        old_argv=sys.argv
        try:
            sys.argv=["mini_swe_runner.py", "definitely-missing-packet.json", ".", "nan"]
            with mock.patch.dict(os.environ, {"FORGEBOSS_ALLOW_PAID_EXECUTOR":"YES"}, clear=False):
                rc=mini_swe_runner.main()
            self.assertEqual(rc, 14)
        finally:
            sys.argv=old_argv

    def test_budget_gate_precedes_miniswe_import_and_model_construction(self):
        source=inspect.getsource(mini_swe_runner.main)
        budget_pos=source.index("budget=_validated_budget(sys.argv[3])")
        import_pos=source.index("from minisweagent.agents.default import DefaultAgent")
        model_pos=source.index("model=LitellmModel(model_name=model_name)")
        self.assertLess(budget_pos, import_pos)
        self.assertLess(budget_pos, model_pos)

    def test_validated_budget_is_the_agent_cost_limit(self):
        source=inspect.getsource(mini_swe_runner.main)
        self.assertIn("cost_limit=budget", source)
        self.assertNotIn("cost_limit=float(sys.argv[3])", source)


if __name__ == "__main__":
    unittest.main()
