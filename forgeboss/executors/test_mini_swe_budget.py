from __future__ import annotations
import inspect,math,unittest
import forgeboss.executors.mini_swe_runner as runner

class MiniSweBudgetTests(unittest.TestCase):
    def test_positive_budget_rejects_invalid_or_nonpositive(self):
        for value in (0,-1,float("nan"),float("inf"),float("-inf"),"NaN","bad",None,True,False):
            with self.subTest(value=value),self.assertRaises(ValueError):runner._positive_budget(value)
        self.assertEqual(runner._positive_budget("0.25"),0.25)
    def test_unknown_or_invalid_measured_cost_remains_null(self):
        for value in (None,float("nan"),float("inf"),float("-inf"),-0.01,"bad",True):
            with self.subTest(value=value):self.assertIsNone(runner._observed_cost(value))
        self.assertEqual(runner._observed_cost(0),0.0);self.assertEqual(runner._observed_cost("0.42"),0.42)
    def test_paid_start_context_precedes_model_construction_and_run(self):
        src=inspect.getsource(runner.main)
        guard_i=src.index("with paid_start_authority(")
        model_i=src.index("LitellmModel(model_name=model_name)")
        run_i=src.index("agent.run(task)")
        self.assertLess(guard_i,model_i);self.assertLess(model_i,run_i)
    def test_old_verify_subprocess_boundary_is_removed(self):
        src=inspect.getsource(runner.main)
        self.assertNotIn('"verify","--lease"',src)
        self.assertIn("FORGEBOSS_CONTROL_ENVELOPE",src)
    def test_result_cost_defaults_to_unknown_not_zero(self):
        src=inspect.getsource(runner.main)
        self.assertIn('"cost_usd":None',src)

if __name__=="__main__":unittest.main()
