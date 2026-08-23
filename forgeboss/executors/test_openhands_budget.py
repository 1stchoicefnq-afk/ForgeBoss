from __future__ import annotations
import math, unittest
from datetime import date
import forgeboss.executors.openhands_runner as runner

class PinnedConversation:
    def __init__(self,agent,workspace,max_iteration_per_run=500):pass

class UnsupportedConversation:
    def __init__(self,agent,workspace):pass

class Metrics:
    def __init__(self,cost):self.accumulated_cost=cost
class LLM:
    def __init__(self,cost):self.metrics=Metrics(cost)

class OpenHandsBudgetTests(unittest.TestCase):
    def test_rate_card_expiry_fails_closed(self):
        with self.assertRaises(RuntimeError):
            runner._iteration_budget_plan(2.50,runner.PINNED_MODEL,today=date(2026,10,1))

    def test_invalid_budget_fails_closed(self):
        for value in (0,-1,float("nan"),float("inf"),"-Infinity","bad"):
            with self.subTest(value=value):
                with self.assertRaises((ValueError,RuntimeError)):
                    runner._iteration_budget_plan(value,runner.PINNED_MODEL)

    def test_real_pinned_api_shape_uses_max_iteration_per_run_only(self):
        plan=runner._iteration_budget_plan(2.50,runner.PINNED_MODEL)
        kwargs=runner._conversation_iteration_kwargs(PinnedConversation,plan)
        self.assertEqual(kwargs,{"max_iteration_per_run":1})
        self.assertNotIn("max_budget_per_run",kwargs)

    def test_exact_boundary_and_multiple_iteration_reservation(self):
        one=runner._iteration_budget_plan(2.50,runner.PINNED_MODEL)
        two=runner._iteration_budget_plan(5.00,runner.PINNED_MODEL)
        self.assertEqual((one["max_iterations"],one["reserved_usd"]),(1,2.50))
        self.assertEqual((two["max_iterations"],two["reserved_usd"]),(2,5.00))

    def test_crossing_iteration_is_prevented_before_paid_work(self):
        with self.assertRaises(RuntimeError):
            runner._iteration_budget_plan(2.4999,runner.PINNED_MODEL)
        plan=runner._iteration_budget_plan(4.9999,runner.PINNED_MODEL)
        self.assertEqual(plan["max_iterations"],1)
        self.assertLessEqual(plan["reserved_usd"],4.9999)

    def test_unknown_model_and_unsupported_sdk_fail_closed(self):
        with self.assertRaises(RuntimeError):
            runner._iteration_budget_plan(10.0,"openai/gpt-5.6-sol")
        plan=runner._iteration_budget_plan(2.50,runner.PINNED_MODEL)
        with self.assertRaises(RuntimeError):
            runner._conversation_iteration_kwargs(UnsupportedConversation,plan)

    def test_provider_failure_accounting_is_truthful(self):
        self.assertIsNone(runner._observed_cost(object()))
        self.assertIsNone(runner._observed_cost(LLM(float("nan"))))
        self.assertEqual(runner._observed_cost(LLM(1.25)),1.25)

if __name__=="__main__":unittest.main()
