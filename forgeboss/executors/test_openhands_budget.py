from __future__ import annotations
import math, unittest
from types import SimpleNamespace
from forgeboss.executors.openhands_runner import _validated_budget,_conversation_budget_kwargs,_observed_cost


class OpenHandsBudgetTests(unittest.TestCase):
    def test_invalid_budget_rejected_before_paid_execution(self):
        for value in (0,-1,float('nan'),float('inf'),float('-inf'),'NaN','Infinity','bad',None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):_validated_budget(value)

    def test_exact_boundary_budget_is_valid(self):
        self.assertEqual(_validated_budget('0.25'),0.25)

    def test_sdk_budget_guard_is_required_and_bound_exactly(self):
        class SupportedConversation:
            def __init__(self,agent,workspace,max_budget_per_run=None):pass
        self.assertEqual(_conversation_budget_kwargs(SupportedConversation,0.25),{'max_budget_per_run':0.25})

        class UnsupportedConversation:
            def __init__(self,agent,workspace):pass
        with self.assertRaises(RuntimeError):_conversation_budget_kwargs(UnsupportedConversation,0.25)

    def test_provider_cost_accounting_is_truthful(self):
        for raw,expected in ((0.0,0.0),(0.25,0.25),('0.50',0.5)):
            with self.subTest(raw=raw):
                self.assertEqual(_observed_cost(SimpleNamespace(metrics=SimpleNamespace(accumulated_cost=raw))),expected)
        for raw in (None,float('nan'),float('inf'),-0.01,'bad'):
            with self.subTest(raw=raw):
                self.assertIsNone(_observed_cost(SimpleNamespace(metrics=SimpleNamespace(accumulated_cost=raw))))
        self.assertIsNone(_observed_cost(SimpleNamespace()))

    def test_over_budget_comparison_uses_observed_cost_not_clamping(self):
        budget=_validated_budget(0.25)
        cost=_observed_cost(SimpleNamespace(metrics=SimpleNamespace(accumulated_cost=0.30)))
        self.assertIsNotNone(cost)
        self.assertGreater(cost,budget)
        self.assertEqual(cost,0.30)


if __name__=='__main__':unittest.main()
