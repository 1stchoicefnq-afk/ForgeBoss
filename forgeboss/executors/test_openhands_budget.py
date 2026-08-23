from __future__ import annotations
import ast
import unittest
from pathlib import Path

from forgeboss.executors.openhands_runner import _hard_budget_kwargs,_observed_cost,_validated_budget


class LegacyConversation:
    def __init__(self,agent=None,workspace=None):
        pass


class BudgetConversation:
    def __init__(self,agent=None,workspace=None,max_budget_per_run=None):
        self.max_budget_per_run=max_budget_per_run


class Metrics:
    def __init__(self,value):
        self.accumulated_cost=value


class LLMWithMetrics:
    def __init__(self,value):
        self.metrics=Metrics(value)


class LLMWithoutMetrics:
    pass


class MetricsWithoutCost:
    pass


class LLMWithoutCost:
    metrics=MetricsWithoutCost()


class OpenHandsBudgetTests(unittest.TestCase):
    def test_rejects_non_numeric_budget(self):
        with self.assertRaises(ValueError):
            _validated_budget('nope')

    def test_rejects_nonfinite_and_nonpositive_budget(self):
        for raw in ('nan','inf','-inf','0','-0.01'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                _validated_budget(raw)

    def test_accepts_positive_finite_budget_exactly(self):
        self.assertEqual(_validated_budget('0.125'),0.125)

    def test_pinned_style_conversation_without_hard_budget_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError,'no verified hard per-run dollar budget'):
            _hard_budget_kwargs(LegacyConversation,0.25)

    def test_supported_hard_budget_is_wired_exactly(self):
        self.assertEqual(_hard_budget_kwargs(BudgetConversation,0.25),{'max_budget_per_run':0.25})

    def test_capability_gate_precedes_llm_construction(self):
        source=Path(__file__).with_name('openhands_runner.py').read_text(encoding='utf-8')
        self.assertLess(source.index('budget_kwargs=_hard_budget_kwargs'),source.index('llm=LLM('))

    def test_conversation_receives_only_verified_budget_kwargs(self):
        source=Path(__file__).with_name('openhands_runner.py').read_text(encoding='utf-8')
        tree=ast.parse(source)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='Conversation']
        self.assertEqual(len(calls),1)
        self.assertTrue(any(k.arg is None and isinstance(k.value,ast.Name) and k.value.id=='budget_kwargs' for k in calls[0].keywords))

    def test_missing_provider_metrics_remain_unknown(self):
        self.assertIsNone(_observed_cost(LLMWithoutMetrics()))
        self.assertIsNone(_observed_cost(LLMWithoutCost()))
        self.assertIsNone(_observed_cost(LLMWithMetrics(None)))

    def test_invalid_or_nonfinite_provider_metrics_remain_unknown(self):
        for raw in ('nope','nan','inf','-inf',-0.01):
            with self.subTest(raw=raw):
                self.assertIsNone(_observed_cost(LLMWithMetrics(raw)))

    def test_observed_zero_and_nonzero_costs_are_preserved(self):
        self.assertEqual(_observed_cost(LLMWithMetrics(0.0)),0.0)
        self.assertEqual(_observed_cost(LLMWithMetrics('0.375')),0.375)

    def test_source_uses_truthful_observed_cost_on_success_and_failure(self):
        source=Path(__file__).with_name('openhands_runner.py').read_text(encoding='utf-8')
        self.assertIn('cost=_observed_cost(llm)',source)
        self.assertIn('result["cost_usd"]=_observed_cost(llm)',source)
        self.assertIn('if cost is not None and cost>budget:',source)
        self.assertNotIn('getattr(llm.metrics,"accumulated_cost",0.0)',source)


if __name__=='__main__':
    unittest.main()
