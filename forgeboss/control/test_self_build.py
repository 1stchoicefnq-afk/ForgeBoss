from __future__ import annotations

import unittest
from dataclasses import replace

from forgeboss.control.self_build import SelfBuildPlanError, finish_line_one_plan


KG="a"*40


class FinishLineOnePlanTests(unittest.TestCase):
    def test_locked_first_run_has_two_disjoint_initial_builders_and_fresh_b2(self):
        plan=finish_line_one_plan(KG,"fl1-test")
        self.assertEqual(len(plan.initial_workers),2)
        self.assertEqual(len(plan.replacement_workers),1)
        a,b=plan.initial_workers
        b2=plan.replacement_workers[0]
        self.assertNotEqual(a.allowed_files,b.allowed_files)
        self.assertEqual(b.allowed_files,b2.allowed_files)
        self.assertNotEqual(b.branch,b2.branch)
        self.assertNotEqual(b.builder_id,b2.builder_id)
        self.assertEqual(b2.replacement_for,b.task_id)

    def test_global_two_dollar_cap_reserves_reassignment_headroom(self):
        plan=finish_line_one_plan(KG,"fl1-test")
        values=[x.budget_usd for x in plan.initial_workers+plan.replacement_workers]
        self.assertEqual(values,["1.00","0.50","0.50"])
        self.assertEqual(plan.global_budget_usd,"2.00")

    def test_first_canaries_are_test_only_and_do_not_touch_control(self):
        plan=finish_line_one_plan(KG,"fl1-test")
        for worker in plan.initial_workers:
            self.assertTrue(all("/test_" in p for p in worker.allowed_files))
            self.assertTrue(all(not p.startswith("forgeboss/control/") for p in worker.allowed_files))

    def test_packet_is_forgeboss_and_pins_exact_known_good(self):
        plan=finish_line_one_plan(KG,"fl1-test")
        p=plan.initial_workers[0].packet(known_good_sha=plan.known_good_sha,run_id=plan.run_id)
        self.assertEqual(p["product"],"ForgeBoss")
        self.assertEqual(p["project_id"],"forgeboss")
        self.assertEqual(p["expected_head_revision"],KG)
        self.assertFalse(p["publish"])
        self.assertFalse(p["merge"])
        self.assertFalse(p["deploy"])

    def test_invalid_known_good_rejected(self):
        with self.assertRaises(SelfBuildPlanError):
            finish_line_one_plan("main","fl1-test")

    def test_overlap_fails_closed(self):
        plan=finish_line_one_plan(KG,"fl1-test")
        a,b=plan.initial_workers
        bad=replace(b,allowed_files=a.allowed_files)
        with self.assertRaisesRegex(SelfBuildPlanError,"overlap"):
            replace(plan,initial_workers=(a,bad)).validate()

    def test_replacement_cannot_reuse_original_branch(self):
        plan=finish_line_one_plan(KG,"fl1-test")
        b=plan.initial_workers[1];b2=plan.replacement_workers[0]
        with self.assertRaisesRegex(SelfBuildPlanError,"fresh branch"):
            replace(plan,replacement_workers=(replace(b2,branch=b.branch),)).validate()

    def test_authority_cannot_exceed_global_cap(self):
        plan=finish_line_one_plan(KG,"fl1-test")
        b2=replace(plan.replacement_workers[0],budget_usd="0.51")
        with self.assertRaisesRegex(SelfBuildPlanError,"global cap"):
            replace(plan,replacement_workers=(b2,)).validate()


if __name__=="__main__":
    unittest.main()
