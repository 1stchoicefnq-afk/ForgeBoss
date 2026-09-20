from __future__ import annotations

import base64
import shutil
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.self_build import finish_line_one_plan
from forgeboss.control.self_build_coordinator import SelfBuildCoordinator,SelfBuildCoordinatorError
from forgeboss.control.store import ControlStore,StoreAuthorityError


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory()
        self.root=Path(self.td.name)
        self.source=self.root/"source";self.source.mkdir()
        self.work=self.root/"work";self.work.mkdir()
        self.base="a"*40
        self.store=ControlStore(self.root/"control.db")
        self.pointer={"schema":2,"generation":7,"current":{
            "verified":True,"revision":self.base,"codeRoot":str(self.source)
        },"previous":None}
        self.provisioned=[]
        def inspect(source,base,git):
            return {"source_head":base,"base_sha":base,"source_root":str(source)}
        def provision(source,target,root,base,branch,git,protected_state=None):
            target=Path(target);target.mkdir()
            self.provisioned.append(target)
            return {"workspace_root":str(target.resolve()),"base_sha":base,"branch":branch}
        def cleanup(target,root,protected_state=None):
            shutil.rmtree(target,ignore_errors=True);return True
        self.coordinator=SelfBuildCoordinator(
            store=self.store,
            receipt_public_key_b64=base64.b64encode(b"r"*32).decode("ascii"),
            inspect_source_fn=inspect,
            provision_workspace_fn=provision,
            cleanup_workspace_fn=cleanup,
        )

    def tearDown(self):
        try:self.store.db.close()
        except Exception:pass
        self.td.cleanup()

    def prepare(self,run="fl1-run-one"):
        return self.coordinator.prepare_initial_run(
            source_root=self.source,known_good_pointer=self.pointer,base_sha=self.base,
            run_id=run,workspace_root=self.work,git_executable="/trusted/git",
            protected_state=object(),
        )

    def test_known_good_sha_mismatch_fails_before_store_mutation(self):
        bad={**self.pointer,"current":{**self.pointer["current"],"revision":"b"*40}}
        with self.assertRaises(SelfBuildCoordinatorError) as cm:
            self.coordinator.prepare_initial_run(
                source_root=self.source,known_good_pointer=bad,base_sha=self.base,
                run_id="fl1-bad",workspace_root=self.work,git_executable="/trusted/git",
                protected_state=object(),
            )
        self.assertEqual(cm.exception.code,"KNOWN_GOOD_SHA_MISMATCH")
        self.assertEqual(self.provisioned,[])
        self.assertEqual(self.store.snapshot()["budgetRuns"],[])

    def test_known_good_root_mismatch_fails_closed(self):
        other=self.root/"other";other.mkdir()
        bad={**self.pointer,"current":{**self.pointer["current"],"codeRoot":str(other)}}
        with self.assertRaises(SelfBuildCoordinatorError) as cm:
            self.coordinator.prepare_initial_run(
                source_root=self.source,known_good_pointer=bad,base_sha=self.base,
                run_id="fl1-badroot",workspace_root=self.work,git_executable="/trusted/git",
                protected_state=object(),
            )
        self.assertEqual(cm.exception.code,"KNOWN_GOOD_ROOT_MISMATCH")

    def test_initial_prepare_reserves_one_fifty_and_keeps_b2_headroom(self):
        out=self.prepare()
        self.assertEqual(len(out["builders"]),2)
        self.assertEqual(out["global_budget_cap_usd"],"2.00")
        self.assertEqual(out["global_budget_reserved_usd"],"1.50")
        self.assertEqual(out["reassignment_headroom_usd"],"0.50")
        budget=self.store.get_budget_run(out["run_id"])
        self.assertEqual(budget["reserved_exact"],"1.5")
        self.assertEqual(budget["remaining_exact"],"0.5")
        self.assertNotEqual(out["builders"][0]["worktree"],out["builders"][1]["worktree"])
        self.assertNotEqual(
            out["builders"][0]["packet"]["allowed_files"],
            out["builders"][1]["packet"]["allowed_files"],
        )

    def test_public_prepare_record_contains_no_assignment_token_or_private_key(self):
        out=self.prepare("fl1-public")
        raw=__import__("json").dumps(out,sort_keys=True).lower()
        self.assertNotIn("assignmenttoken",raw)
        self.assertNotIn("assignment_token",raw)
        self.assertNotIn("private_key",raw)
        self.assertNotIn("privatekey",raw)

    def test_replacement_revokes_b_and_uses_fresh_task_branch_workspace_and_last_headroom(self):
        out=self.prepare("fl1-reassign")
        old=out["builders"][1]
        replacement=self.coordinator.prepare_replacement(
            prepared_run=out,source_root=self.source,workspace_root=self.work,
            git_executable="/trusted/git",protected_state=object(),
        )
        self.assertEqual(replacement["replacement_for"],old["task_id"])
        self.assertNotEqual(replacement["task_id"],old["task_id"])
        self.assertNotEqual(replacement["builder_id"],old["builder_id"])
        self.assertNotEqual(replacement["worktree"],old["worktree"])
        self.assertNotEqual(replacement["packet"]["branch"],old["packet"]["branch"])
        old_lease=self.store.get_lease(old["task_id"])
        self.assertIsNotNone(old_lease["revoked_at"])
        with self.assertRaises(StoreAuthorityError):
            self.store.assignment_identity(old["task_id"],old["authority"]["run_id"],old["owner_epoch"])
        budget=self.store.get_budget_run(out["run_id"])
        self.assertEqual(budget["reserved_exact"],"2")
        self.assertEqual(budget["remaining_exact"],"0")

    def test_separate_cycles_generate_separate_durable_task_ids(self):
        p1=finish_line_one_plan(self.base,"cycle-one")
        p2=finish_line_one_plan(self.base,"cycle-two")
        self.assertNotEqual(
            {x.task_id for x in p1.initial_workers+p1.replacement_workers},
            {x.task_id for x in p2.initial_workers+p2.replacement_workers},
        )


if __name__=="__main__":
    unittest.main()
