from __future__ import annotations
import tempfile,unittest
from pathlib import Path
from forgeboss.control.store import ControlStore,WorkspaceCollisionError,_repository_identity

class RepositoryIdentityR4Tests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name)/"worktrees";self.root.mkdir();self.db=Path(self.td.name)/"state"/"control.sqlite3";self.store=ControlStore(self.db)
    def tearDown(self):
        try:self.store.db.close()
        except Exception:pass
        self.td.cleanup()
    def create(self,task_id,repo):
        return self.store.create_task({"taskId":task_id,"repository":repo,"purpose":"r4","baseSha":"a"*40,"branch":"b-"+task_id,"allowedPaths":["src/shared.py"],"requiredTests":[],"budgetUsd":1.0})
    def counts(self):
        return (self.store.db.execute("SELECT COUNT(*) n FROM tasks").fetchone()["n"],self.store.db.execute("SELECT COUNT(*) n FROM task_events").fetchone()["n"])

    def test_valid_case_and_backslash_aliases_share_identity(self):
        self.assertEqual(_repository_identity("Owner/Repo"),"owner/repo")
        self.assertEqual(_repository_identity(r"OWNER\REPO"),"owner/repo")

    def test_malformed_repository_authorities_fail_before_task_or_event_commit(self):
        bad=[""," owner/repo","owner/repo ","owner","owner/","/repo","owner/./repo","owner/../repo","owner/repo/extra","https://github.com/owner/repo","http://x/y","git@github.com:owner/repo","C:/owner/repo",r"\\server\owner\repo",r"\\?\C:\owner\repo","owner//repo","owner/re\npo","owner/re\tpo"]
        before=self.counts()
        for i,repo in enumerate(bad):
            with self.subTest(repo=repo):
                with self.assertRaises(WorkspaceCollisionError) as cm:self.create(f"bad-{i}",repo)
                self.assertEqual(cm.exception.code,"REPOSITORY_STATE_INVALID");self.assertEqual(self.counts(),before)

    def test_valid_aliases_collide_same_base_and_scope(self):
        self.create("A","Owner/Repo");self.create("B",r"owner\repo")
        self.store.claim_workspace("A","run-a",self.root/"wa","b-A","a"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        with self.assertRaises(WorkspaceCollisionError) as cm:self.store.claim_workspace("B","run-b",self.root/"wb","b-B","a"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        self.assertEqual(cm.exception.code,"WRITABLE_SCOPE_COLLISION")

    def test_different_valid_repositories_remain_independent(self):
        self.create("A","owner/repo-a");self.create("B","owner/repo-b")
        a=self.store.claim_workspace("A","run-a",self.root/"wa","b-A","a"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        b=self.store.claim_workspace("B","run-b",self.root/"wb","b-B","a"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        self.assertEqual(a["owner_epoch"],1);self.assertEqual(b["owner_epoch"],1)

if __name__=="__main__":unittest.main()
