from __future__ import annotations
import tempfile,unittest
from pathlib import Path
from forgeboss.control.store import ControlStore,WorkspaceCollisionError,_git_object_id,_repository_identity

class RepositoryIdentityR5Tests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name)/"worktrees";self.root.mkdir();self.db=Path(self.td.name)/"state"/"control.sqlite3";self.store=ControlStore(self.db)
    def tearDown(self):
        try:self.store.db.close()
        except Exception:pass
        self.td.cleanup()
    def create(self,task_id,repo,base_sha="a"*40,paths=None):
        return self.store.create_task({"taskId":task_id,"repository":repo,"purpose":"r5","baseSha":base_sha,"branch":"b-"+task_id,"allowedPaths":list(paths or ["src/shared.py"]),"requiredTests":[],"budgetUsd":1.0})
    def counts(self):
        return (self.store.db.execute("SELECT COUNT(*) n FROM tasks").fetchone()["n"],self.store.db.execute("SELECT COUNT(*) n FROM task_events").fetchone()["n"])
    def claim_state(self,task_id):
        return {
            "spent":self.store.get_task(task_id)["budget_spent"],
            "runs":self.store.db.execute("SELECT COUNT(*) n FROM task_runs WHERE task_id=?",(task_id,)).fetchone()["n"],
            "claims":self.store.db.execute("SELECT COUNT(*) n FROM task_events WHERE task_id=? AND event_type='workspace.claimed'",(task_id,)).fetchone()["n"],
            "lease":self.store.get_lease(task_id),
        }

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

    def test_git_object_id_accepts_sha1_sha256_and_canonicalizes_lowercase(self):
        self.assertEqual(_git_object_id("A"*40),"a"*40)
        self.assertEqual(_git_object_id("B"*64),"b"*64)
        self.assertEqual(self.create("sha1","owner/repo-1","C"*40)["base_sha"],"c"*40)
        self.assertEqual(self.create("sha256","owner/repo-2","D"*64)["base_sha"],"d"*64)

    def test_malformed_base_sha_fails_before_task_or_event_commit(self):
        bad=[None,"","a"*39,"a"*41,"a"*63,"a"*65,"g"*40,"z"*64," "+"a"*40,"a"*40+" ",True,123]
        before=self.counts()
        for i,base_sha in enumerate(bad):
            with self.subTest(base_sha=base_sha):
                with self.assertRaises(WorkspaceCollisionError) as cm:self.create(f"bad-base-{i}","owner/repo",base_sha)
                self.assertEqual(cm.exception.code,"BASE_SHA_INVALID");self.assertEqual(self.counts(),before)

    def test_case_alias_of_same_base_collides_before_budget_run_lease_or_claim_event(self):
        upper="A"*40;lower="a"*40
        self.create("A","Owner/Repo",upper);self.create("B","owner/repo",lower)
        self.assertEqual(self.store.get_task("A")["base_sha"],lower)
        self.store.claim_workspace("A","run-a",self.root/"wa","b-A",lower,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        before=self.claim_state("B")
        with self.assertRaises(WorkspaceCollisionError) as cm:self.store.claim_workspace("B","run-b",self.root/"wb","b-B",lower,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        self.assertEqual(cm.exception.code,"WRITABLE_SCOPE_COLLISION");self.assertEqual(self.claim_state("B"),before)

    def test_distinct_canonical_bases_remain_independent(self):
        base_a="A"*40;base_b="B"*40
        self.create("A","Owner/Repo",base_a);self.create("B","owner/repo",base_b)
        a=self.store.claim_workspace("A","run-a",self.root/"wa","b-A",base_a.lower(),runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        b=self.store.claim_workspace("B","run-b",self.root/"wb","b-B",base_b.lower(),runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        self.assertEqual(a["owner_epoch"],1);self.assertEqual(b["owner_epoch"],1)

    def test_corrupt_persisted_base_authority_fails_closed_during_collision_scan(self):
        self.create("A","owner/repo","a"*40);self.create("B","owner/repo","b"*40)
        self.store.claim_workspace("A","run-a",self.root/"wa","b-A","a"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        self.store.db.execute("UPDATE tasks SET base_sha='not-an-object-id' WHERE task_id='A'")
        before=self.claim_state("B")
        with self.assertRaises(WorkspaceCollisionError) as cm:self.store.claim_workspace("B","run-b",self.root/"wb","b-B","b"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=.1)
        self.assertEqual(cm.exception.code,"BASE_SHA_INVALID");self.assertEqual(self.claim_state("B"),before)

if __name__=="__main__":unittest.main()
