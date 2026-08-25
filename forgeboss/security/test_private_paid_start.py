from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from forgeboss.security import executor_guard as guard
from forgeboss.security import private_paid_start as p


class PrivatePaidStartTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name);self.host=self.root/"host";self.host.mkdir()
        (self.host/"x.py").write_text("old\n",encoding="utf-8")
        self.packet=self.root/"packet.json";self.packet.write_text(json.dumps({"allowed_files":["x.py"],"context_files":[],"expected_head_revision":"a"*40}),encoding="utf-8")
        self.lease=self.root/"lease.json";self.lease.write_text(json.dumps({"allowed_files":["x.py"],"paid_authority":None,"paid_consumed":False}),encoding="utf-8")
        self.db=self.root/"forgeboss.db";self._make_db()
        self.authority={"taskId":"task-1","runId":"run-1","ownerEpoch":2,"budgetUsd":0.25,"worktreePath":str(self.host.resolve()),"runtime":{"adapter":"mini-swe"},"allowedPaths":["x.py"],"envelopeSha256":"e"*64}
        self.signed_env={"taskId":"task-1","runId":"run-1","ownerEpoch":2,"budgetUsd":0.25,"worktreePath":str(self.host.resolve()),"runtime":{"adapter":"mini-swe"},"allowedPaths":["x.py"],"baseSha":"a"*40,"expiresAt":time.time()+120}
    def tearDown(self):self.td.cleanup()
    def _make_db(self):
        db=sqlite3.connect(self.db)
        db.executescript("""CREATE TABLE tasks(task_id TEXT PRIMARY KEY,assigned_runtime TEXT);CREATE TABLE workspace_leases(task_id TEXT,worktree_path TEXT,owner_run_id TEXT,owner_epoch INTEGER,expires_at REAL,released_at REAL,budget_reserved REAL);""")
        db.execute("INSERT INTO tasks VALUES(?,?)",("task-1","mini-swe"))
        db.execute("INSERT INTO workspace_leases VALUES(?,?,?,?,?,?,?)",("task-1",str(self.host.resolve()),"run-1",2,time.time()+300,None,0.25));db.commit();db.close()
    @contextmanager
    def _paid(self,*_args,**_kwargs):
        data=json.loads(self.lease.read_text(encoding="utf-8"));data["paid_authority"]=dict(self.authority);data["paid_consumed"]=True;self.lease.write_text(json.dumps(data),encoding="utf-8");yield dict(self.authority)
    def _common_patches(self):
        return (
            patch.object(p,"CONTROL_DB",self.db),
            patch.object(guard,"_load_control_envelope",return_value=dict(self.signed_env)),
            patch.object(guard,"_control_authority",return_value=dict(self.authority)),
            patch.object(guard,"_positive_budget",side_effect=lambda x:float(x)),
        )
    def _fake_archive(self,*_):return b"archive"
    def _fake_extract(self,_raw,dst):(dst/"x.py").write_text("old\n",encoding="utf-8")
    def test_stale_durable_run_epoch_is_rejected(self):
        with patch.object(p,"CONTROL_DB",self.db):
            bad=dict(self.authority);bad["runId"]="stale-run"
            with self.assertRaises(p.PrivatePaidStartError):p._assert_current_durable_writer(bad,self.host,"mini-swe")
    def test_stale_run_fails_before_paid_consumption(self):
        stale=dict(self.authority);stale["runId"]="stale-run";called=[]
        @contextmanager
        def should_not_run(*_a,**_k):
            called.append(True);yield stale
        a,b,c,d=self._common_patches()
        with a,b,patch.object(guard,"_control_authority",return_value=stale),d,patch.object(guard,"paid_start_authority",side_effect=should_not_run):
            with self.assertRaises(p.PrivatePaidStartError):p.prepare_private_paid_start(self.lease,"tok",self.packet,self.host,"mini-swe","signed",0.25)
        self.assertEqual(called,[]);self.assertFalse(json.loads(self.lease.read_text(encoding="utf-8"))["paid_consumed"])
    def test_prepare_binds_private_snapshot_before_return(self):
        a,b,c,d=self._common_patches()
        with a,b,c,d,patch.object(guard,"paid_start_authority",side_effect=self._paid),patch.object(p,"_git_archive_exact",side_effect=self._fake_archive),patch.object(p,"_safe_extract_tar",side_effect=self._fake_extract):
            s=p.prepare_private_paid_start(self.lease,"tok",self.packet,self.host,"mini-swe","signed",0.25)
        try:
            self.assertNotEqual(Path(s["workspace"]),self.host);self.assertEqual((Path(s["workspace"])/"x.py").read_text(encoding="utf-8"),"old\n");self.assertEqual(s["authority"]["runId"],"run-1")
        finally:p.cleanup_private_session(s)
    def test_concurrent_host_mutation_blocks_copyback(self):
        private=self.root/"private";private.mkdir();(private/"x.py").write_text("old\n",encoding="utf-8")
        session={"workspace":str(private),"hostWorkspace":str(self.host),"packet":{"allowed_files":["x.py"],"context_files":[]},"privateBaseline":guard.snapshot(private),"hostBaseline":guard.snapshot(self.host)}
        (private/"x.py").write_text("worker\n",encoding="utf-8");(self.host/"x.py").write_text("racer\n",encoding="utf-8")
        with self.assertRaises(p.PrivatePaidStartError):p.commit_private_result(session)
        self.assertEqual((self.host/"x.py").read_text(encoding="utf-8"),"racer\n")
    def test_out_of_scope_private_change_is_rejected(self):
        private=self.root/"private2";private.mkdir();(private/"x.py").write_text("old\n",encoding="utf-8")
        session={"workspace":str(private),"hostWorkspace":str(self.host),"packet":{"allowed_files":["x.py"],"context_files":[]},"privateBaseline":guard.snapshot(private),"hostBaseline":guard.snapshot(self.host)}
        (private/"oops.txt").write_text("bad\n",encoding="utf-8")
        with self.assertRaises(p.PrivatePaidStartError):p.commit_private_result(session)

if __name__=="__main__":unittest.main()
