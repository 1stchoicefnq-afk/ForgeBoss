from __future__ import annotations
import json,os,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import forgeboss.executors.mini_swe_runner as runner
from forgeboss.control.envelope import secret_file,sign_envelope
class MiniSweBudgetTests(unittest.TestCase):
    def test_positive_budget_rejects_invalid_or_nonpositive(self):
        for value in (0,-1,float('nan'),float('inf'),float('-inf'),'NaN','bad',None,True,False):
            with self.subTest(value=value),self.assertRaises(ValueError):runner._positive_budget(value)
        self.assertEqual(runner._positive_budget('0.25'),0.25)
    def test_unknown_or_invalid_measured_cost_remains_null(self):
        for value in (None,float('nan'),float('inf'),float('-inf'),-0.01,'bad',True):
            with self.subTest(value=value):self.assertIsNone(runner._observed_cost(value))
        self.assertEqual(runner._observed_cost(0),0.0);self.assertEqual(runner._observed_cost('0.42'),0.42)
    def signed_env(self,root,work,budget,adapter='mini-swe'):
        _,secret=secret_file(root);payload={"envelopeVersion":1,"protocolVersion":1,"taskId":"T","repository":"owner/repo","baseSha":"a"*40,"branch":"b","worktreePath":str(work),"runId":"R","attempt":1,"ownerEpoch":1,"runtime":{"adapter":adapter,"provider":"openai","model":"x"},"allowedPaths":["x"],"deniedPaths":[],"allowedTools":["python"],"contextBundleHash":None,"transcript":{},"events":{},"budgetUsd":budget,"expiresAt":time.time()+60};return sign_envelope(payload,secret)
    def test_controller_budget_comes_from_valid_signed_envelope(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);work=root/'work';work.mkdir();env_path=root/'env.json';env_path.write_text(json.dumps(self.signed_env(root,work,0.4)),encoding='utf-8')
            with mock.patch.object(runner,'ROOT',root),mock.patch.dict(os.environ,{"FORGEBOSS_CONTROL_ENVELOPE":str(env_path)}):self.assertEqual(runner._controller_budget(work),0.4)
    def test_tampered_or_wrong_workspace_runtime_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);work=root/'work';work.mkdir();other=root/'other';other.mkdir();env_path=root/'env.json';env=self.signed_env(root,work,0.4);env['budgetUsd']=0.9;env_path.write_text(json.dumps(env),encoding='utf-8')
            with mock.patch.object(runner,'ROOT',root),mock.patch.dict(os.environ,{"FORGEBOSS_CONTROL_ENVELOPE":str(env_path)}),self.assertRaises(PermissionError):runner._controller_budget(work)
            env_path.write_text(json.dumps(self.signed_env(root,work,0.4,'openhands')),encoding='utf-8')
            with mock.patch.object(runner,'ROOT',root),mock.patch.dict(os.environ,{"FORGEBOSS_CONTROL_ENVELOPE":str(env_path)}),self.assertRaises(PermissionError):runner._controller_budget(work)
            env_path.write_text(json.dumps(self.signed_env(root,other,0.4)),encoding='utf-8')
            with mock.patch.object(runner,'ROOT',root),mock.patch.dict(os.environ,{"FORGEBOSS_CONTROL_ENVELOPE":str(env_path)}),self.assertRaises(PermissionError):runner._controller_budget(work)
if __name__=='__main__':unittest.main()
