from __future__ import annotations

import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forgeboss.executors.isolation_broker as broker


class IsolationBrokerTests(unittest.TestCase):
    def _change(self,path,data=b"new"):
        return {"path":path,"action":"write","contentBase64":base64.b64encode(data).decode(),"sha256":hashlib.sha256(data).hexdigest()}

    def _authority(self,root):
        return {"ordinary":broker.guard.snapshot(root),"git":{"g":"same"},"head":"h"*40}

    def _patch_git(self,git_meta=None,head=None):
        return (mock.patch.object(broker.guard,"git_metadata_snapshot",return_value={"g":"same"} if git_meta is None else git_meta),
                mock.patch.object(broker.guard,"git",return_value="h"*40 if head is None else head))

    def test_override_is_test_only(self):
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)/"broker";fake.write_text("x",encoding="utf-8")
            with mock.patch.dict(os.environ,{"FORGEBOSS_TEST_ISOLATION_BROKER":str(fake)},clear=False):
                os.environ.pop("FORGEBOSS_TEST_MODE",None)
                with self.assertRaises(broker.IsolationBrokerError):broker._broker_path()
            with mock.patch.dict(os.environ,{"FORGEBOSS_TEST_ISOLATION_BROKER":str(fake),"FORGEBOSS_TEST_MODE":"YES"},clear=False):
                self.assertEqual(broker._broker_path(),fake.resolve())

    def test_reply_requires_exact_authority(self):
        expected={"taskId":"t","runId":"r","ownerEpoch":1,"envelopeSha256":"e","budgetUsd":1.0}
        broker._validate_reply_authority({"authority":dict(expected)},expected)
        for key,value in (("runId","other"),("ownerEpoch",2),("envelopeSha256","x"),("budgetUsd",2.0)):
            bad={"authority":dict(expected)};bad["authority"][key]=value
            with self.subTest(key=key),self.assertRaises(broker.IsolationBrokerError):broker._validate_reply_authority(bad,expected)

    def test_apply_good_change_with_stable_git_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"a.txt").write_text("old",encoding="utf-8");packet={"allowed_files":["a.txt"],"context_files":[]};baseline=self._authority(root);p1,p2=self._patch_git()
            with p1,p2:self.assertEqual(broker._apply_changes(root,packet,baseline,[self._change("a.txt")]),["a.txt"])
            self.assertEqual((root/"a.txt").read_bytes(),b"new")

    def test_git_only_drift_rejects_before_first_host_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"a.txt").write_text("old",encoding="utf-8");packet={"allowed_files":["a.txt"],"context_files":[]};baseline=self._authority(root)
            with mock.patch.object(broker.guard,"git_metadata_snapshot",return_value={"g":"drift"}),mock.patch.object(broker.guard,"git",return_value="h"*40):
                with self.assertRaisesRegex(broker.IsolationBrokerError,"Git authority drifted"):broker._apply_changes(root,packet,baseline,[self._change("a.txt")])
            self.assertEqual((root/"a.txt").read_text(encoding="utf-8"),"old")

    def test_head_only_drift_rejects_before_first_host_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"a.txt").write_text("old",encoding="utf-8");packet={"allowed_files":["a.txt"],"context_files":[]};baseline=self._authority(root)
            with mock.patch.object(broker.guard,"git_metadata_snapshot",return_value={"g":"same"}),mock.patch.object(broker.guard,"git",return_value="x"*40):
                with self.assertRaisesRegex(broker.IsolationBrokerError,"HEAD drifted"):broker._apply_changes(root,packet,baseline,[self._change("a.txt")])
            self.assertEqual((root/"a.txt").read_text(encoding="utf-8"),"old")

    def test_malformed_second_change_causes_zero_partial_writes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"a.txt").write_text("A",encoding="utf-8");(root/"b.txt").write_text("B",encoding="utf-8");packet={"allowed_files":["a.txt","b.txt"],"context_files":[]};baseline=self._authority(root);changes=[self._change("a.txt",b"AA"),{"path":"b.txt","action":"write","contentBase64":"%%%","sha256":"0"*64}];p1,p2=self._patch_git()
            with p1,p2:
                with self.assertRaises(broker.IsolationBrokerError):broker._apply_changes(root,packet,baseline,changes)
            self.assertEqual((root/"a.txt").read_text(),"A");self.assertEqual((root/"b.txt").read_text(),"B")

    def test_mid_apply_failure_rolls_back_prior_touched_file(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"a.txt").write_text("A",encoding="utf-8");(root/"b.txt").write_text("B",encoding="utf-8");packet={"allowed_files":["a.txt","b.txt"],"context_files":[]};baseline=self._authority(root);changes=[self._change("a.txt",b"AA"),self._change("b.txt",b"BB")];real=broker._atomic_write_bytes;calls={"n":0}
            def flaky(target,data):
                calls["n"]+=1
                if calls["n"]==2:raise OSError("synthetic second write failure")
                return real(target,data)
            p1,p2=self._patch_git()
            with p1,p2,mock.patch.object(broker,"_atomic_write_bytes",side_effect=flaky):
                with self.assertRaises(OSError):broker._apply_changes(root,packet,baseline,changes)
            self.assertEqual((root/"a.txt").read_text(),"A");self.assertEqual((root/"b.txt").read_text(),"B")

    def test_post_apply_git_drift_rolls_back_worker_output(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"a.txt").write_text("old",encoding="utf-8");packet={"allowed_files":["a.txt"],"context_files":[]};baseline=self._authority(root)
            with mock.patch.object(broker.guard,"git_metadata_snapshot",side_effect=[{"g":"same"},{"g":"drift"}]),mock.patch.object(broker.guard,"git",return_value="h"*40):
                with self.assertRaisesRegex(broker.IsolationBrokerError,"Git authority drifted during"):broker._apply_changes(root,packet,baseline,[self._change("a.txt")])
            self.assertEqual((root/"a.txt").read_text(),"old")

    def test_target_preimage_race_is_detected_before_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);target=root/"a.txt";target.write_text("old",encoding="utf-8");packet={"allowed_files":["a.txt"],"context_files":[]};baseline=self._authority(root);real_assert=broker._assert_authority
            def race(host,base,label):real_assert(host,base,label);target.write_text("racer",encoding="utf-8")
            p1,p2=self._patch_git()
            with p1,p2,mock.patch.object(broker,"_assert_authority",side_effect=race):
                with self.assertRaisesRegex(broker.IsolationBrokerError,"target preimage changed"):broker._apply_changes(root,packet,baseline,[self._change("a.txt")])
            self.assertEqual(target.read_text(),"racer")

    def test_call_broker_rejects_non_isolated_claims(self):
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)/"broker";fake.write_text("x",encoding="utf-8");env={"FORGEBOSS_TEST_ISOLATION_BROKER":str(fake),"FORGEBOSS_TEST_MODE":"YES"};base={"schema":1,"ok":True,"isolated":True,"hostWorkspaceMounted":False,"workerHasRuntimeControl":False,"paidConsumed":True}
            with mock.patch.dict(os.environ,env,clear=False),mock.patch("subprocess.run") as run:
                run.return_value=mock.Mock(returncode=0,stdout=(__import__('json').dumps(base)).encode(),stderr=b"");self.assertTrue(broker._call_broker({"schema":1})["isolated"])
                for field,value in (("isolated",False),("hostWorkspaceMounted",True),("workerHasRuntimeControl",True),("paidConsumed",False)):
                    reply=dict(base);reply[field]=value;run.return_value=mock.Mock(returncode=0,stdout=(__import__('json').dumps(reply)).encode(),stderr=b"")
                    with self.subTest(field=field),self.assertRaises(broker.IsolationBrokerError):broker._call_broker({"schema":1})


if __name__=="__main__":unittest.main()
