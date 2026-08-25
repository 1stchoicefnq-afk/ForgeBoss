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
    def test_override_is_test_only(self):
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)/"broker"
            fake.write_text("x",encoding="utf-8")
            with mock.patch.dict(os.environ,{"FORGEBOSS_TEST_ISOLATION_BROKER":str(fake)},clear=False):
                os.environ.pop("FORGEBOSS_TEST_MODE",None)
                with self.assertRaises(broker.IsolationBrokerError):broker._broker_path()
            with mock.patch.dict(os.environ,{"FORGEBOSS_TEST_ISOLATION_BROKER":str(fake),"FORGEBOSS_TEST_MODE":"YES"},clear=False):
                self.assertEqual(broker._broker_path(),fake.resolve())

    def test_reply_requires_real_private_boundary_flags(self):
        expected={"taskId":"t","runId":"r","ownerEpoch":1,"envelopeSha256":"e","budgetUsd":1.0}
        good={"authority":dict(expected)}
        broker._validate_reply_authority(good,expected)
        for key,value in (("runId","other"),("ownerEpoch",2),("envelopeSha256","x"),("budgetUsd",2.0)):
            bad={"authority":dict(expected)};bad["authority"][key]=value
            with self.subTest(key=key),self.assertRaises(broker.IsolationBrokerError):broker._validate_reply_authority(bad,expected)

    def test_apply_rejects_out_of_scope_and_host_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"a.txt").write_text("old",encoding="utf-8")
            packet={"allowed_files":["a.txt"],"context_files":[]}
            baseline=broker.guard.snapshot(root)
            data=b"new"
            good=[{"path":"a.txt","action":"write","contentBase64":base64.b64encode(data).decode(),"sha256":hashlib.sha256(data).hexdigest()}]
            broker._apply_changes(root,packet,baseline,good)
            self.assertEqual((root/"a.txt").read_bytes(),data)
            baseline=broker.guard.snapshot(root)
            bad=[{"path":"b.txt","action":"write","contentBase64":base64.b64encode(b"x").decode(),"sha256":hashlib.sha256(b"x").hexdigest()}]
            with self.assertRaises(broker.IsolationBrokerError):broker._apply_changes(root,packet,baseline,bad)
            baseline=broker.guard.snapshot(root);(root/"a.txt").write_text("racer",encoding="utf-8")
            with self.assertRaises(broker.IsolationBrokerError):broker._apply_changes(root,packet,baseline,good)
            self.assertEqual((root/"a.txt").read_text(encoding="utf-8"),"racer")

    def test_call_broker_rejects_non_isolated_claims(self):
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)/"broker";fake.write_text("x",encoding="utf-8")
            env={"FORGEBOSS_TEST_ISOLATION_BROKER":str(fake),"FORGEBOSS_TEST_MODE":"YES"}
            base={"schema":1,"ok":True,"isolated":True,"hostWorkspaceMounted":False,"workerHasRuntimeControl":False,"paidConsumed":True}
            with mock.patch.dict(os.environ,env,clear=False),mock.patch("subprocess.run") as run:
                run.return_value=mock.Mock(returncode=0,stdout=(__import__('json').dumps(base)).encode(),stderr=b"")
                self.assertEqual(broker._call_broker({"schema":1})["isolated"],True)
                for field,value in (("isolated",False),("hostWorkspaceMounted",True),("workerHasRuntimeControl",True),("paidConsumed",False)):
                    reply=dict(base);reply[field]=value
                    run.return_value=mock.Mock(returncode=0,stdout=(__import__('json').dumps(reply)).encode(),stderr=b"")
                    with self.subTest(field=field),self.assertRaises(broker.IsolationBrokerError):broker._call_broker({"schema":1})


if __name__=="__main__":unittest.main()
