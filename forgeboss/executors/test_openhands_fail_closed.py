from __future__ import annotations
import os,sys,unittest
from unittest import mock
import forgeboss.executors.openhands_runner as runner

class OpenHandsFailClosedTests(unittest.TestCase):
    def test_paid_gate_disabled_stops(self):
        with mock.patch.object(sys,'argv',['openhands_runner.py','p','w','1.0']),mock.patch.dict(os.environ,{},clear=True):
            self.assertEqual(runner.main(),3)
    def test_paid_gate_enabled_still_stops_without_hard_cap(self):
        with mock.patch.object(sys,'argv',['openhands_runner.py','p','w','1.0']),mock.patch.dict(os.environ,{"FORGEBOSS_ALLOW_PAID_EXECUTOR":"YES"},clear=True):
            self.assertEqual(runner.main(),12)

if __name__=='__main__':unittest.main()
