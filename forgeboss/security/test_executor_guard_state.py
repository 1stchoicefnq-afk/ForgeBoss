from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ExecutorGuardStateTests(unittest.TestCase):
    def test_import_does_not_create_runtime_state(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"runtime-state"
            env=dict(os.environ)
            env["FORGEBOSS_STATE_ROOT"]=str(state)
            p=subprocess.run(
                [sys.executable,"-c","import forgeboss.security.executor_guard"],
                cwd=str(Path(__file__).resolve().parents[2]),
                env=env,capture_output=True,text=True,timeout=30,
            )
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertFalse(state.exists(),"import alone must not mutate external or source runtime state")


if __name__=="__main__":
    unittest.main()
