from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

from forgeboss.control.process_supervisor import ProcessSupervisor, STATE_STOPPED

PY = str(Path(sys.executable).resolve())


class SupervisorV7KernelContainmentTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper proof")
    def test_nonleader_thread_forked_setsid_child_cannot_escape_stop(self):
        sup = ProcessSupervisor()
        try:
            code = (
                "import os,threading,time\n"
                "def spawn():\n"
                " pid=os.fork()\n"
                " if pid==0:\n"
                "  os.setsid(); time.sleep(30); os._exit(0)\n"
                "t=threading.Thread(target=spawn)\n"
                "t.start(); t.join(); time.sleep(30)\n"
            )
            assignment = sup.launch("thread-fork", [PY, "-c", code])
            time.sleep(.2)
            evidence = sup.stop("thread-fork", assignment.generation, timeout=4.0)
            self.assertEqual(evidence.state, STATE_STOPPED)
            self.assertTrue(evidence.containment_empty)
        finally:
            sup.close()


if __name__ == "__main__":
    unittest.main()
