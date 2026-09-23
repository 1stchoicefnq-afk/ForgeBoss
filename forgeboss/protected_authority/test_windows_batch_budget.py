from __future__ import annotations

import threading
import time
import unittest

from forgeboss.protected_authority.lifecycle import WindowsNamedPipeServer
from forgeboss.protected_authority.protocol import AuthorityError


class WindowsBatchBudgetPortableTests(unittest.TestCase):
    def _server(self):
        srv=object.__new__(WindowsNamedPipeServer)
        srv.handles=[101,102]
        srv.handle=101
        srv.preauth_timeout_ms=100
        srv.handler_timeout_ms=500
        srv.poll_interval=0.001
        srv._stop=threading.Event()
        srv._stuck=[]
        srv._quarantined=set()
        srv._worker_lock=threading.Lock()
        return srv

    def test_authenticated_work_longer_than_old_one_second_slack_is_not_stuck(self):
        srv=self._server()
        def serve(h):
            if h==101:
                time.sleep(0.20)
                return b"ok"
            raise AuthorityError("IPC_PREAUTH_TIMEOUT")
        srv._serve_handle=serve
        out=srv.serve_batch()
        self.assertEqual(out[0],b"ok")
        self.assertEqual(out[1].code,"IPC_PREAUTH_TIMEOUT")
        self.assertEqual(srv.handles,[101,102])

    def test_authority_error_message_contains_machine_code(self):
        err=AuthorityError("EXACT_TEST_CODE")
        self.assertEqual(err.code,"EXACT_TEST_CODE")
        self.assertIn("EXACT_TEST_CODE",str(err))


if __name__=="__main__":
    unittest.main()
