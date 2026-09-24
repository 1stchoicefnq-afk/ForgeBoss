from __future__ import annotations

import threading
import time
import unittest

from forgeboss.protected_authority.lifecycle import WindowsNamedPipeServer
from forgeboss.protected_authority.protocol import AuthorityError


class WindowsBatchBudgetPortableTests(unittest.TestCase):
    def _server(self,handles=None,*,preauth_timeout_ms=100,handler_timeout_ms=500):
        srv=object.__new__(WindowsNamedPipeServer)
        srv.handles=list(handles or [101,102])
        srv.handle=srv.handles[0]
        srv.preauth_timeout_ms=preauth_timeout_ms
        srv.handler_timeout_ms=handler_timeout_ms
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

    def test_one_stuck_instance_does_not_kill_the_host(self):
        srv=self._server([101,102,103,104],preauth_timeout_ms=10,handler_timeout_ms=40)
        def serve(h):
            if h==101:
                time.sleep(0.20)
                return b"late"
            return ("ok-"+str(h)).encode()
        srv._serve_handle=serve
        out=srv.serve_batch()
        self.assertEqual([x for x in srv.handles],[102,103,104])
        self.assertIsInstance(out[0],AuthorityError)
        self.assertEqual(out[0].code,"IPC_HANDLER_QUARANTINED")
        self.assertEqual(out[1:], [b"ok-102",b"ok-103",b"ok-104"])

    def test_all_stuck_instances_trigger_deliberate_shutdown_reason(self):
        srv=self._server([101,102,103,104],preauth_timeout_ms=10,handler_timeout_ms=40)
        def serve(_h):
            time.sleep(0.20)
            return b"late"
        srv._serve_handle=serve
        with self.assertRaises(AuthorityError) as cm:
            srv.serve_batch()
        self.assertEqual(cm.exception.code,"IPC_ALL_INSTANCES_QUARANTINED")
        self.assertEqual(srv.handles,[])
        self.assertIsNone(srv.handle)

    def test_windows_server_source_flushes_before_disconnect(self):
        import inspect
        source=inspect.getsource(WindowsNamedPipeServer._serve_handle)
        self.assertIn("FlushFileBuffers",source)
        self.assertLess(source.index("FlushFileBuffers"),source.index("DisconnectNamedPipe"))

    def test_authority_error_message_contains_machine_code(self):
        err=AuthorityError("EXACT_TEST_CODE")
        self.assertEqual(err.code,"EXACT_TEST_CODE")
        self.assertIn("EXACT_TEST_CODE",str(err))


if __name__=="__main__":
    unittest.main()
