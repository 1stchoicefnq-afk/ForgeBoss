from __future__ import annotations
import inspect,os,unittest
from forgeboss.broker import __main__ as broker_main
class BrokerServiceEntrypointTests(unittest.TestCase):
    def test_windows_entrypoint_is_real_scm_service_lifecycle(self):
        src=inspect.getsource(broker_main._windows_service_main);self.assertIn("StartServiceCtrlDispatcherW",src);self.assertIn("RegisterServiceCtrlHandlerExW",src);self.assertIn("SetServiceStatus",src);self.assertIn("SERVICE_CONTROL_STOP",src);self.assertIn("wake_windows_pipe",src)
    def test_linux_entrypoint_has_bounded_shutdown_signal_path(self):
        src=inspect.getsource(broker_main._linux_main);self.assertIn("SIGTERM",src);self.assertIn("SIGINT",src);self.assertIn("serve_forever(stop)",src)
if __name__=="__main__":unittest.main()
