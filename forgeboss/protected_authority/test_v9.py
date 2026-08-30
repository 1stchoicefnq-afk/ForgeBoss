from __future__ import annotations

import threading
import unittest
from pathlib import Path

from forgeboss.protected_authority.lifecycle import LinuxAuthorityDaemon
from forgeboss.protected_authority.protocol import AuthorityError


class _Conn:
    def shutdown(self, _how):
        pass
    def close(self):
        pass


class LinuxShutdownV9Tests(unittest.TestCase):
    def _daemon_shell(self, worker):
        d = object.__new__(LinuxAuthorityDaemon)
        d.listener = None
        d._stop = threading.Event()
        d._active_lock = threading.Lock()
        d._active = {_Conn()}
        d._workers = [worker]
        d.preauth_timeout = 0.05
        d.accept_poll = 0.01
        d.path = Path('/tmp/forgeboss-authority-v9-nonexistent.sock')
        return d

    def test_surviving_postauth_worker_fails_closed_and_blocks_restart(self):
        release = threading.Event()
        worker = threading.Thread(target=lambda: release.wait(5), daemon=True)
        worker.start()
        d = self._daemon_shell(worker)
        with self.assertRaises(AuthorityError) as cm:
            d.close()
        self.assertEqual(cm.exception.code, 'IPC_WORKER_STUCK')
        self.assertEqual(d._workers, [worker])
        self.assertTrue(d._active)
        with self.assertRaises(AuthorityError) as cm2:
            d.start()
        self.assertEqual(cm2.exception.code, 'IPC_WORKER_STUCK')
        release.set()
        worker.join(1)
        d.close()
        self.assertEqual(d._workers, [])
        self.assertFalse(d._active)

    def test_exited_worker_allows_clean_shutdown_state(self):
        worker = threading.Thread(target=lambda: None)
        worker.start(); worker.join(1)
        d = self._daemon_shell(worker)
        d.close()
        self.assertEqual(d._workers, [])
        self.assertFalse(d._active)


if __name__ == '__main__':
    unittest.main()
