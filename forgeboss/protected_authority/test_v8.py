from __future__ import annotations

import threading
import time
import unittest
from pathlib import Path

from forgeboss.protected_authority.github_backend import GitHubAppBackend
from forgeboss.protected_authority.lifecycle import LinuxAuthorityDaemon
from forgeboss.protected_authority.protocol import AuthorityError


class ControlBackend(GitHubAppBackend):
    def __init__(self, responses):
        super().__init__(app_id=1, installation_id=2)
        self.responses = list(responses)
        self.requests = []
    def _token(self, _pem, repository, operation):
        self.assert_token = (repository, operation)
        return 'token'
    def _request(self, method, path, *, token=None, body=None):
        self.requests.append((method, path, token, body))
        if not self.responses:
            raise AssertionError('unexpected GitHub request')
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def pr(number, *, state='open', head_sha='h'*40, head_ref='root', base_sha='b'*40,
       base_ref='main', repo='Owner/Repo', title='', body='', updated='2026-08-30T00:00:00Z'):
    return {
        'number': number,
        'state': state,
        'title': title,
        'body': body,
        'updated_at': updated,
        'head': {'sha': head_sha, 'ref': head_ref, 'repo': {'full_name': repo}},
        'base': {'sha': base_sha, 'ref': base_ref},
    }


class GitHubControlBindingV8Tests(unittest.TestCase):
    def test_discovers_only_exact_current_repair_child(self):
        root = pr(10, head_sha='a'*40, head_ref='feature/root')
        exact = pr(12, head_sha='c'*40, head_ref='autopilot/repair-pr10-r2',
                   base_sha='a'*40, base_ref='feature/root')
        stale = pr(13, head_sha='d'*40, head_ref='autopilot/repair-pr10-old',
                   base_sha='9'*40, base_ref='feature/root')
        b = ControlBackend([root, [exact, stale]])
        out = b.read_github_control(repository='Owner/Repo', control_revision=139,
            payload={'rootPr': 10, 'preferredRepairPr': 0}, private_key=b'k')
        self.assertEqual(out['binding']['status'], 'EXACT_REPAIR_CHILD_BOUND')
        self.assertEqual(out['binding']['selection_reason'], 'discovered-exact')
        self.assertEqual(out['repair_pr']['number'], 12)
        self.assertEqual([x['number'] for x in out['exact_repair_candidates']], [12])
        self.assertIn('base=feature%2Froot', b.requests[-1][1])

    def test_ambiguous_exact_children_fail_closed(self):
        root = pr(10, head_sha='a'*40, head_ref='feature/root')
        a = pr(12, head_ref='autopilot/repair-pr10-a', base_sha='a'*40, base_ref='feature/root')
        bpr = pr(13, head_ref='autopilot/repair-pr10-b', base_sha='a'*40, base_ref='feature/root')
        b = ControlBackend([root, [a, bpr]])
        with self.assertRaises(AuthorityError) as cm:
            b.read_github_control(repository='Owner/Repo', control_revision=139,
                payload={'rootPr': 10, 'preferredRepairPr': 0}, private_key=b'k')
        self.assertEqual(cm.exception.code, 'REPAIR_CHILD_AMBIGUOUS')

    def test_stale_preferred_does_not_bind(self):
        root = pr(10, head_sha='a'*40, head_ref='feature/root')
        preferred = pr(12, head_ref='repair/old', base_sha='9'*40, base_ref='feature/root')
        b = ControlBackend([root, preferred, []])
        out = b.read_github_control(repository='Owner/Repo', control_revision=139,
            payload={'rootPr': 10, 'preferredRepairPr': 12}, private_key=b'k')
        self.assertEqual(out['binding']['status'], 'NO_CURRENT_EXACT_REPAIR_CHILD')
        self.assertTrue(out['binding']['stale_preferred'])
        self.assertEqual(out['binding']['preferred_base_sha'], '9'*40)

    def test_closed_or_foreign_root_is_denied(self):
        for root, code in (
            (pr(10, state='closed'), 'ROOT_PR_NOT_OPEN'),
            (pr(10, repo='Other/Repo'), 'ROOT_PR_REPOSITORY_MISMATCH'),
        ):
            with self.subTest(code=code):
                b = ControlBackend([root])
                with self.assertRaises(AuthorityError) as cm:
                    b.read_github_control(repository='Owner/Repo', control_revision=139,
                        payload={'rootPr': 10, 'preferredRepairPr': 0}, private_key=b'k')
                self.assertEqual(cm.exception.code, code)


class _Conn:
    def shutdown(self, _how): pass
    def close(self): pass


class LinuxShutdownTrackingV8Tests(unittest.TestCase):
    def _daemon_shell(self, worker):
        d = object.__new__(LinuxAuthorityDaemon)
        d.listener = None
        d._stop = threading.Event()
        d._active_lock = threading.Lock()
        d._active = {_Conn()}
        d._workers = [worker]
        d.preauth_timeout = 0.05
        d.accept_poll = 0.01
        d.path = Path('/tmp/forgeboss-authority-v8-nonexistent.sock')
        return d

    def test_stalled_postauth_worker_survives_tracking_and_blocks_restart(self):
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
        release.set();worker.join(1)
        d.close()
        self.assertEqual(d._workers, [])
        self.assertFalse(d._active)


if __name__ == '__main__':
    unittest.main()
